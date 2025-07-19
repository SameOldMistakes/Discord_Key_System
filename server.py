import discord
from discord import app_commands
from discord.ext import commands, tasks
import os
import random
import json
import string
from datetime import datetime, timedelta
from dotenv import load_dotenv
import platform
import ipaddress
import asyncio
from aiohttp import web
import time
from cryptography.fernet import Fernet
import io
import traceback
import re
import shutil

# --- Initial Setup ---
load_dotenv()

# Load essential variables from .env
DISCORD_BOT_TOKEN = os.getenv('DISCORD_BOT_TOKEN')
SUPER_ADMIN_IDS = {int(id.strip()) for id in os.getenv('SUPER_ADMIN_IDS', '').split(',') if id.strip()}

if not DISCORD_BOT_TOKEN or not SUPER_ADMIN_IDS:
    print("FATAL: DISCORD_BOT_TOKEN and SUPER_ADMIN_IDS must be set in the .env file.")
    exit()

# --- Configuration File Handling ---
CONFIG_FILE = 'config.json'

def load_config():
    """Loads the config file, creating it if it doesn't exist."""
    if not os.path.exists(CONFIG_FILE):
        print("Config file not found, creating a new one.")
        # On first run, setup_complete is False
        default_config = {
            "log_channel_id": None,
            "webhook_url": None,
            "admin_role_ids": [],
            "moderator_role_ids": [],
            "backup_interval_hours": 24,
            "setup_complete": False
        }
        save_config(default_config)
        return default_config
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        print("Error decoding config.json, returning a default config.")
        return {}

def save_config(data):
    """Saves data to the config file."""
    with open(CONFIG_FILE, 'w') as f:
        json.dump(data, f, indent=4)

config = load_config()

# --- Role & Permission Management ---

ENCRYPTION_KEY = config.get('encryption_key')
if not ENCRYPTION_KEY:
    print("ENCRYPTION_KEY not found in config file.")
    print("Generating new encryption key...")
    ENCRYPTION_KEY = Fernet.generate_key().decode()
    config['encryption_key'] = ENCRYPTION_KEY
    save_config(config)
    print("New key generated and saved to config file.")

fernet = Fernet(ENCRYPTION_KEY.encode())

BACKUP_INTERVAL_HOURS = int(config.get('backup_interval_hours', 24))

intents = discord.Intents.default()
intents.messages = True
intents.guilds = True
intents.members = True
intents.message_content = True
bot = commands.Bot(command_prefix='/', intents=intents)

# Constants
USERS_FILE = 'allowed_users.json'
LICENSES_FILE = 'licenses.json'
IP_BLACKLIST_FILE = 'ip_blacklist.json'
SESSIONS_FILE = 'sessions.json'
HWID_RESET_REQUESTS = {}
REQUEST_COOLDOWNS = {}
MAX_REQUESTS_PER_MINUTE = 3

# --- Helper Functions ---
def get_os_version():
    return platform.platform()

def load_json(filename, default=None):
    if default is None:
        default = {}
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        with open(filename, 'w') as f:
            json.dump(default, f)
        return default

def save_json(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

async def log_to_discord(embed):
    log_channel_id = config.get('log_channel_id')
    if log_channel_id:
        try:
            channel = bot.get_channel(log_channel_id) or await bot.fetch_channel(log_channel_id)
            if channel:
                await channel.send(embed=embed)
        except (discord.NotFound, discord.Forbidden):
            print(f"Could not log to channel {log_channel_id}. It might be deleted or I lack permissions.")
        except Exception as e:
            print(f"An error occurred while logging to Discord: {e}")

async def send_webhook_alert(embed):
    webhook_url = config.get('webhook_url')
    if webhook_url:
        try:
            async with aiohttp.ClientSession() as session:
                webhook = discord.Webhook.from_url(webhook_url, session=session)
                await webhook.send(embed=embed)
        except Exception as e:
            print(f"Failed to send webhook alert: {e}")

def load_users():
    users = load_json(USERS_FILE)
    current_time = datetime.now()
    # Prune expired users
    expired_users = [uid for uid, data in users.items() if not data.get('lifetime') and 'expiration_date' in data and datetime.fromisoformat(data['expiration_date']) < current_time]
    for uid in expired_users:
        del users[uid]
    if expired_users:
        save_json(users, USERS_FILE)
    return users

def save_users(data):
    save_json(data, USERS_FILE)

def load_licenses():
    return load_json(LICENSES_FILE)

def save_licenses(data):
    save_json(data, LICENSES_FILE)

# Initial data load
users_data = load_users()
licenses_data = load_licenses()
ip_blacklist = load_json(IP_BLACKLIST_FILE, default=[])
sessions = load_json(SESSIONS_FILE)

# --- Permission Decorators ---
def is_moderator():
    async def predicate(interaction: discord.Interaction):
        if interaction.user.id in SUPER_ADMIN_IDS:
            return True
        user_roles = {r.id for r in interaction.user.roles}
        admin_roles = set(config.get('admin_role_ids', []))
        moderator_roles = set(config.get('moderator_role_ids', []))
        # Admins are also moderators
        return not user_roles.isdisjoint(admin_roles | moderator_roles)
    return app_commands.check(predicate)

def is_admin():
    async def predicate(interaction: discord.Interaction):
        if interaction.user.id in SUPER_ADMIN_IDS:
            return True
        user_roles = {r.id for r in interaction.user.roles}
        admin_roles = set(config.get('admin_role_ids', []))
        return not user_roles.isdisjoint(admin_roles)
    return app_commands.check(predicate)

def is_super_admin():
    async def predicate(interaction: discord.Interaction):
        return interaction.user.id in SUPER_ADMIN_IDS
    return app_commands.check(predicate)

# --- Setup & Admin Commands ---
@bot.tree.command(name="setup", description="Configure the bot's settings (Super Admin only)")
@is_super_admin()
async def setup(interaction: discord.Interaction, 
              log_channel: str = None,
              admin_role: discord.Role = None, 
              moderator_role: discord.Role = None, 
              webhook_url: str = None):
    
    
    updated_settings = []
    skipped_settings = []

    # --- Channel Processing ---
    if log_channel:
        channel_id = None
        # Extract ID from mention, URL, or raw ID
        match = re.search(r'(\d{17,19})', log_channel)
        if match:
            channel_id = int(match.group(1))
        
        if channel_id:
            try:
                # Verify the channel exists and is a text channel
                fetched_channel = await bot.fetch_channel(channel_id)
                if isinstance(fetched_channel, discord.TextChannel):
                    config['log_channel_id'] = fetched_channel.id
                    updated_settings.append(f"**Log Channel:** <#{fetched_channel.id}>")
                else:
                    skipped_settings.append("**Log Channel:** Not a valid text channel.")
            except (discord.NotFound, discord.Forbidden):
                skipped_settings.append("**Log Channel:** Could not find or access the specified channel.")
        else:
            skipped_settings.append("**Log Channel:** Invalid format. Use channel mention, ID, or URL.")
    
    # --- Role & Webhook Processing ---
    if admin_role:
        config['admin_role_ids'] = [admin_role.id]
        updated_settings.append(f"**Admin Role:** {admin_role.mention}")
    
    if moderator_role:
        config['moderator_role_ids'] = [moderator_role.id]
        updated_settings.append(f"**Moderator Role:** {moderator_role.mention}")

    if webhook_url:
        webhook_pattern = re.compile(r'^https://(ptb\.|canary\.)?discord\.com/api/webhooks/\d+/[a-zA-Z0-9_-]+$')
        if webhook_pattern.match(webhook_url):
            config['webhook_url'] = webhook_url
            updated_settings.append("**Webhook URL:** Set successfully")
        else:
            skipped_settings.append("**Webhook URL:** Invalid format.")

    # --- Finalize and Respond ---
    if updated_settings:
        config['setup_complete'] = True # Mark setup as complete if at least one thing was set
        save_config(config)
        
        description = "The following settings have been updated:" + "\n- " + "\n- ".join(updated_settings)
        if skipped_settings:
            description += "\n\nThe following were not updated:" + "\n- " + "\n- ".join(skipped_settings)

        embed = discord.Embed(title="✅ Setup Finished", description=description, color=discord.Color.green())
        await interaction.response.send_message(embed=embed, ephemeral=True)
    else:
        description = "No settings were changed."
        if skipped_settings:
            description += "\n\nIssues found:" + "\n- " + "\n- ".join(skipped_settings)
        embed = discord.Embed(title="ℹ️ Setup Finished", description=description, color=discord.Color.blue())
        await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="generate_license", description="Generate a single license key")
@is_moderator()
async def generate_license(interaction: discord.Interaction, days: int = 30, lifetime: bool = False):
    key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=20))
    licenses_data[key] = {'days': days, 'lifetime': lifetime, 'used': False}
    save_licenses(licenses_data)
    await interaction.response.send_message(f"Generated license key: `{key}`", ephemeral=True)

@bot.tree.command(name="generate_bulk_licenses", description="Generate bulk license keys")
@is_moderator()
async def generate_bulk_licenses(interaction: discord.Interaction, amount: int, days: int = 30, lifetime: bool = False):
    if amount > 100: # Prevent abuse
        return await interaction.response.send_message("Cannot generate more than 100 keys at once.", ephemeral=True)
    
    keys = [''.join(random.choices(string.ascii_uppercase + string.digits, k=20)) for _ in range(amount)]
    for key in keys:
        licenses_data[key] = {'days': days, 'lifetime': lifetime, 'used': False}
    save_licenses(licenses_data)

    file_content = "\n".join(keys)
    file = discord.File(io.StringIO(file_content), filename=f"licenses_{amount}_{days}d.txt")
    await interaction.response.send_message(f"Generated {amount} license keys.", file=file, ephemeral=True)

@bot.tree.command(name="add_user", description="Manually add a user with lifetime access")
@is_admin()
async def add_user(interaction: discord.Interaction, user: discord.User):
    user_id = str(user.id)
    users_data[user_id] = {'lifetime': True, 'hwid': None, 'created_at': datetime.now().isoformat()}
    save_users(users_data)
    await interaction.response.send_message(f"User {user.mention} has been given lifetime access.", ephemeral=True)

@bot.tree.command(name="remove_user", description="Remove a user from the system")
@is_super_admin()
async def remove_user(interaction: discord.Interaction, user: discord.User):
    user_id = str(user.id)
    if user_id in users_data:
        del users_data[user_id]
        save_users(users_data)
        await interaction.response.send_message(f"User {user.mention} has been removed.", ephemeral=True)
    else:
        await interaction.response.send_message("User not found.", ephemeral=True)

@bot.tree.command(name="reset_hwid", description="Reset a user's HWID")
@is_admin()
async def reset_hwid(interaction: discord.Interaction, user: discord.User):
    user_id = str(user.id)
    if user_id in users_data:
        users_data[user_id]['hwid'] = None
        save_users(users_data)
        await interaction.response.send_message(f"HWID for {user.mention} has been reset.", ephemeral=True)
    else:
        await interaction.response.send_message("User not found.", ephemeral=True)

@bot.tree.command(name="extend_user", description="Extend a user's subscription")
@is_admin()
async def extend_user(interaction: discord.Interaction, user: discord.User, days: int):
    user_id = str(user.id)
    if user_id not in users_data:
        return await interaction.response.send_message("User not found.", ephemeral=True)
    
    if users_data[user_id].get('lifetime'):
        return await interaction.response.send_message("User already has lifetime access.", ephemeral=True)

    expiry = datetime.fromisoformat(users_data[user_id]['expiration_date'])
    new_expiry = expiry + timedelta(days=days)
    users_data[user_id]['expiration_date'] = new_expiry.isoformat()
    save_users(users_data)
    await interaction.response.send_message(f"Extended {user.mention}'s subscription by {days} days. New expiry: {new_expiry.strftime('%Y-%m-%d')}", ephemeral=True)

@bot.tree.command(name="view_users", description="View all allowed users")
@is_moderator()
async def view_users(interaction: discord.Interaction):
    if not users_data:
        return await interaction.response.send_message("No users in the system.", ephemeral=True)

    file_content = "UserID,Username,HWID,Expires/Lifetime,Joined\n"
    for user_id, data in users_data.items():
        try:
            user = await bot.fetch_user(int(user_id))
            username = f"{user.name}#{user.discriminator}"
        except (discord.NotFound, ValueError):
            username = "Unknown User"
        
        expiry = "Lifetime" if data.get('lifetime') else datetime.fromisoformat(data['expiration_date']).strftime('%Y-%m-%d')
        hwid = data.get('hwid', 'Not Set')
        joined = datetime.fromisoformat(data['created_at']).strftime('%Y-%m-%d')
        file_content += f"{user_id},{username},{hwid},{expiry},{joined}\n"

    file = discord.File(io.StringIO(file_content), filename="all_users.csv")
    await interaction.response.send_message("Here are all the users in the system.", file=file, ephemeral=True)

@bot.tree.command(name="user_info", description="Get information about a specific user")
@is_moderator()
async def user_info(interaction: discord.Interaction, user: discord.User):
    user_id = str(user.id)
    user_data = users_data.get(user_id)

    if not user_data:
        return await interaction.response.send_message("User not found in the system.", ephemeral=True)

    embed = discord.Embed(title=f"User Info - {user.name}", color=discord.Color.blue())
    embed.set_thumbnail(url=user.display_avatar.url)

    if user_data.get('lifetime'):
        embed.add_field(name="Subscription", value="Lifetime")
    else:
        expiry = datetime.fromisoformat(user_data['expiration_date'])
        embed.add_field(name="Subscription Expires", value=expiry.strftime('%Y-%m-%d %H:%M:%S'))

    embed.add_field(name="HWID", value=f"`{user_data.get('hwid', 'Not set')}`")
    embed.add_field(name="Last IP", value=f"`{user_data.get('ip', 'Not set')}`")
    embed.add_field(name="OS", value=f"`{user_data.get('os', 'Unknown')}`")
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="view_licenses", description="View all generated licenses")
@is_moderator()
async def view_licenses(interaction: discord.Interaction):
    if not licenses_data:
        return await interaction.response.send_message("No licenses have been generated.", ephemeral=True)

    file_content = "Key,Days,Lifetime,Used,Used By,Used At\n"
    for key, data in licenses_data.items():
        file_content += f"{key},{data.get('days', 'N/A')},{data.get('lifetime', False)},{data.get('used', False)},{data.get('used_by', '')},{data.get('used_at', '')}\n"
    
    file = discord.File(io.StringIO(file_content), filename="all_licenses.csv")
    await interaction.response.send_message("Here are all the generated licenses.", file=file, ephemeral=True)

@bot.tree.command(name="bot_status", description="Check bot's status and latency")
@is_moderator()
async def bot_status(interaction: discord.Interaction):
    latency = bot.latency * 1000  # in ms
    await interaction.response.send_message(f"Pong! Latency: {latency:.2f}ms", ephemeral=True)

@bot.tree.command(name="revoke_license", description="Revoke an unused license key")
@is_admin()
async def revoke_license(interaction: discord.Interaction, key: str):
    if key in licenses_data and not licenses_data[key].get('used'):
        del licenses_data[key]
        save_json(licenses_data, LICENSES_FILE)
        await interaction.response.send_message(f"License key `{key}` has been revoked.", ephemeral=True)
    else:
        await interaction.response.send_message("License key is either invalid or has already been used.", ephemeral=True)

@bot.tree.command(name="stats", description="Show detailed statistics")
@is_moderator()
async def stats(interaction: discord.Interaction):
    active_users = len(users_data)
    now = datetime.now()
    
    new_users_week = sum(1 for u in users_data.values() if 'created_at' in u and now - datetime.fromisoformat(u['created_at']) < timedelta(days=7))
    new_users_month = sum(1 for u in users_data.values() if 'created_at' in u and now - datetime.fromisoformat(u['created_at']) < timedelta(days=30))

    redeemed_week = sum(1 for lic in licenses_data.values() if lic.get('used') and 'used_at' in lic and now - datetime.fromisoformat(lic['used_at']) < timedelta(days=7))
    redeemed_month = sum(1 for lic in licenses_data.values() if lic.get('used') and 'used_at' in lic and now - datetime.fromisoformat(lic['used_at']) < timedelta(days=30))

    os_counts = {}
    for user in users_data.values():
        os_name = user.get('os', 'Unknown')
        os_counts[os_name] = os_counts.get(os_name, 0) + 1
    os_dist = "\n".join([f"{os}: {count}" for os, count in os_counts.items()]) if os_counts else "No data"

    embed = discord.Embed(title="System Statistics", color=discord.Color.gold())
    embed.add_field(name="Active Users", value=str(active_users), inline=False)
    embed.add_field(name="User Growth", value=f"Last 7 Days: {new_users_week}\nLast 30 Days: {new_users_month}")
    embed.add_field(name="Licenses Redeemed", value=f"Last 7 Days: {redeemed_week}\nLast 30 Days: {redeemed_month}")
    embed.add_field(name="OS Distribution", value=os_dist, inline=False)
    await interaction.response.send_message(embed=embed, ephemeral=True)

# --- IP Blacklist Commands ---
@bot.tree.command(name="blacklist_ip", description="Blacklist an IP address")
@is_admin()
async def blacklist_ip(interaction: discord.Interaction, ip_address: str):
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        return await interaction.response.send_message("Invalid IP address format.", ephemeral=True)

    if ip_address not in ip_blacklist:
        ip_blacklist.append(ip_address)
        save_json(ip_blacklist, IP_BLACKLIST_FILE)
        await interaction.response.send_message(f"IP `{ip_address}` has been blacklisted.", ephemeral=True)
    else:
        await interaction.response.send_message(f"IP `{ip_address}` is already blacklisted.", ephemeral=True)

@bot.tree.command(name="unblacklist_ip", description="Unblacklist an IP address")
@is_admin()
async def unblacklist_ip(interaction: discord.Interaction, ip_address: str):
    if ip_address in ip_blacklist:
        ip_blacklist.remove(ip_address)
        save_json(ip_blacklist, IP_BLACKLIST_FILE)
        await interaction.response.send_message(f"IP `{ip_address}` has been unblacklisted.", ephemeral=True)
    else:
        await interaction.response.send_message(f"IP `{ip_address}` is not blacklisted.", ephemeral=True)

@bot.tree.command(name="view_blacklist", description="View the IP blacklist")
@is_moderator()
async def view_blacklist(interaction: discord.Interaction):
    if not ip_blacklist:
        return await interaction.response.send_message("The IP blacklist is empty.", ephemeral=True)
    await interaction.response.send_message("Blacklisted IPs:\n" + "\n".join(f"`{ip}`" for ip in ip_blacklist), ephemeral=True)

# --- User Commands ---
@bot.tree.command(name="my_info", description="Check your subscription status")
async def my_info(interaction: discord.Interaction):
    user_id = str(interaction.user.id)
    user_data = users_data.get(user_id)

    if not user_data:
        return await interaction.response.send_message("You are not in the system. Please redeem a license key.", ephemeral=True)

    embed = discord.Embed(title="Your Information", color=discord.Color.purple())
    expiry = "Lifetime" if user_data.get('lifetime') else datetime.fromisoformat(user_data['expiration_date']).strftime('%Y-%m-%d %H:%M:%S')
    embed.add_field(name="Subscription", value=f"Expires: {expiry}")
    embed.add_field(name="HWID", value=f"`{user_data.get('hwid', 'Not set')}`")
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="redeem_license", description="Redeem a license key")
async def redeem_license(interaction: discord.Interaction, key: str):
    if key not in licenses_data or licenses_data[key].get('used'):
        return await interaction.response.send_message("Invalid or already used license key.", ephemeral=True)

    license_info = licenses_data[key]
    user_id = str(interaction.user.id)

    if license_info.get('lifetime'):
        users_data[user_id] = {'lifetime': True, 'hwid': None, 'created_at': datetime.now().isoformat()}
        expiry_message = "You now have lifetime access."
    else:
        days = license_info.get('days', 30)
        expiration_date = datetime.now() + timedelta(days=days)
        users_data[user_id] = {
            'lifetime': False, 
            'expiration_date': expiration_date.isoformat(), 
            'hwid': None,
            'created_at': datetime.now().isoformat()
        }
        expiry_message = f"Your access expires on {expiration_date.strftime('%Y-%m-%d')}."

    licenses_data[key]['used'] = True
    licenses_data[key]['used_by'] = user_id
    licenses_data[key]['used_at'] = datetime.now().isoformat()
    save_licenses(licenses_data)
    save_users(users_data)

    await interaction.response.send_message(f"License redeemed successfully! {expiry_message}", ephemeral=True)

    log_embed = discord.Embed(title="License Redeemed", color=discord.Color.blue())
    log_embed.add_field(name="User", value=interaction.user.mention)
    log_embed.add_field(name="License Key", value=f"`{key}`")
    await log_to_discord(log_embed)


# --- Core Logic & HTTP Server ---
async def send_2fa_code(user_id, ip_address, hwid):
    user_data = users_data.get(user_id)
    if not user_data:
        return False, "User not found. Please redeem a license key."

    if user_data.get('hwid') and user_data['hwid'] != hwid:
        return False, "IP address or HWID mismatch"

    if not user_data.get('hwid'):
        user_data['hwid'] = hwid
        user_data['ip'] = ip_address
        save_users(users_data)

    code = ''.join(random.choices(string.digits, k=6))
    user_data['2fa_code'] = code
    user_data['2fa_expiry'] = (datetime.now() + timedelta(minutes=5)).isoformat()
    save_users(users_data)

    try:
        user = await bot.fetch_user(int(user_id))
        os_version = get_os_version()
        user_data['os'] = os_version # Save OS for stats
        save_users(users_data)

        embed = discord.Embed(title="🔐 Your 2FA Code", color=discord.Color.blue())
        embed.description = f"Here is your one-time login code. It will expire shortly."
        embed.add_field(name="Verification Code", value=f"**`{code}`**", inline=False)
        embed.add_field(name="System Info", value=f"**IP:** `{ip_address}`\n**HWID:** `{hwid}`\n**OS:** `{os_version}`", inline=False)
        embed.set_footer(text="If you did not request this, please contact an administrator.")
        await user.send(embed=embed)

        log_embed = discord.Embed(title="2FA Code Sent", color=discord.Color.orange())
        log_embed.add_field(name="User", value=user.mention)
        await log_to_discord(log_embed)

        return True, code
    except (discord.NotFound, discord.Forbidden):
        return False, "Could not send DM. Please check your privacy settings."
    except Exception as e:
        print(f"Error sending 2FA: {e}")
        return False, "An internal error occurred."

async def handle_2fa_request(request):
    try:
        data = await request.json()
    except Exception:
        return web.json_response({'success': False, 'message': 'Invalid payload'}, status=400)

    user_id = data.get('user_id')
    ip_address = data.get('ip_address')
    hwid = data.get('hwid')

    if ip_address in ip_blacklist:
        alert_embed = discord.Embed(title="Blacklisted IP Blocked", color=discord.Color.dark_red())
        alert_embed.add_field(name="IP Address", value=ip_address)
        await send_webhook_alert(alert_embed)
        return web.json_response({'success': False, 'message': 'Access denied.'}, status=403)

    if not all([user_id, ip_address, hwid]):
        return web.json_response({'success': False, 'message': 'Missing required data'}, status=400)

    current_time = time.time()
    if user_id in REQUEST_COOLDOWNS:
        last_req_time, req_count = REQUEST_COOLDOWNS[user_id]
        if current_time - last_req_time < 60:
            if req_count >= MAX_REQUESTS_PER_MINUTE:
                return web.json_response({'success': False, 'message': 'Too many requests. Please wait.'}, status=429)
            REQUEST_COOLDOWNS[user_id] = (last_req_time, req_count + 1)
        else:
            REQUEST_COOLDOWNS[user_id] = (current_time, 1)
    else:
        REQUEST_COOLDOWNS[user_id] = (current_time, 1)

    success, response = await send_2fa_code(user_id, ip_address, hwid)
    if success:
        session_token = fernet.encrypt(json.dumps({
            'user_id': user_id,
            'expires_at': (datetime.now() + timedelta(hours=24)).isoformat()
        }).encode()).decode()
        sessions[user_id] = session_token
        save_json(sessions, SESSIONS_FILE)
        return web.json_response({'success': True, 'message': response, 'session_token': session_token})
    else:
        if response == "IP address or HWID mismatch":
            alert_embed = discord.Embed(title="HWID/IP Mismatch Alert", color=discord.Color.red())
            alert_embed.add_field(name="User ID", value=user_id)
            alert_embed.add_field(name="Stored IP", value=users_data[user_id].get('ip'))
            alert_embed.add_field(name="Request IP", value=ip_address)
            alert_embed.add_field(name="Stored HWID", value=users_data[user_id].get('hwid'))
            alert_embed.add_field(name="Request HWID", value=hwid)
            await send_webhook_alert(alert_embed)
        return web.json_response({'success': False, 'message': response})

async def handle_token_login(request):
    try:
        data = await request.json()
        token = data.get('session_token')
        user_id = data.get('user_id')
        ip_address = data.get('ip_address')  # Get IP address from request

        # Check IP blacklist first
        if ip_address and ip_address in ip_blacklist:
            alert_embed = discord.Embed(title="Blacklisted IP Blocked (Token Login)", color=discord.Color.dark_red())
            alert_embed.add_field(name="IP Address", value=ip_address)
            alert_embed.add_field(name="User ID", value=user_id)
            await send_webhook_alert(alert_embed)
            return web.json_response({'success': False, 'message': 'Access denied.'}, status=403)

        if not token or not user_id or sessions.get(user_id) != token:
            return web.json_response({'success': False, 'message': 'Invalid session token.'}, status=401)
        
        decrypted_token = json.loads(fernet.decrypt(token.encode()).decode())
        if datetime.fromisoformat(decrypted_token['expires_at']) < datetime.now():
            del sessions[user_id]
            save_json(sessions, SESSIONS_FILE)
            return web.json_response({'success': False, 'message': 'Session expired.'}, status=401)

        return web.json_response({'success': True, 'message': 'Login successful.'})
    except Exception:
        return web.json_response({'success': False, 'message': 'Invalid token format.'}, status=400)

async def start_http_server():
    app = web.Application()
    app.router.add_post('/2fa_request', handle_2fa_request)
    app.router.add_post('/login_with_token', handle_token_login)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 8080)
    await site.start()
    print("HTTP server started on http://0.0.0.0:8080")

# --- Background Tasks ---
@tasks.loop(hours=BACKUP_INTERVAL_HOURS)
async def backup_task():
    await bot.wait_until_ready()
    backup_dir = 'backups'
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    for filename in [USERS_FILE, LICENSES_FILE, IP_BLACKLIST_FILE, SESSIONS_FILE]:
        if os.path.exists(filename):
            shutil.copy(filename, os.path.join(backup_dir, f"{timestamp}_{os.path.basename(filename)}"))
    print(f"[{datetime.now()}] Created data backups.")
    log_embed = discord.Embed(title="Automatic Backup Complete", description=f"A backup of all data files was successfully created.", color=discord.Color.light_grey())
    await log_to_discord(log_embed)

@tasks.loop(hours=24)
async def check_expirations_task():
    await bot.wait_until_ready()
    now = datetime.now()
    for user_id, data in list(users_data.items()):
        if not data.get('lifetime') and 'expiration_date' in data:
            try:
                expiry_date = datetime.fromisoformat(data['expiration_date'])
                # Notify if expiring within 3 days and hasn't been notified yet
                if timedelta(days=0) < (expiry_date - now) <= timedelta(days=3):
                    user = await bot.fetch_user(int(user_id))
                    await user.send(f"👋 Your subscription is expiring in less than 3 days on **{expiry_date.strftime('%Y-%m-%d')}**. Please contact an admin to renew.")
            except Exception as e:
                print(f"Could not send expiry notification to {user_id}: {e}")

# --- Bot Startup and Main Loop ---
@bot.event
async def on_ready():
    print(f'--- Logged in as {bot.user} (ID: {bot.user.id}) ---')
    print(f'--- Discord.py Version: {discord.__version__} ---')
    try:
        synced = await bot.tree.sync()
        print(f"--- Synced {len(synced)} slash command(s) ---")
        if not backup_task.is_running():
            backup_task.start()
        if not check_expirations_task.is_running():
            check_expirations_task.start()

        # First-run setup message
        if not config.get('setup_complete'):
            for admin_id in SUPER_ADMIN_IDS:
                try:
                    admin_user = await bot.fetch_user(admin_id)
                    embed = discord.Embed(title="👋 Welcome & Setup Required", 
                                          description="Thank you for setting up the bot! As a Super Admin, you need to run the initial configuration.", 
                                          color=discord.Color.orange())
                    embed.add_field(name="Command to Run", value="`/setup`", inline=False)
                    embed.add_field(name="What to Configure", value="- Log Channel\n- Admin Role\n- Moderator Role\n- Webhook URL (for alerts)", inline=False)
                    embed.set_footer(text="This message is only shown once.")
                    await admin_user.send(embed=embed)
                    print(f"Sent setup instructions to Super Admin {admin_user.name}.")
                except Exception as e:
                    print(f"Failed to send setup DM to Super Admin ID {admin_id}: {e}")

    except Exception as e:
        print(f"Failed to sync commands: {e}")

async def main():
    async with bot:
        # Start the HTTP server in the background
        http_server_task = asyncio.create_task(start_http_server())
        # Start the bot
        await bot.start(DISCORD_BOT_TOKEN)

@bot.tree.command(name="help", description="Shows a list of available commands based on your permissions.")
async def help_command(interaction: discord.Interaction):
    user_id = interaction.user.id
    user_roles = {r.id for r in interaction.user.roles}

    is_s_admin = user_id in SUPER_ADMIN_IDS
    is_a = is_s_admin or not user_roles.isdisjoint(set(config.get('admin_role_ids', [])))
    is_m = is_a or not user_roles.isdisjoint(set(config.get('moderator_role_ids', [])))

    embed = discord.Embed(
        title="Help - Command List",
        description="Here are the commands you have access to:",
        color=discord.Color.blue()
    )

    # Public commands
    public_cmds = (
        "`/redeem_license [key]` - Redeem a license key to gain access.\n"
        "`/my_info` - Check your own subscription status.\n"
        "`/help` - Shows this help message."
    )
    embed.add_field(name="�� Public Commands", value=public_cmds, inline=False)

    # Define command descriptions to avoid repetition
    mod_cmds_text = (
        "`/generate_license [...]` - Create a single license key.\n"
        "`/generate_bulk_licenses [...]` - Create up to 100 keys.\n"
        "`/view_licenses` / `/view_users` - Get CSV files of data.\n"
        "`/user_info [user]` - View details for a user.\n"
        "`/stats` / `/bot_status` / `/view_blacklist` - View system info."
    )
    admin_cmds_text = (
        "`/add_user [user]` - Grant lifetime access.\n"
        "`/extend_user [user] [days]` - Extend a subscription.\n"
        "`/reset_hwid [user]` - Reset a user's HWID.\n"
        "`/revoke_license [key]` - Revoke an unused key.\n"
        "`/blacklist_ip [ip]` - Block an IP address.\n"
        "`/unblacklist_ip [ip]` - Unblock an IP address."
    )
    super_admin_cmds_text = (
        "`/setup [...]` - Configure the bot's core settings.\n"
        "`/remove_user [user]` - Permanently remove a user."
    )

    # Hierarchical command display
    if is_s_admin:
        embed.add_field(name="👑 Super Admin Commands", value=super_admin_cmds_text, inline=False)
        embed.add_field(name="🛡️ Admin Commands", value=admin_cmds_text, inline=False)
        embed.add_field(name="🛠️ Moderator Commands", value=mod_cmds_text, inline=False)
    elif is_a:
        embed.add_field(name="🛡️ Admin Commands", value=admin_cmds_text, inline=False)
        embed.add_field(name="🛠️ Moderator Commands", value=mod_cmds_text, inline=False)
    elif is_m:
        embed.add_field(name="🛠️ Moderator Commands", value=mod_cmds_text, inline=False)

    await interaction.response.send_message(embed=embed, ephemeral=True)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutting down.")
