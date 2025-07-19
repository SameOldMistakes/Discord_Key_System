# Discord Authentication & Licensing Bot

A comprehensive Discord bot designed for secure software licensing and user access management. Features hardware ID binding, 2FA authentication, and role-based administration with automated license management.

## 🚀 Key Features

### Security & Authentication
- **🔐 Two-Factor Authentication:** Secure Discord DM-based 2FA codes with 5-minute expiration
- **🖥️ Hardware ID Binding:** Links user access to specific devices using HWID verification
- **📍 IP Address Tracking:** Monitors and validates user locations with blacklist support
- **⚡ Rate Limiting:** Built-in protection against brute force attacks (3 requests/minute)
- **🛡️ Anti-Debug Protection:** Client-side security measures against reverse engineering

### License Management
- **🎫 Flexible Licensing:** Generate single or bulk license keys (up to 100 at once)
- **⏰ Subscription Control:** Support for both time-limited and lifetime access
- **📊 Usage Tracking:** Comprehensive statistics and user activity monitoring
- **🔄 Automatic Renewals:** Expiration notifications and subscription management

### Administration
- **👥 Role-Based Access:** Three permission levels (Super Admin, Admin, Moderator)
- **⚙️ Dynamic Configuration:** Interactive setup via Discord commands
- **💾 Automated Backups:** Regular data backups every 24 hours
- **📈 Real-time Monitoring:** Detailed logging and webhook alerts
- **🌐 HTTP API:** RESTful endpoints for client application integration

---

## 📋 Quick Start Guide

### Prerequisites

- **Python 3.12+** - [Download here](https://www.python.org/downloads/)
- **Discord Bot** - Create one at the [Discord Developer Portal](https://discord.com/developers/applications)
- **Discord Server** - Where you'll manage the bot (with appropriate permissions)

### Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd DiscordAuthSystem
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment:**
   ```bash
   # Copy the example environment file
   copy .env.example .env  # Windows
   cp .env.example .env    # Linux/Mac
   ```

4. **Edit `.env` file:**
   ```env
   # Required: Your Discord bot token
   DISCORD_BOT_TOKEN=your_bot_token_here
   
   # Required: Your Discord User ID (enable Developer Mode to copy ID)
   SUPER_ADMIN_IDS=123456789012345678
   ```

5. **Start the bot:**
   ```bash
   python server.py
   ```

### Initial Configuration

1. **First Run Setup:**
   - The bot will automatically send you a DM with setup instructions
   - Join your Discord server where the bot has been added
   - Use the `/setup` command to configure:
     - 📢 **Log Channel** - For system notifications
     - 👑 **Admin Role** - Users with administrative privileges
     - 🛠️ **Moderator Role** - Users with moderation privileges
     - 🔗 **Webhook URL** - For critical security alerts

2. **Verification:**
   - Run `/help` to see available commands
   - Check that the bot responds and shows appropriate permissions

---

## 📚 Command Reference

All commands are Discord slash commands. Use `/help` in Discord to see commands available to your permission level.

### 🔴 Super Admin Commands
*Available only to users listed in `SUPER_ADMIN_IDS`*

| Command | Description | Usage |
|---------|-------------|-------|
| `/setup` | Configure bot settings | `/setup [log_channel] [admin_role] [moderator_role] [webhook_url]` |
| `/remove_user` | Permanently remove a user | `/remove_user <user>` |

### 🟠 Admin Commands  
*Available to Admins and Super Admins*

| Command | Description | Usage |
|---------|-------------|-------|
| `/add_user` | Grant lifetime access to a user | `/add_user <user>` |
| `/extend_user` | Extend user's subscription | `/extend_user <user> <days>` |
| `/reset_hwid` | Reset user's Hardware ID | `/reset_hwid <user>` |
| `/revoke_license` | Revoke an unused license key | `/revoke_license <key>` |
| `/blacklist_ip` | Block an IP address | `/blacklist_ip <ip_address>` |
| `/unblacklist_ip` | Unblock an IP address | `/unblacklist_ip <ip_address>` |

### 🟡 Moderator Commands
*Available to Moderators, Admins, and Super Admins*

| Command | Description | Usage |
|---------|-------------|-------|
| `/generate_license` | Create a single license key | `/generate_license [days=30] [lifetime=false]` |
| `/generate_bulk_licenses` | Create multiple license keys (max 100) | `/generate_bulk_licenses <amount> [days=30] [lifetime=false]` |
| `/view_licenses` | Download CSV of all license keys | `/view_licenses` |
| `/view_users` | Download CSV of all users | `/view_users` |
| `/user_info` | View user details | `/user_info <user>` |
| `/stats` | Show system statistics | `/stats` |
| `/view_blacklist` | View blacklisted IP addresses | `/view_blacklist` |
| `/bot_status` | Check bot latency | `/bot_status` |

### 🟢 Public Commands
*Available to everyone*

| Command | Description | Usage |
|---------|-------------|-------|
| `/redeem_license` | Redeem a license key | `/redeem_license <key>` |
| `/my_info` | Check your subscription status | `/my_info` |
| `/help` | Show available commands | `/help` |

---

## 🔌 Client Integration

The system provides a complete client-server authentication flow for integrating with your applications.

### HTTP API Endpoints

#### `POST /2fa_request`
Initiates 2FA authentication for a user.

**Request Body:**
```json
{
  "user_id": "123456789012345678",
  "ip_address": "192.168.1.100",
  "hwid": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
}
```

**Response:**
```json
{
  "success": true,
  "message": "123456",
  "session_token": "encrypted_session_token_here"
}
```

#### `POST /login_with_token`
Validates a session token for automatic login.

**Request Body:**
```json
{
  "session_token": "encrypted_session_token",
  "user_id": "123456789012345678"
}
```

### Example Client Implementation

The included `client.py` demonstrates:

- **Hardware ID Detection:** Automatic HWID generation using Windows WMI
- **IP Address Detection:** External IP resolution via ipify.org
- **Anti-Debug Protection:** Process monitoring for security tools
- **Session Management:** Automatic token storage and reuse
- **2FA Flow:** Complete authentication workflow

**Basic Usage:**
```bash
# Get your hardware ID
python client.py --get-hwid

# Run authentication flow
python client.py
```


## 🔒 Security Features

### Authentication Security
- **Multi-Factor Authentication:** Discord DM-based 2FA with time-limited codes
- **Hardware Binding:** HWID verification prevents account sharing
- **Session Management:** Encrypted session tokens with 24-hour expiration
- **Rate Limiting:** Protection against brute force attacks (3 requests/minute)
- **IP Monitoring:** Real-time IP tracking with blacklist capabilities

### Data Protection
- **Encrypted Storage:** Session tokens encrypted using Fernet symmetric encryption
- **Automatic Backups:** Daily backups of all critical data files
- **Secure Communication:** HTTPS support for production deployments
- **Access Control:** Role-based permissions with three security levels

### Anti-Tampering
- **Process Monitoring:** Client-side detection of debugging tools
- **Integrity Checks:** Validation of client requests and data
- **Audit Logging:** Comprehensive logging of all security events

---

## 🛠️ Troubleshooting

### Common Issues

#### Bot Not Responding
```bash
# Check if bot is online
python server.py

# Verify token in .env file
echo $DISCORD_BOT_TOKEN  # Linux/Mac
echo %DISCORD_BOT_TOKEN% # Windows
```

#### Permission Errors
- Ensure bot has `Send Messages` and `Use Slash Commands` permissions
- Verify Super Admin IDs are correct in `.env`
- Check that roles are properly configured via `/setup`

#### 2FA Not Working
- Verify user can receive DMs from the bot
- Check if user is in the system (`/my_info`)
- Ensure user has redeemed a valid license key

#### Client Connection Issues
```python
# Test server connectivity
import requests
response = requests.get('http://127.0.0.1:8080')
print(response.status_code)
```

### Log Files
- Server logs: Console output when running `python server.py`
- Discord logs: Check your configured log channel
- Backup files: Located in `./backups/` directory

---

## 📊 System Requirements

### Server Requirements
- **Python:** 3.8 or higher
- **RAM:** 512MB minimum (1GB recommended)
- **Storage:** 100MB for application + data
- **Network:** Stable internet connection
- **OS:** Windows, Linux, or macOS

### Client Requirements
- **OS:** Windows (for HWID detection)
- **Python:** 3.8+ (if using Python client)
- **Network:** Internet access for authentication

### Production Deployment
- **HTTPS:** Required for secure communication
- **Reverse Proxy:** Nginx or Apache recommended
- **Process Manager:** PM2, systemd, or Docker
- **Monitoring:** Health checks and alerting

---

## 📈 Performance & Scaling

### Current Limitations
- **Concurrent Users:** ~1000 simultaneous authentications
- **License Generation:** 100 keys per bulk operation
- **Data Storage:** JSON file-based (suitable for small-medium deployments)

### Optimization Tips
- Use SSD storage for better I/O performance
- Implement database backend for large-scale deployments
- Configure proper caching for session management
- Use load balancing for high-availability setups



## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup
```bash
# Clone the repository
git clone <repository-url>
cd DiscordAuthSystem

# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env

# Edit .env with your configuration
# Start development server
python server.py
```



## 🆘 Support

If you encounter any issues or have questions:

1. **Check the [Troubleshooting](#🛠️-troubleshooting) section**
2. **Review the [Command Reference](#📚-command-reference)**
3. **Ensure your setup follows the [Quick Start Guide](#📋-quick-start-guide)**
4. **Check server logs for error messages**

For additional support, please create an issue in the repository with:
- Detailed description of the problem
- Steps to reproduce the issue
- Server logs and error messages
- Your environment details (OS, Python version, etc.)

---

**⭐ If this project helped you, please consider giving it a star!**

