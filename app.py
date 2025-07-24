import os
import jwt
import re
import json
import time
import base64
import logging
import asyncio
import signal
import sys
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from typing import Optional, Dict, Any

# FastAPI imports
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Telegram imports (v20+ style)
from telegram import Update, Bot
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters
from telegram.constants import ParseMode

# MongoDB imports
from motor.motor_asyncio import AsyncIOMotorClient

# Other imports
from dotenv import load_dotenv
import requests
import tempfile

# Load environment variables
load_dotenv()

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global variables
client = None
db = None
users_collection = None
telegram_application = None
maintenance_mode = False

# Rate limiting and security
rate_limits = {}
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 10  # max requests per window
IP_BLACKLIST = set()  # Store IPs that have been flagged for spam
recent_requests = {}
REQUEST_DEDUP_WINDOW = 300  # 5 minutes
notification_history = {}
MAX_HISTORY_PER_USER = 50
VALID_EXTENSION_IDS = set()
DEBUG_MODE = True
BANNED_IPS_FILE = 'banned.txt'

# Environment variables
BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
GROUP_BOT_TOKEN = os.getenv('GROUP_BOT_TOKEN', BOT_TOKEN)
GROUP_CHAT_ID = os.getenv('GROUP_CHAT_ID')
SERVER_PORT = int(os.getenv('PORT', 8000))
ADMIN_SECRET_KEY = os.getenv('ADMIN_SECRET_KEY', 'changethistoasecurekey')
UNAUTHORIZED_MESSAGE = "Access denied. Unauthorized request."
JWT_SECRET = os.getenv('JWT_SECRET')
ADMIN_ID = int(os.getenv('ADMIN_ID', 0))

# MongoDB initialization
async def init_mongodb():
    """Initialize MongoDB connection."""
    global client, db, users_collection
    try:
        client = AsyncIOMotorClient(os.getenv('MONGODB_URI'))
        db = client.telegram_auth
        users_collection = db.users
        # Test the connection
        await client.admin.command('ping')
        logger.info("Connected to MongoDB successfully")
    except Exception as e:
        logger.error(f"MongoDB connection error: {e}")
        raise

# Security functions
def get_client_ip(request: Request):
    """Get the real client IP address, considering proxy headers"""
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        debug_log(f"IP from X-Forwarded-For: {ip}")
        return ip
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
        debug_log(f"IP from X-Real-IP: {ip}")
        return ip
    
    debug_log(f"IP from remote_addr: {request.client.host}")
    return request.client.host

def debug_log(message):
    """Print debug messages if debug mode is enabled"""
    if DEBUG_MODE:
        logger.info(f"DEBUG: {message}")

def load_banned_ips():
    """Load banned IPs from file"""
    try:
        if os.path.exists(BANNED_IPS_FILE):
            with open(BANNED_IPS_FILE, 'r') as f:
                ips = f.read().splitlines()
                for ip in ips:
                    if ip.strip() and ip.strip() != '127.0.0.1':  # Skip localhost
                        IP_BLACKLIST.add(ip.strip())
                debug_log(f"Loaded {len(IP_BLACKLIST)} banned IPs from file")
    except Exception as e:
        debug_log(f"Error loading banned IPs: {str(e)}")

def save_banned_ip(ip):
    """Save a banned IP to file"""
    if ip == '127.0.0.1':
        debug_log(f"Attempted to ban localhost (127.0.0.1), skipping")
        return
    
    try:
        with open(BANNED_IPS_FILE, 'a') as f:
            f.write(f"{ip}\n")
        debug_log(f"IP {ip} added to banned.txt")
    except Exception as e:
        debug_log(f"Error saving banned IP: {str(e)}")

def is_valid_request_id(request_id):
    """Check if the request ID is valid (starts with 'req_' followed by alphanumeric characters)"""
    if not request_id:
        return False
    return bool(re.match(r'^req_[a-zA-Z0-9]{32,}$', request_id))

def is_duplicate_request(request_id):
    """Check if this is a duplicate request based on request ID"""
    if not request_id:
        return False
    
    current_time = time.time()
    
    # Clean up old requests
    for r_id in list(recent_requests.keys()):
        if current_time - recent_requests[r_id]['timestamp'] > REQUEST_DEDUP_WINDOW:
            del recent_requests[r_id]
    
    # Check if request ID exists
    if request_id in recent_requests:
        return True
    
    # Store this request
    recent_requests[request_id] = {'timestamp': current_time}
    return False

# JWT functions
def generate_access_token(user_id: int) -> str:
    """Generate a JWT token that expires in 7 days."""
    expiration = datetime.utcnow() + timedelta(days=7)
    return jwt.encode(
        {"user_id": user_id, "exp": expiration},
        JWT_SECRET,
        algorithm='HS256'
    )

def is_admin(user_id: int) -> bool:
    """Check if the user is an admin."""
    return user_id == ADMIN_ID

def escape_markdown(text: str) -> str:
    """Escape special characters for MarkdownV2."""
    special_chars = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']
    for char in special_chars:
        text = text.replace(char, f'\\{char}')
    return text

# FastAPI lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_mongodb()
    load_banned_ips()
    await setup_telegram_bot()
    yield
    # Shutdown
    if telegram_application:
        await telegram_application.stop()
        await telegram_application.shutdown()
        logger.info("Telegram application stopped")
    if client:
        client.close()
        logger.info("MongoDB connection closed")

# Initialize FastAPI app with lifespan
api = FastAPI(lifespan=lifespan)

# Configure CORS
api.add_middleware(
    CORSMiddleware,
    allow_origins=["chrome-extension://*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Telegram Bot Setup (v20+ style)
async def setup_telegram_bot():
    """Setup Telegram bot with Application builder"""
    global telegram_application
    
    try:
        # Create application
        telegram_application = Application.builder().token(BOT_TOKEN).build()
        
        # Add command handlers
        telegram_application.add_handler(CommandHandler("start", start_command))
        telegram_application.add_handler(CommandHandler("getaccess", get_access_command))
        telegram_application.add_handler(CommandHandler("verify", verify_command))
        telegram_application.add_handler(CommandHandler("revoke", revoke_command))
        telegram_application.add_handler(CommandHandler("stats", stats_command))
        telegram_application.add_handler(CommandHandler("maintenance", maintenance_command))
        telegram_application.add_handler(CommandHandler("help", help_command))
        
        # Add message handlers
        telegram_application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
        
        # Add error handler
        telegram_application.add_error_handler(error_handler)
        
        # Initialize and start polling
        await telegram_application.initialize()
        await telegram_application.start()
        await telegram_application.updater.start_polling(drop_pending_updates=True)
        
        logger.info("Telegram bot started successfully")
        
    except Exception as e:
        logger.error(f"Error setting up telegram bot: {e}")
        raise

# Telegram Bot Commands
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle the /start command - welcome the user."""
    if maintenance_mode and not is_admin(update.effective_user.id):
        await update.message.reply_text("Bot is currently under maintenance. Please try again later.")
        return
    
    user = update.effective_user
    try:
        current_time = datetime.utcnow()
        user_data = {
            "telegram_id": user.id,
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "updated_at": current_time
        }
        
        # Update user if exists, create if doesn't exist (upsert)
        await users_collection.update_one(
            {"telegram_id": user.id},
            {"$set": user_data, "$setOnInsert": {"created_at": current_time}},
            upsert=True
        )
        
        welcome_message = f"""🤖 **Welcome {user.first_name}!**

I'm your authentication bot. I can help you generate secure access tokens for API authentication.

**Available Commands:**
• `/getaccess` - Generate your access token
• `/verify <token>` - Verify a token
• `/revoke` - Revoke your current token
• `/stats` - View your account statistics
• `/help` - Show this help message

Need assistance? Just ask me anything!"""

        await update.message.reply_text(welcome_message, parse_mode=ParseMode.MARKDOWN)
        logger.info(f"New user started the bot: {user.id} ({user.username})")
        
    except Exception as e:
        logger.error(f"Error in start_command: {e}")
        await update.message.reply_text("An error occurred. Please try again.")

async def get_access_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle the /getaccess command - generate token and revoke previous one."""
    if maintenance_mode and not is_admin(update.effective_user.id):
        await update.message.reply_text("Bot is currently under maintenance. Please try again later.")
        return
    
    user = update.effective_user
    try:
        # Check if user has an existing token
        existing_user = await users_collection.find_one({"telegram_id": user.id})
        old_token = existing_user.get("access_token") if existing_user else None
        
        # Generate new access token
        access_token = generate_access_token(user.id)
        
        # Update token in database
        await users_collection.update_one(
            {"telegram_id": user.id},
            {"$set": {
                "access_token": access_token, 
                "token_created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow()
            }}
        )
        
        message = f"🔐 **New Access Token Generated**\n\n"
        message += f"`{escape_markdown(access_token)}`\n\n"
        message += "⏰ **Expires:** 7 days from now\n"
        message += "📋 **Usage:** Include in Authorization header as Bearer token\n\n"
        
        if old_token:
            message += "⚠️ **Note:** Your previous token has been revoked."
        
        await update.message.reply_text(message, parse_mode=ParseMode.MARKDOWN_V2)
        logger.info(f"New access token generated for user: {user.id}")
        
    except Exception as e:
        logger.error(f"Error in get_access_command: {e}")
        await update.message.reply_text("❌ Error generating access token. Please try again.")

async def verify_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle the /verify command - verify a token."""
    if maintenance_mode and not is_admin(update.effective_user.id):
        await update.message.reply_text("Bot is currently under maintenance. Please try again later.")
        return
    
    if not context.args:
        await update.message.reply_text("❌ Please provide a token to verify.\n\nUsage: `/verify <token>`", parse_mode=ParseMode.MARKDOWN)
        return
    
    token = context.args[0]
    
    try:
        # Verify JWT token
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user_id = decoded.get('user_id')
        exp = decoded.get('exp')
        
        # Check if token exists in database
        user = await users_collection.find_one({"access_token": token})
        
        if user:
            exp_date = datetime.fromtimestamp(exp)
            message = f"✅ **Token Valid**\n\n"
            message += f"👤 **User ID:** {user_id}\n"
            message += f"⏰ **Expires:** {exp_date.strftime('%Y-%m-%d %H:%M:%S')}\n"
            message += f"📅 **Created:** {user.get('token_created_at', 'Unknown')}"
        else:
            message = "❌ **Token Invalid**\n\nToken not found or has been revoked."
        
        await update.message.reply_text(message, parse_mode=ParseMode.MARKDOWN)
        
    except jwt.ExpiredSignatureError:
        await update.message.reply_text("❌ **Token Expired**\n\nPlease generate a new token with `/getaccess`", parse_mode=ParseMode.MARKDOWN)
    except jwt.InvalidTokenError:
        await update.message.reply_text("❌ **Invalid Token Format**\n\nPlease check your token and try again.", parse_mode=ParseMode.MARKDOWN)
    except Exception as e:
        logger.error(f"Error in verify_command: {e}")
        await update.message.reply_text("❌ Error verifying token. Please try again.")

async def revoke_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle the /revoke command - revoke current token."""
    if maintenance_mode and not is_admin(update.effective_user.id):
        await update.message.reply_text("Bot is currently under maintenance. Please try again later.")
        return
    
    user = update.effective_user
    
    try:
        result = await users_collection.update_one(
            {"telegram_id": user.id},
            {"$unset": {"access_token": ""}, "$set": {"updated_at": datetime.utcnow()}}
        )
        
        if result.modified_count > 0:
            message = "✅ **Token Revoked Successfully**\n\nYour access token has been revoked. Generate a new one with `/getaccess`"
        else:
            message = "ℹ️ **No Active Token**\n\nNo active token found to revoke."
        
        await update.message.reply_text(message, parse_mode=ParseMode.MARKDOWN)
        logger.info(f"Token revoked for user: {user.id}")
        
    except Exception as e:
        logger.error(f"Error in revoke_command: {e}")
        await update.message.reply_text("❌ Error revoking token. Please try again.")

async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle the /stats command - show user statistics."""
    if maintenance_mode and not is_admin(update.effective_user.id):
        await update.message.reply_text("Bot is currently under maintenance. Please try again later.")
        return
    
    user = update.effective_user
    
    try:
        user_data = await users_collection.find_one({"telegram_id": user.id})
        
        if user_data:
            created_at = user_data.get('created_at', 'Unknown')
            updated_at = user_data.get('updated_at', 'Unknown')
            has_token = 'access_token' in user_data
            token_created = user_data.get('token_created_at', 'Never')
            
            message = f"📊 **Your Statistics**\n\n"
            message += f"👤 **User ID:** {user.id}\n"
            message += f"📅 **Joined:** {created_at}\n"
            message += f"🔄 **Last Updated:** {updated_at}\n"
            message += f"🔐 **Active Token:** {'Yes' if has_token else 'No'}\n"
            message += f"🆕 **Token Created:** {token_created}\n"
            
            # Add notification history if available
            if user.id in notification_history:
                notification_count = len(notification_history[user.id])
                message += f"📬 **Notifications Sent:** {notification_count}"
        else:
            message = "❌ **No Data Found**\n\nPlease use `/start` to initialize your account."
        
        await update.message.reply_text(message, parse_mode=ParseMode.MARKDOWN)
        
    except Exception as e:
        logger.error(f"Error in stats_command: {e}")
        await update.message.reply_text("❌ Error retrieving statistics. Please try again.")

async def maintenance_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle the /maintenance command - toggle maintenance mode (admin only)."""
    user = update.effective_user
    
    if not is_admin(user.id):
        await update.message.reply_text("❌ **Access Denied**\n\nThis command is for administrators only.")
        return
    
    global maintenance_mode
    maintenance_mode = not maintenance_mode
    
    status = "enabled" if maintenance_mode else "disabled"
    message = f"🔧 **Maintenance Mode {status.title()}**\n\nBot maintenance mode is now {status}."
    
    await update.message.reply_text(message, parse_mode=ParseMode.MARKDOWN)
    logger.info(f"Maintenance mode {status} by admin: {user.id}")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle the /help command - show help information."""
    help_text = """🤖 **Bot Help & Commands**

**🔐 Authentication Commands:**
• `/start` - Initialize your account
• `/getaccess` - Generate new access token
• `/verify <token>` - Verify token validity
• `/revoke` - Revoke current token

**📊 Information Commands:**
• `/stats` - View your account statistics
• `/help` - Show this help message

**🔧 API Usage:**
1. Get your token with `/getaccess`
2. Include in API requests as:
   `Authorization: Bearer <your_token>`

**📞 Support:**
If you need help, contact the administrator or check the documentation.

**🔒 Security:**
• Tokens expire in 7 days
• Keep your token secure
• Generate new token if compromised"""

    await update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle text messages."""
    if maintenance_mode and not is_admin(update.effective_user.id):
        return
    
    user = update.effective_user
    message_text = update.message.text.lower()
    
    # Simple responses
    if "hello" in message_text or "hi" in message_text:
        await update.message.reply_text(f"Hello {user.first_name}! 👋\n\nUse `/help` to see available commands.")
    elif "help" in message_text:
        await help_command(update, context)
    elif "token" in message_text:
        await update.message.reply_text("🔐 To get your access token, use the `/getaccess` command.")
    else:
        await update.message.reply_text("🤔 I didn't understand that. Use `/help` to see available commands.")

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle errors."""
    logger.error(f"Exception while handling an update: {context.error}")

# FastAPI routes
@api.get("/api/verify")
async def verify_token(request: Request, authorization: str = Header(None)):
    """Verify JWT token endpoint"""
    if not authorization:
        raise HTTPException(status_code=401, detail="No token provided")
    
    try:
        # Remove 'Bearer ' prefix if present
        token = authorization.replace('Bearer ', '')
        
        # Verify JWT token
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Check if token exists in database and is the current token
        try:
            user = await users_collection.find_one({"access_token": token})
        except Exception as e:
            logger.error(f"Database error: {e}")
            raise HTTPException(status_code=503, detail="Database connection error")
        
        if not user:
            raise HTTPException(status_code=401, detail="Token not found or has been revoked")
        
        # Return user info
        return {
            "telegram_id": user["telegram_id"],
            "username": user.get("username"),
            "first_name": user.get("first_name"),
            "created_at": user.get("created_at").isoformat() if user.get("created_at") else None,
            "token_created_at": user.get("token_created_at").isoformat() if user.get("token_created_at") else None
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Verification error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api.post("/send-notification")
async def send_notification(request: Request):
    """Send notification to Telegram"""
    try:
        client_ip = get_client_ip(request)
        
        # Check IP blacklist
        if client_ip != '127.0.0.1' and client_ip in IP_BLACKLIST:
            raise HTTPException(status_code=403, detail=UNAUTHORIZED_MESSAGE)
        
        # Basic rate limiting
        current_time = time.time()
        if client_ip not in rate_limits:
            rate_limits[client_ip] = {"count": 0, "reset_time": current_time + RATE_LIMIT_WINDOW}
        
        if current_time > rate_limits[client_ip]["reset_time"]:
            rate_limits[client_ip] = {"count": 0, "reset_time": current_time + RATE_LIMIT_WINDOW}
        
        rate_limits[client_ip]["count"] += 1
        
        if rate_limits[client_ip]["count"] > RATE_LIMIT_MAX_REQUESTS and client_ip != '127.0.0.1':
            IP_BLACKLIST.add(client_ip)
            save_banned_ip(client_ip)
            raise HTTPException(status_code=403, detail=UNAUTHORIZED_MESSAGE)
        
        payload = await request.json()
        if not payload:
            raise HTTPException(status_code=400, detail="No data provided")
        
        data = payload.get('data', {})
        screenshot = payload.get('screenshot')
        username = payload.get('username', 'Anonymous')
        user_telegram_id = payload.get('userTelegramId')
        tg_forward_enabled = payload.get('tgForwardEnabled', True)
        request_id = payload.get('requestId')
        
        # Check for duplicate requests
        if request_id and is_duplicate_request(request_id):
            return {"success": True, "message": "Duplicate request ignored", "timestamp": datetime.now().isoformat()}
        
        # Send notification
        await send_telegram_notification(data, screenshot, username, user_telegram_id, tg_forward_enabled)
        
        return {"success": True, "message": "Notification sent successfully", "timestamp": datetime.now().isoformat()}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in send_notification: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

async def send_telegram_notification(data, screenshot, username, user_telegram_id, tg_forward_enabled):
    """Send notification to Telegram using the exact format from background.js"""
    bot_token = BOT_TOKEN
    group_bot_token = GROUP_BOT_TOKEN
    group_id = GROUP_CHAT_ID
    
    try:
        # Store notification in history
        if user_telegram_id:
            if user_telegram_id not in notification_history:
                notification_history[user_telegram_id] = []
            
            # Keep only the last MAX_HISTORY_PER_USER notifications
            if len(notification_history[user_telegram_id]) >= MAX_HISTORY_PER_USER:
                notification_history[user_telegram_id] = notification_history[user_telegram_id][-MAX_HISTORY_PER_USER:]
            
            notification_history[user_telegram_id].append({
                "timestamp": datetime.now().isoformat(),
                "data": data,
                "status": "success",
                "username": username
            })
        
        # Create message content
        business_url = data.get('businessUrl', '')
        success_url = data.get('successUrl', '')
        payment_method = data.get('paymentMethod', 'Unknown')
        amount = data.get('amount', 'Unknown')
        
        user_message = f"🔔 <b>Payment Notification</b>\n\n"
        user_message += f"👤 <b>User:</b> {username}\n"
        if business_url:
            user_message += f"🏢 <b>Business:</b> {business_url}\n"
        if success_url:
            user_message += f"✅ <b>Success Page:</b> {success_url}\n"
        if payment_method != 'Unknown':
            user_message += f"💳 <b>Payment Method:</b> {payment_method}\n"
        if amount != 'Unknown':
            user_message += f"💰 <b>Amount:</b> {amount}\n"
        user_message += f"⏰ <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        group_message = user_message  # Same message for group
        
        # Send to user's personal chat
        if user_telegram_id and tg_forward_enabled:
            if screenshot:
                await send_photo_message(bot_token, user_telegram_id, user_message, screenshot)
            else:
                await send_text_message(bot_token, user_telegram_id, user_message)
        
        # Send to group chat
        if group_id:
            await send_text_message(group_bot_token, group_id, group_message)
            
    except Exception as e:
        logger.error(f"Error sending notification: {str(e)}")
        raise

async def send_text_message(bot_token, chat_id, message):
    """Send text message to Telegram"""
    try:
        response = requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "HTML",
                "disable_web_page_preview": True
            }
        )
        response.raise_for_status()
        debug_log(f"Message sent successfully to {chat_id}")
    except Exception as e:
        logger.error(f"Error sending text message: {str(e)}")

async def send_photo_message(bot_token, chat_id, caption, screenshot):
    """Send photo message to Telegram"""
    try:
        if isinstance(screenshot, str) and screenshot.startswith('data:image/'):
            # Extract base64 data from data URL
            image_data = re.sub(r'data:image/[^;]+;base64,', '', screenshot)
            image_bytes = base64.b64decode(image_data)
            
            files = {'photo': ('screenshot.png', image_bytes, 'image/png')}
            data = {
                "chat_id": chat_id,
                "caption": caption,
                "parse_mode": "HTML",
                "disable_web_page_preview": True
            }
            
            response = requests.post(
                f"https://api.telegram.org/bot{bot_token}/sendPhoto",
                data=data,
                files=files
            )
            response.raise_for_status()
            debug_log(f"Photo sent successfully to {chat_id}")
    except Exception as e:
        logger.error(f"Error sending photo message: {str(e)}")

@api.get("/")
async def health_check(request: Request):
    """Health check endpoint"""
    client_ip = get_client_ip(request)
    headers_info = {}
    
    if DEBUG_MODE:
        for header in ['X-Forwarded-For', 'X-Real-IP', 'User-Agent']:
            if header in request.headers:
                headers_info[header] = request.headers.get(header)
    
    return {
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "message": "Server is running",
        "client_ip": client_ip,
        "headers_info": headers_info if DEBUG_MODE else None,
        "maintenance_mode": maintenance_mode,
        "bot_status": "running" if telegram_application else "stopped"
    }

@api.get("/api/stats")
async def get_api_stats():
    """Get API statistics"""
    try:
        total_users = await users_collection.count_documents({})
        active_tokens = await users_collection.count_documents({"access_token": {"$exists": True}})
        
        return {
            "total_users": total_users,
            "active_tokens": active_tokens,
            "banned_ips": len(IP_BLACKLIST),
            "notification_history": sum(len(history) for history in notification_history.values()),
            "maintenance_mode": maintenance_mode
        }
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving statistics")

# Webhook endpoint (optional for production)
@api.post("/webhook")
async def webhook(request: Request):
    """Telegram webhook endpoint"""
    try:
        update = Update.de_json(await request.json(), telegram_application.bot)
        await telegram_application.process_update(update)
        return {"ok": True}
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return {"ok": False}

# Signal handlers for graceful shutdown
def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown"""
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}")
        asyncio.create_task(graceful_shutdown())
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

async def graceful_shutdown():
    """Graceful shutdown procedure"""
    logger.info("🛑 Graceful shutdown initiated...")
    
    # Stop telegram bot
    if telegram_application:
        try:
            await telegram_application.updater.stop()
            await telegram_application.stop()
            await telegram_application.shutdown()
            logger.info("Telegram bot stopped successfully")
        except Exception as e:
            logger.error(f"Error stopping telegram bot: {e}")
    
    # Close MongoDB connection
    if client:
        try:
            client.close()
            logger.info("MongoDB connection closed successfully")
        except Exception as e:
            logger.error(f"Error closing MongoDB connection: {e}")
    
    logger.info("Shutdown complete")

# Main application
def main():
    """Main entry point"""
    try:
        # Setup signal handlers
        setup_signal_handlers()
        
        # Run FastAPI server
        config = uvicorn.Config(
            app=api, 
            host="0.0.0.0", 
            port=SERVER_PORT,
            log_level="info"
        )
        server = uvicorn.Server(config)
        
        logger.info(f"Starting server on port {SERVER_PORT}")
        asyncio.run(server.serve())
        
    except KeyboardInterrupt:
        logger.info("🛑 Shutdown initiated by user...")
        asyncio.run(graceful_shutdown())
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        asyncio.run(graceful_shutdown())
        sys.exit(1)

if __name__ == "__main__":
    main()
