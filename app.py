import os
import jwt
import re
import json
import time
import base64
import tempfile
import logging
import asyncio
import signal
import sys
from datetime import datetime, timedelta
from functools import wraps
from contextlib import asynccontextmanager

# FastAPI imports
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Telegram imports
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

# MongoDB imports
from motor.motor_asyncio import AsyncIOMotorClient

# Other imports
from dotenv import load_dotenv
import requests

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
bot = None
api_server = None
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
BOT_TOKEN = os.getenv('BOT_TOKEN')
GROUP_BOT_TOKEN = os.getenv('GROUP_BOT_TOKEN', BOT_TOKEN)
GROUP_CHAT_ID = os.getenv('GROUP_CHAT_ID')
SERVER_PORT = int(os.getenv('PORT', 8000))  # Render uses PORT
ADMIN_SECRET_KEY = os.getenv('ADMIN_SECRET_KEY', 'changethistoasecurekey')
UNAUTHORIZED_MESSAGE = "Access denied. Unauthorized request."

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
        print("Connected to MongoDB")
    except Exception as e:
        print(f"MongoDB connection error: {e}")
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
        print(f"DEBUG: {message}")

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

# FastAPI lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_mongodb()
    load_banned_ips()
    yield
    # Shutdown
    if client:
        await client.close()
        print("MongoDB connection closed")

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

# JWT functions
def generate_access_token(user_id: int) -> str:
    """Generate a JWT token that expires in 7 days."""
    expiration = datetime.utcnow() + timedelta(days=7)
    return jwt.encode(
        {"user_id": user_id, "exp": expiration},
        os.getenv('JWT_SECRET'),
        algorithm='HS256'
    )

def is_admin(user_id: int) -> bool:
    """Check if the user is an admin."""
    return str(user_id) == os.getenv('ADMIN_ID')

def escape_markdown(text: str) -> str:
    """Escape special characters for MarkdownV2."""
    special_chars = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!']
    for char in special_chars:
        text = text.replace(char, f'\\{char}')
    return text

# FastAPI routes
@api.get("/api/verify")
async def verify_token(request: Request, authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="No token provided")
    
    try:
        # Remove 'Bearer ' prefix if present
        token = authorization.replace('Bearer ', '')
        
        # Verify JWT token
        try:
            decoded = jwt.decode(token, os.getenv('JWT_SECRET'), algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token has expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Check if token exists in database and is the current token
        try:
            user = await users_collection.find_one({"access_token": token})
        except Exception as e:
            print(f"Database error: {e}")
            raise HTTPException(status_code=503, detail="Database connection error")
        
        if not user:
            raise HTTPException(status_code=401, detail="Token not found or has been revoked")
        
        # Return user info
        return {
            "telegram_id": user["telegram_id"],
            "username": user.get("username"),
            "created_at": user.get("created_at").isoformat() if user.get("created_at") else None
        }
    except Exception as e:
        print(f"Verification error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api.post("/send-notification")
async def send_notification(request: Request):
    """Send notification to Telegram"""
    try:
        client_ip = get_client_ip(request)
        
        # Check IP blacklist
        if client_ip != '127.0.0.1' and client_ip in IP_BLACKLIST:
            return {"error": "Access denied", "message": UNAUTHORIZED_MESSAGE}, 403
        
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
            return {"error": "Access denied", "message": UNAUTHORIZED_MESSAGE}, 403
        
        payload = await request.json()
        if not payload:
            return {"error": "No data provided"}, 400
        
        data = payload.get('data', {})
        screenshot = payload.get('screenshot')
        username = payload.get('username', 'Anonymous')
        user_telegram_id = payload.get('userTelegramId')
        tg_forward_enabled = payload.get('tgForwardEnabled', True)
        
        # Send notification
        await send_telegram_notification(data, screenshot, username, user_telegram_id, tg_forward_enabled)
        
        return {"success": True, "message": "Notification sent successfully", "timestamp": datetime.now().isoformat()}
    except Exception as e:
        debug_log(f"Error in send_notification: {str(e)}")
        return {"error": str(e)}, 500

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
                "username": username  # Store username for reference
            })
        
        # Create message content
        business_url = data.get('businessUrl', '')
        success_url = data.get('successUrl', '')
        
        # Ensure we have valid URLs
        if not business_url or business_url.strip():
            business_url = ""
        if not success_url or success_url.strip():
            success_url = ""
        
        user_message = f"🔔 <b>Payment Notification</b>\n\n"
        user_message += f"👤 <b>User:</b> {username}\n"
        if business_url:
            user_message += f"🏢 <b>Business:</b> {business_url}\n"
        if success_url:
            user_message += f"✅ <b>Success Page:</b> {success_url}\n"
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
        debug_log(f"Error sending notification: {str(e)}")

async def send_text_message(bot_token, chat_id, message):
    """Send text message to Telegram"""
    try:
        debug_log(f"Sending text message to chat_id: {chat_id}")
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
        debug_log(f"Message sent successfully: {response.status_code}")
    except Exception as e:
        debug_log(f"Error sending text message: {str(e)}")

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
    except Exception as e:
        debug_log(f"Error sending photo message: {str(e)}")

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
        "headers_info": headers_info if DEBUG_MODE else None
    }

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
            "updated_at": current_time
        }
        
        # Update user if exists, create if doesn't exist (upsert)
        await users_collection.update_one(
            {"telegram_id": user.id},
            {"$set": user_data, "$setOnInsert": {"created_at": current_time}},
            upsert=True
        )
        
        welcome_message = f"""Welcome {user.first_name}! 

I'm your authentication bot. I can help you generate secure access tokens for API authentication.

• Use /getaccess to generate your access token
• Use /verify <token> to verify a token
• Need help? Just type /help"""

        await update.message.reply_text(welcome_message)
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
            {"$set": {"access_token": access_token, "updated_at": datetime.utcnow()}}
        )
        
        message = f"Here's your new access token:\n\n`{escape_markdown(access_token)}`\n\n"
        message += "This token will expire in 7 days.\n"
        message += "The token is in a monospace block for easy copying."
        
        if old_token:
            message += "\n\n⚠️ Your previous token has been revoked."
        
        await update.message.reply_text(message, parse_mode='MarkdownV2')
        logger.info(f"New access token generated for user: {user.id}")
        
    except Exception as e:
        logger.error(f"Error in get_access_command: {e}")
        await update.message.reply_text("Error generating access token. Please try again.")

# Additional command handlers would go here...

class TelegramBot:
    def __init__(self):
        self.application = None
        self.running = False
    
    async def start(self):
        """Start the Telegram bot."""
        if self.running:
            return
        
        try:
            print("Starting Telegram bot...")
            self.application = Application.builder().token(os.getenv('TELEGRAM_BOT_TOKEN')).build()
            
            # Add handlers
            self.application.add_handler(CommandHandler("start", start_command))
            self.application.add_handler(CommandHandler("getaccess", get_access_command))
            # Add more handlers as needed...
            
            await self.application.initialize()
            await self.application.start()
            await self.application.updater.start_polling()
            self.running = True
            print("Telegram bot started successfully")
            logger.info("Telegram bot started successfully")
            
        except Exception as e:
            logger.error(f"Error starting Telegram bot: {e}")
            print(f"Error starting Telegram bot: {e}")
            raise
    
    async def stop(self):
        """Stop the Telegram bot."""
        if not self.running:
            return
        
        try:
            print("Stopping Telegram bot...")
            if self.application and self.application.updater:
                await self.application.updater.stop()
            if self.application:
                await self.application.stop()
                await self.application.shutdown()
            self.running = False
            print("Telegram bot stopped successfully")
            logger.info("Telegram bot stopped successfully")
            
        except Exception as e:
            logger.error(f"Error stopping Telegram bot: {e}")
            print(f"Error stopping Telegram bot: {e}")

async def run_services():
    """Run both services concurrently."""
    global bot
    
    try:
        # Initialize services
        bot = TelegramBot()
        
        # Create tasks for both services
        bot_task = asyncio.create_task(bot.start())
        
        # Start FastAPI server
        config = uvicorn.Config(app=api, host="0.0.0.0", port=SERVER_PORT, loop="asyncio")
        server = uvicorn.Server(config)
        api_task = asyncio.create_task(server.serve())
        
        # Wait for both services to complete
        await asyncio.gather(bot_task, api_task)
        
    except Exception as e:
        print(f"Error starting services: {e}")
        await shutdown()
        sys.exit(1)

async def shutdown():
    """Shutdown all services gracefully."""
    print("🛑 Graceful shutdown...")
    
    shutdown_tasks = []
    
    if bot:
        shutdown_tasks.append(asyncio.create_task(bot.stop()))
    
    if client:
        try:
            await client.close()
            print("MongoDB connection closed")
        except Exception as e:
            print(f"Error closing MongoDB connection: {e}")
    
    if shutdown_tasks:
        await asyncio.gather(*shutdown_tasks, return_exceptions=True)

def handle_signals():
    """Setup signal handlers."""
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda s, f: asyncio.create_task(shutdown()))

def main():
    """Main entry point."""
    try:
        # Set up signal handlers
        handle_signals()
        
        # Create and set event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Run services
        loop.run_until_complete(run_services())
        loop.run_forever()
        
    except KeyboardInterrupt:
        print("🛑 Shutdown initiated by user...")
        loop.run_until_complete(shutdown())
        print("Shutdown complete.")
    except Exception as e:
        print(f"Fatal error: {e}")
        if loop.is_running():
            loop.run_until_complete(shutdown())
        sys.exit(1)
    finally:
        loop.close()

if __name__ == "__main__":
    main()

