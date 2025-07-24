const express = require('express');
const { Telegraf, Markup } = require('telegraf');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('rate-limiter-flexible');
const winston = require('winston');
const axios = require('axios');
const moment = require('moment');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

// ====================================
// CONFIGURATION & SETUP
// ====================================

const PORT = process.env.PORT || 8000;
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const GROUP_CHAT_ID = process.env.GROUP_CHAT_ID;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_ID = parseInt(process.env.ADMIN_ID) || 0;
const MONGODB_URI = process.env.MONGODB_URI;

// Logger setup
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'telegram-bot-api' },
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' }),
        new winston.transports.Console({
            format: winston.format.simple()
        })
    ]
});

// Rate limiting
const rateLimiter = new rateLimit.RateLimiterMemory({
    keyGenerator: (req) => req.ip,
    points: 10, // Number of requests
    duration: 60, // Per 60 seconds
});

// Global variables
let maintenanceMode = false;
const notificationHistory = new Map();
const bannedIPs = new Set();
const recentRequests = new Map();

// ====================================
// MONGODB MODELS
// ====================================

// User Schema
const userSchema = new mongoose.Schema({
    telegramId: { type: Number, required: true, unique: true },
    username: String,
    firstName: String,
    lastName: String,
    accessToken: String,
    tokenCreatedAt: Date,
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true }
});

const User = mongoose.model('User', userSchema);

// Notification Schema
const notificationSchema = new mongoose.Schema({
    userId: Number,
    username: String,
    data: Object,
    screenshot: String,
    sentAt: { type: Date, default: Date.now },
    status: { type: String, default: 'sent' }
});

const Notification = mongoose.model('Notification', notificationSchema);

// ====================================
// DATABASE CONNECTION
// ====================================

async function connectDB() {
    try {
        await mongoose.connect(MONGODB_URI);
        logger.info('✅ Connected to MongoDB successfully');
    } catch (error) {
        logger.error('❌ MongoDB connection error:', error);
        process.exit(1);
    }
}

// ====================================
// TELEGRAM BOT SETUP
// ====================================

const bot = new Telegraf(BOT_TOKEN);

// Middleware untuk maintenance mode
bot.use(async (ctx, next) => {
    if (maintenanceMode && ctx.from.id !== ADMIN_ID) {
        return ctx.reply('🔧 Bot is currently under maintenance. Please try again later.');
    }
    return next();
});

// Error handling
bot.catch((err, ctx) => {
    logger.error(`❌ Bot error for ${ctx.updateType}:`, err);
});

// ====================================
// UTILITY FUNCTIONS
// ====================================

// Generate JWT token
function generateAccessToken(userId) {
    return jwt.sign(
        { 
            userId: userId, 
            exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60) // 7 days
        },
        JWT_SECRET
    );
}

// Verify JWT token
function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
}

// Check if user is admin
function isAdmin(userId) {
    return userId === ADMIN_ID;
}

// Escape markdown characters
function escapeMarkdown(text) {
    return text.replace(/[_*[\]()~`>#+\-=|{}.!\\]/g, '\\$&');
}

// Load banned IPs
function loadBannedIPs() {
    try {
        if (fs.existsSync('banned.txt')) {
            const data = fs.readFileSync('banned.txt', 'utf8');
            const ips = data.split('\n').filter(ip => ip.trim() && ip.trim() !== '127.0.0.1');
            ips.forEach(ip => bannedIPs.add(ip.trim()));
            logger.info(`📝 Loaded ${bannedIPs.size} banned IPs`);
        }
    } catch (error) {
        logger.error('Error loading banned IPs:', error);
    }
}

// Save banned IP
function saveBannedIP(ip) {
    if (ip === '127.0.0.1') return;
    
    try {
        fs.appendFileSync('banned.txt', ip + '\n');
        logger.info(`🚫 IP ${ip} added to banned list`);
    } catch (error) {
        logger.error('Error saving banned IP:', error);
    }
}

// Check duplicate requests
function isDuplicateRequest(requestId) {
    if (!requestId) return false;
    
    const now = Date.now();
    const fiveMinutesAgo = now - (5 * 60 * 1000);
    
    // Clean old requests
    for (const [id, timestamp] of recentRequests.entries()) {
        if (timestamp < fiveMinutesAgo) {
            recentRequests.delete(id);
        }
    }
    
    if (recentRequests.has(requestId)) {
        return true;
    }
    
    recentRequests.set(requestId, now);
    return false;
}

// ====================================
// TELEGRAM BOT COMMANDS
// ====================================

// /start command
bot.start(async (ctx) => {
    const user = ctx.from;
    
    try {
        // Update or create user
        await User.findOneAndUpdate(
            { telegramId: user.id },
            {
                telegramId: user.id,
                username: user.username,
                firstName: user.first_name,
                lastName: user.last_name,
                updatedAt: new Date()
            },
            { upsert: true, new: true }
        );

        const welcomeMessage = `🤖 **Welcome ${user.first_name}!**

I'm your authentication bot. I can help you generate secure access tokens for API authentication.

**Available Commands:**
• \`/getaccess\` - Generate your access token
• \`/verify <token>\` - Verify a token
• \`/revoke\` - Revoke your current token
• \`/stats\` - View your account statistics
• \`/help\` - Show this help message

Need assistance? Just ask me anything!`;

        await ctx.replyWithMarkdownV2(welcomeMessage);
        logger.info(`👤 New user started bot: ${user.id} (${user.username})`);

    } catch (error) {
        logger.error('Error in start command:', error);
        await ctx.reply('❌ An error occurred. Please try again.');
    }
});

// /getaccess command
bot.command('getaccess', async (ctx) => {
    const user = ctx.from;
    
    try {
        // Generate new token
        const accessToken = generateAccessToken(user.id);
        
        // Update user with new token
        await User.findOneAndUpdate(
            { telegramId: user.id },
            {
                accessToken: accessToken,
                tokenCreatedAt: new Date(),
                updatedAt: new Date()
            },
            { upsert: true }
        );

        const message = `🔐 **New Access Token Generated**

\`${escapeMarkdown(accessToken)}\`

⏰ **Expires:** 7 days from now
📋 **Usage:** Include in Authorization header as Bearer token

⚠️ **Note:** Your previous token has been revoked.`;

        await ctx.replyWithMarkdownV2(message);
        logger.info(`🔑 New token generated for user: ${user.id}`);

    } catch (error) {
        logger.error('Error in getaccess command:', error);
        await ctx.reply('❌ Error generating access token. Please try again.');
    }
});

// /verify command
bot.command('verify', async (ctx) => {
    const args = ctx.message.text.split(' ').slice(1);
    
    if (args.length === 0) {
        return ctx.reply('❌ Please provide a token to verify.\n\nUsage: `/verify <token>`');
    }

    const token = args[0];
    
    try {
        const decoded = verifyToken(token);
        
        if (!decoded) {
            return ctx.reply('❌ **Invalid Token**\n\nToken is malformed or has expired.');
        }

        // Check if token exists in database
        const user = await User.findOne({ accessToken: token });
        
        if (user) {
            const expDate = new Date(decoded.exp * 1000);
            const message = `✅ **Token Valid**

👤 **User ID:** ${decoded.userId}
⏰ **Expires:** ${moment(expDate).format('YYYY-MM-DD HH:mm:ss')}
📅 **Created:** ${moment(user.tokenCreatedAt).format('YYYY-MM-DD HH:mm:ss')}`;

            await ctx.reply(message);
        } else {
            await ctx.reply('❌ **Token Invalid**\n\nToken not found or has been revoked.');
        }

    } catch (error) {
        logger.error('Error in verify command:', error);
        await ctx.reply('❌ Error verifying token. Please try again.');
    }
});

// /revoke command
bot.command('revoke', async (ctx) => {
    const user = ctx.from;
    
    try {
        const result = await User.findOneAndUpdate(
            { telegramId: user.id },
            {
                $unset: { accessToken: "", tokenCreatedAt: "" },
                updatedAt: new Date()
            }
        );

        if (result && result.accessToken) {
            await ctx.reply('✅ **Token Revoked Successfully**\n\nYour access token has been revoked. Generate a new one with `/getaccess`');
        } else {
            await ctx.reply('ℹ️ **No Active Token**\n\nNo active token found to revoke.');
        }

        logger.info(`🗑️ Token revoked for user: ${user.id}`);

    } catch (error) {
        logger.error('Error in revoke command:', error);
        await ctx.reply('❌ Error revoking token. Please try again.');
    }
});

// /stats command
bot.command('stats', async (ctx) => {
    const user = ctx.from;
    
    try {
        const userData = await User.findOne({ telegramId: user.id });
        
        if (userData) {
            const notificationCount = await Notification.countDocuments({ userId: user.id });
            const hasToken = !!userData.accessToken;
            
            const message = `📊 **Your Statistics**

👤 **User ID:** ${user.id}
📅 **Joined:** ${moment(userData.createdAt).format('YYYY-MM-DD HH:mm:ss')}
🔄 **Last Updated:** ${moment(userData.updatedAt).format('YYYY-MM-DD HH:mm:ss')}
🔐 **Active Token:** ${hasToken ? 'Yes' : 'No'}
🆕 **Token Created:** ${userData.tokenCreatedAt ? moment(userData.tokenCreatedAt).format('YYYY-MM-DD HH:mm:ss') : 'Never'}
📬 **Notifications Sent:** ${notificationCount}`;

            await ctx.reply(message);
        } else {
            await ctx.reply('❌ **No Data Found**\n\nPlease use `/start` to initialize your account.');
        }

    } catch (error) {
        logger.error('Error in stats command:', error);
        await ctx.reply('❌ Error retrieving statistics. Please try again.');
    }
});

// /maintenance command (admin only)
bot.command('maintenance', async (ctx) => {
    if (!isAdmin(ctx.from.id)) {
        return ctx.reply('❌ **Access Denied**\n\nThis command is for administrators only.');
    }

    maintenanceMode = !maintenanceMode;
    const status = maintenanceMode ? 'enabled' : 'disabled';
    
    await ctx.reply(`🔧 **Maintenance Mode ${status.charAt(0).toUpperCase() + status.slice(1)}**\n\nBot maintenance mode is now ${status}.`);
    logger.info(`🔧 Maintenance mode ${status} by admin: ${ctx.from.id}`);
});

// /help command
bot.command('help', async (ctx) => {
    const helpText = `🤖 **Bot Help & Commands**

**🔐 Authentication Commands:**
• \`/start\` - Initialize your account
• \`/getaccess\` - Generate new access token
• \`/verify <token>\` - Verify token validity
• \`/revoke\` - Revoke current token

**📊 Information Commands:**
• \`/stats\` - View your account statistics
• \`/help\` - Show this help message

**🔧 API Usage:**
1\\. Get your token with \`/getaccess\`
2\\. Include in API requests as:
   \`Authorization: Bearer <your_token>\`

**📞 Support:**
If you need help, contact the administrator or check the documentation\\.

**🔒 Security:**
• Tokens expire in 7 days
• Keep your token secure
• Generate new token if compromised`;

    await ctx.replyWithMarkdownV2(helpText);
});

// Handle text messages
bot.on('text', async (ctx) => {
    const text = ctx.message.text.toLowerCase();
    const user = ctx.from;

    if (text.includes('hello') || text.includes('hi')) {
        await ctx.reply(`Hello ${user.first_name}! 👋\n\nUse /help to see available commands.`);
    } else if (text.includes('help')) {
        await ctx.telegram.callApi('sendMessage', {
            chat_id: ctx.chat.id,
            text: '/help'
        });
    } else if (text.includes('token')) {
        await ctx.reply('🔐 To get your access token, use the `/getaccess` command.');
    } else {
        await ctx.reply("🤔 I didn't understand that. Use `/help` to see available commands.");
    }
});

// ====================================
// EXPRESS API SETUP
// ====================================

const app = express();

// Middleware
app.use(helmet());
app.use(cors({
    origin: ['chrome-extension://*'],
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting middleware
app.use(async (req, res, next) => {
    try {
        await rateLimiter.consume(req.ip);
        next();
    } catch (rejRes) {
        const secs = Math.round(rejRes.msBeforeNext / 1000) || 1;
        res.set('Retry-After', String(secs));
        
        // Add to banned list if too many requests
        if (req.ip !== '127.0.0.1') {
            bannedIPs.add(req.ip);
            saveBannedIP(req.ip);
        }
        
        res.status(429).json({ error: 'Too many requests', message: 'Rate limit exceeded' });
    }
});

// IP blocking middleware
app.use((req, res, next) => {
    const clientIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
                     req.headers['x-real-ip'] || 
                     req.connection.remoteAddress || 
                     req.ip;

    if (bannedIPs.has(clientIP) && clientIP !== '127.0.0.1') {
        return res.status(403).json({ 
            error: 'Access denied', 
            message: 'IP address is banned' 
        });
    }

    req.clientIP = clientIP;
    next();
});

// ====================================
// API ROUTES
// ====================================

// Health check
app.get('/', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        message: 'Server is running',
        client_ip: req.clientIP,
        maintenance_mode: maintenanceMode,
        bot_status: 'running'
    });
});

// Verify token endpoint
app.get('/api/verify', async (req, res) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.replace('Bearer ', '');
    
    try {
        const decoded = verifyToken(token);
        
        if (!decoded) {
            return res.status(401).json({ error: 'Invalid or expired token' });
        }

        // Check if token exists in database
        const user = await User.findOne({ accessToken: token });
        
        if (!user) {
            return res.status(401).json({ error: 'Token not found or has been revoked' });
        }

        res.json({
            telegram_id: user.telegramId,
            username: user.username,
            first_name: user.firstName,
            created_at: user.createdAt,
            token_created_at: user.tokenCreatedAt
        });

    } catch (error) {
        logger.error('Token verification error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Send notification endpoint
app.post('/send-notification', async (req, res) => {
    try {
        const { data = {}, screenshot, username = 'Anonymous', userTelegramId, tgForwardEnabled = true, requestId } = req.body;

        // Check for duplicate requests
        if (requestId && isDuplicateRequest(requestId)) {
            return res.json({
                success: true,
                message: 'Duplicate request ignored',
                timestamp: new Date().toISOString()
            });
        }

        // Create notification message
        const businessUrl = data.businessUrl || '';
        const successUrl = data.successUrl || '';
        const paymentMethod = data.paymentMethod || 'Unknown';
        const amount = data.amount || 'Unknown';

        let message = `🔔 <b>Payment Notification</b>\n\n`;
        message += `👤 <b>User:</b> ${username}\n`;
        if (businessUrl) message += `🏢 <b>Business:</b> ${businessUrl}\n`;
        if (successUrl) message += `✅ <b>Success Page:</b> ${successUrl}\n`;
        if (paymentMethod !== 'Unknown') message += `💳 <b>Payment Method:</b> ${paymentMethod}\n`;
        if (amount !== 'Unknown') message += `💰 <b>Amount:</b> ${amount}\n`;
        message += `⏰ <b>Time:</b> ${moment().format('YYYY-MM-DD HH:mm:ss')}`;

        // Send to user's personal chat
        if (userTelegramId && tgForwardEnabled) {
            try {
                if (screenshot) {
                    // Convert base64 to buffer and send as photo
                    const base64Data = screenshot.replace(/^data:image\/[a-z]+;base64,/, '');
                    const buffer = Buffer.from(base64Data, 'base64');
                    
                    await bot.telegram.sendPhoto(userTelegramId, { source: buffer }, {
                        caption: message,
                        parse_mode: 'HTML'
                    });
                } else {
                    await bot.telegram.sendMessage(userTelegramId, message, { parse_mode: 'HTML' });
                }
            } catch (botError) {
                logger.error('Error sending to user:', botError);
            }
        }

        // Send to group chat
        if (GROUP_CHAT_ID) {
            try {
                await bot.telegram.sendMessage(GROUP_CHAT_ID, message, { parse_mode: 'HTML' });
            } catch (botError) {
                logger.error('Error sending to group:', botError);
            }
        }

        // Save notification to database
        const notification = new Notification({
            userId: userTelegramId,
            username,
            data,
            screenshot: screenshot ? 'included' : 'none',
            sentAt: new Date(),
            status: 'sent'
        });

        await notification.save();

        res.json({
            success: true,
            message: 'Notification sent successfully',
            timestamp: new Date().toISOString()
        });

        logger.info(`📬 Notification sent for user: ${username}`);

    } catch (error) {
        logger.error('Send notification error:', error);
        res.status(500).json({ error: 'Failed to send notification' });
    }
});

// API statistics
app.get('/api/stats', async (req, res) => {
    try {
        const totalUsers = await User.countDocuments({});
        const activeTokens = await User.countDocuments({ accessToken: { $exists: true } });
        const totalNotifications = await Notification.countDocuments({});

        res.json({
            total_users: totalUsers,
            active_tokens: activeTokens,
            total_notifications: totalNotifications,
            banned_ips: bannedIPs.size,
            maintenance_mode: maintenanceMode
        });

    } catch (error) {
        logger.error('Stats error:', error);
        res.status(500).json({ error: 'Error retrieving statistics' });
    }
});

// Webhook endpoint (optional)
app.post('/webhook', (req, res) => {
    try {
        bot.handleUpdate(req.body);
        res.json({ ok: true });
    } catch (error) {
        logger.error('Webhook error:', error);
        res.json({ ok: false });
    }
});

// ====================================
// STARTUP & SHUTDOWN
// ====================================

async function startup() {
    try {
        // Load banned IPs
        loadBannedIPs();
        
        // Connect to database
        await connectDB();
        
        // Start bot
        await bot.launch();
        logger.info('🤖 Telegram bot started successfully');
        
        // Start Express server
        app.listen(PORT, () => {
            logger.info(`🚀 Server running on port ${PORT}`);
            logger.info(`🌐 Health check: http://localhost:${PORT}/`);
        });

    } catch (error) {
        logger.error('❌ Startup error:', error);
        process.exit(1);
    }
}

// Graceful shutdown
function gracefulShutdown() {
    logger.info('🛑 Graceful shutdown initiated...');
    
    bot.stop('SIGTERM');
    mongoose.connection.close();
    
    logger.info('✅ Shutdown complete');
    process.exit(0);
}

// Signal handlers
process.once('SIGINT', gracefulShutdown);
process.once('SIGTERM', gracefulShutdown);

// Start the application
startup();
