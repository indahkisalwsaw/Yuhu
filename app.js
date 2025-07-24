const { Telegraf } = require('telegraf');
const express = require('express');
const { MongoClient } = require('mongodb');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const winston = require('winston');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

// ====================================
// LOGGING SETUP
// ====================================
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.printf(({ timestamp, level, message, stack }) => {
            return `${timestamp} [${level.toUpperCase()}]: ${stack || message}`;
        })
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.colorize({ all: true })
        }),
        new winston.transports.File({ filename: 'bot.log' })
    ]
});

// ====================================
// ENVIRONMENT VARIABLES
// ====================================
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_ID = parseInt(process.env.ADMIN_ID) || 0;
const PORT = process.env.PORT || 8000;
const GROUP_CHAT_ID = process.env.GROUP_CHAT_ID;
const DB_NAME = 'telegram_auth';

// Validate required environment variables
if (!BOT_TOKEN) {
    logger.error('❌ TELEGRAM_BOT_TOKEN is required');
    process.exit(1);
}

if (!JWT_SECRET) {
    logger.error('❌ JWT_SECRET is required');
    process.exit(1);
}

// ====================================
// GLOBAL VARIABLES
// ====================================
let bot = null;
let app = null;
let mongoClient = null;
let db = null;
let isShuttingDown = false;
let botStarted = false;

// ====================================
// UTILITY FUNCTIONS
// ====================================
function generateAccessToken(userId) {
    return jwt.sign(
        { 
            userId: userId, 
            exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60) // 7 days
        },
        JWT_SECRET
    );
}

function verifyToken(token) {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error) {
        return null;
    }
}

function isAdmin(userId) {
    return userId === ADMIN_ID;
}

function escapeMarkdown(text) {
    return text.replace(/[_*[\]()~`>#+\-=|{}.!\\]/g, '\\$&');
}

// ====================================
// MONGODB CONNECTION (Native Driver)
// ====================================
async function connectMongoDB() {
    try {
        if (!MONGODB_URI) {
            logger.warn('⚠️  MongoDB URI not provided, running without database');
            return false;
        }

        logger.info('🔄 Connecting to MongoDB...');
        logger.info(`🔗 URI: ${MONGODB_URI.replace(/:[^:]*@/, ':***@')}`);
        
        // Connection options
        const options = {
            serverSelectionTimeoutMS: 10000,
            socketTimeoutMS: 30000,
            connectTimeoutMS: 10000,
            maxPoolSize: 10,
            retryWrites: true,
            w: 'majority'
        };

        // Create MongoDB client
        mongoClient = new MongoClient(MONGODB_URI, options);
        
        // Connect with timeout
        const connectionPromise = mongoClient.connect();
        const timeoutPromise = new Promise((_, reject) => 
            setTimeout(() => reject(new Error('Connection timeout after 15 seconds')), 15000)
        );

        await Promise.race([connectionPromise, timeoutPromise]);

        // Get database
        db = mongoClient.db(DB_NAME);
        
        // Test connection
        await db.admin().ping();
        
        logger.info('✅ Connected to MongoDB successfully');
        logger.info(`📊 Database: ${DB_NAME}`);
        logger.info(`🌐 Host: ${mongoClient.s.options.hosts[0]}`);
        
        return true;

    } catch (error) {
        logger.error('❌ MongoDB connection failed:', {
            message: error.message,
            code: error.code
        });
        
        // Specific error handling
        if (error.message.includes('ENOTFOUND')) {
            logger.error('🌐 DNS Resolution failed - Check internet connection');
        } else if (error.message.includes('ECONNREFUSED')) {
            logger.error('🚫 Connection refused - Check MongoDB service');
        } else if (error.message.includes('Authentication failed')) {
            logger.error('🔐 Authentication failed - Check username/password');
        } else if (error.message.includes('timeout')) {
            logger.error('⏰ Connection timeout - Check network/firewall');
        }
        
        logger.warn('⚠️  Continuing without database...');
        return false;
    }
}

// ====================================
// DATABASE HELPER FUNCTIONS
// ====================================
async function findUser(telegramId) {
    if (!db) return null;
    try {
        return await db.collection('users').findOne({ telegramId: telegramId });
    } catch (error) {
        logger.error('❌ Error finding user:', error);
        return null;
    }
}

async function saveUser(userData) {
    if (!db) return null;
    try {
        return await db.collection('users').findOneAndUpdate(
            { telegramId: userData.telegramId },
            { 
                $set: {
                    ...userData,
                    updatedAt: new Date()
                },
                $setOnInsert: { createdAt: new Date() }
            },
            { upsert: true, returnDocument: 'after' }
        );
    } catch (error) {
        logger.error('❌ Error saving user:', error);
        return null;
    }
}

async function saveNotification(notificationData) {
    if (!db) return null;
    try {
        return await db.collection('notifications').insertOne({
            ...notificationData,
            sentAt: new Date()
        });
    } catch (error) {
        logger.error('❌ Error saving notification:', error);
        return null;
    }
}

async function getUserStats(telegramId) {
    if (!db) return { user: null, notificationCount: 0 };
    try {
        const user = await findUser(telegramId);
        const notificationCount = await db.collection('notifications').countDocuments({ 
            userId: telegramId 
        });
        return { user, notificationCount };
    } catch (error) {
        logger.error('❌ Error getting stats:', error);
        return { user: null, notificationCount: 0 };
    }
}

// ====================================
// TELEGRAM BOT SETUP
// ====================================
function setupTelegramBot() {
    logger.info('🤖 Setting up Telegram bot...');
    
    bot = new Telegraf(BOT_TOKEN);

    // /start command
    bot.start(async (ctx) => {
        const user = ctx.from;
        logger.info(`📨 /start command from ${user.first_name} (${user.id})`);
        
        try {
            // Save user to database
            if (db) {
                await saveUser({
                    telegramId: user.id,
                    username: user.username,
                    firstName: user.first_name,
                    lastName: user.last_name
                });
            }

            const welcomeMessage = `🤖 **Selamat datang ${user.first_name}!**

Saya adalah bot autentikasi Anda. Saya dapat membantu Anda:

**🔐 Perintah Utama:**
• \`/getaccess\` - Generate access token
• \`/verify <token>\` - Verifikasi token
• \`/revoke\` - Hapus token aktif  
• \`/stats\` - Lihat statistik akun
• \`/help\` - Tampilkan bantuan

**⚡ Test Commands:**
• \`/ping\` - Test responsivitas bot
• \`/status\` - Status sistem bot

Mulai dengan mengetik /help untuk informasi lebih lanjut!`;

            await ctx.replyWithMarkdownV2(escapeMarkdown(welcomeMessage));
            logger.info(`✅ Welcome message sent to ${user.first_name}`);

        } catch (error) {
            logger.error('❌ Error in start command:', error);
            await ctx.reply('❌ Terjadi kesalahan. Silakan coba lagi.');
        }
    });

    // /help command
    bot.help(async (ctx) => {
        logger.info(`📨 /help command from ${ctx.from.first_name}`);
        
        const helpMessage = `📚 **Bantuan Bot**

**🔐 Perintah Autentikasi:**
• \`/start\` - Mulai menggunakan bot
• \`/getaccess\` - Generate token akses baru
• \`/verify <token>\` - Cek validitas token
• \`/revoke\` - Hapus token yang aktif

**📊 Informasi:**
• \`/stats\` - Statistik akun Anda
• \`/help\` - Tampilkan pesan ini

**⚡ Testing:**
• \`/ping\` - Test response time
• \`/status\` - Status sistem

**💡 Cara Menggunakan:**
1\\. Generate token dengan \`/getaccess\`
2\\. Gunakan token di header API: \`Authorization: Bearer <token>\`
3\\. Token berlaku selama 7 hari

**🔒 Keamanan:**
• Jangan bagikan token Anda
• Generate token baru jika terjadi kebocoran
• Token otomatis expired setelah 7 hari`;

        await ctx.replyWithMarkdownV2(escapeMarkdown(helpMessage));
    });

    // /ping command
    bot.command('ping', async (ctx) => {
        const startTime = Date.now();
        logger.info(`📨 /ping from ${ctx.from.first_name}`);
        
        const message = await ctx.reply('🏓 Pong!');
        const responseTime = Date.now() - startTime;
        
        await ctx.telegram.editMessageText(
            ctx.chat.id,
            message.message_id,
            null,
            `🏓 Pong!\n⚡ Response time: ${responseTime}ms\n🕐 Server time: ${new Date().toLocaleString('id-ID')}`
        );
    });

    // /status command
    bot.command('status', async (ctx) => {
        logger.info(`📨 /status from ${ctx.from.first_name}`);
        
        const uptime = process.uptime();
        const memory = process.memoryUsage();
        const dbStatus = db ? '✅ Connected' : '❌ Disconnected';
        
        const statusMessage = `🔧 **Status Sistem**

**⚡ Bot Status:** 🟢 Online
**🕐 Uptime:** ${Math.floor(uptime/3600)}h ${Math.floor((uptime%3600)/60)}m ${Math.floor(uptime%60)}s
**💾 Memory Usage:** ${Math.round(memory.heapUsed/1024/1024)}MB / ${Math.round(memory.heapTotal/1024/1024)}MB
**🗄️ Database:** ${dbStatus}
**📡 API Server:** 🟢 Running on port ${PORT}
**🤖 Bot Version:** 1.0.0

**📊 Process Info:**
• **Node.js:** ${process.version}
• **Platform:** ${process.platform}
• **PID:** ${process.pid}`;

        await ctx.replyWithMarkdownV2(escapeMarkdown(statusMessage));
    });

    // /getaccess command
    bot.command('getaccess', async (ctx) => {
        const user = ctx.from;
        logger.info(`📨 /getaccess from ${user.first_name} (${user.id})`);
        
        try {
            // Generate new access token
            const accessToken = generateAccessToken(user.id);
            
            // Save to database
            if (db) {
                await saveUser({
                    telegramId: user.id,
                    username: user.username,
                    firstName: user.first_name,
                    lastName: user.last_name,
                    accessToken: accessToken,
                    tokenCreatedAt: new Date()
                });
            }

            const tokenMessage = `🔐 **Access Token Generated**

\`${escapeMarkdown(accessToken)}\`

**📋 Informasi:**
• **Berlaku:** 7 hari dari sekarang
• **Penggunaan:** Header Authorization Bearer
• **Status:** Token lama telah di\\-revoke

**💡 Contoh Penggunaan:**
\`\`\`
Authorization: Bearer ${escapeMarkdown(accessToken.substring(0, 20))}...
\`\`\`

⚠️ **Penting:** Simpan token ini dengan aman\\!`;

            await ctx.replyWithMarkdownV2(tokenMessage);
            logger.info(`✅ Access token generated for ${user.first_name}`);

        } catch (error) {
            logger.error('❌ Error generating access token:', error);
            await ctx.reply('❌ Gagal generate token. Silakan coba lagi.');
        }
    });

    // /verify command
    bot.command('verify', async (ctx) => {
        const args = ctx.message.text.split(' ').slice(1);
        const user = ctx.from;
        
        if (args.length === 0) {
            return ctx.reply('❌ Silakan berikan token untuk diverifikasi.\n\n**Usage:** `/verify <token>`');
        }

        const token = args[0];
        logger.info(`📨 /verify from ${user.first_name}`);
        
        try {
            const decoded = verifyToken(token);
            
            if (!decoded) {
                return ctx.reply('❌ **Token Invalid**\n\nToken tidak valid atau sudah expired.');
            }

            // Check in database
            let dbUser = null;
            if (db) {
                dbUser = await db.collection('users').findOne({ accessToken: token });
            }
            
            const expDate = new Date(decoded.exp * 1000);
            const now = new Date();
            const timeLeft = Math.floor((expDate - now) / (1000 * 60 * 60 * 24));
            
            let verificationMessage = `✅ **Token Valid**

**👤 User ID:** ${decoded.userId}
**⏰ Expires:** ${expDate.toLocaleString('id-ID')}
**📅 Time Left:** ${timeLeft} hari`;

            if (dbUser) {
                verificationMessage += `\n**📊 Created:** ${dbUser.tokenCreatedAt?.toLocaleString('id-ID') || 'Unknown'}`;
            }

            await ctx.replyWithMarkdownV2(escapeMarkdown(verificationMessage));

        } catch (error) {
            logger.error('❌ Error verifying token:', error);
            await ctx.reply('❌ Error saat verifikasi token.');
        }
    });

    // /revoke command
    bot.command('revoke', async (ctx) => {
        const user = ctx.from;
        logger.info(`📨 /revoke from ${user.first_name}`);
        
        try {
            let revoked = false;
            
            if (db) {
                const result = await db.collection('users').findOneAndUpdate(
                    { telegramId: user.id },
                    { 
                        $unset: { accessToken: "", tokenCreatedAt: "" },
                        $set: { updatedAt: new Date() }
                    }
                );
                revoked = result && result.accessToken;
            }

            if (revoked || !db) {
                await ctx.reply('✅ **Token Berhasil Di-revoke**\n\nToken akses Anda telah dihapus. Generate token baru dengan `/getaccess`');
            } else {
                await ctx.reply('ℹ️ **Tidak Ada Token Aktif**\n\nTidak ditemukan token aktif untuk di-revoke.');
            }

        } catch (error) {
            logger.error('❌ Error revoking token:', error);
            await ctx.reply('❌ Error saat revoke token.');
        }
    });

    // /stats command
    bot.command('stats', async (ctx) => {
        const user = ctx.from;
        logger.info(`📨 /stats from ${user.first_name}`);
        
        try {
            const { user: userData, notificationCount } = await getUserStats(user.id);

            let statsMessage = `📊 **Statistik Akun**

**👤 User Info:**
• **Telegram ID:** ${user.id}
• **Username:** @${user.username || 'tidak ada'}
• **Nama:** ${user.first_name} ${user.last_name || ''}`;

            if (userData) {
                const hasToken = !!userData.accessToken;
                statsMessage += `

**📋 Account Data:**
• **Bergabung:** ${userData.createdAt?.toLocaleDateString('id-ID') || 'Unknown'}
• **Update Terakhir:** ${userData.updatedAt?.toLocaleDateString('id-ID') || 'Unknown'}
• **Token Aktif:** ${hasToken ? '✅ Ya' : '❌ Tidak'}
• **Token Dibuat:** ${userData.tokenCreatedAt?.toLocaleDateString('id-ID') || 'Belum pernah'}
• **📬 Notifikasi:** ${notificationCount} pesan`;
            } else {
                statsMessage += `\n\n**⚠️ Database:** Data tidak tersedia`;
            }

            await ctx.replyWithMarkdownV2(escapeMarkdown(statsMessage));

        } catch (error) {
            logger.error('❌ Error getting stats:', error);
            await ctx.reply('❌ Error saat mengambil statistik.');
        }
    });

    // Handle text messages
    bot.on('text', async (ctx) => {
        const text = ctx.message.text.toLowerCase();
        const user = ctx.from;
        
        logger.info(`📝 Text from ${user.first_name}: ${ctx.message.text}`);
        
        if (text.includes('hello') || text.includes('halo') || text.includes('hi')) {
            await ctx.reply(`👋 Halo ${user.first_name}! Selamat datang!\n\nKetik /help untuk melihat perintah yang tersedia.`);
        } else if (text.includes('help') || text.includes('bantuan')) {
            await ctx.reply('📚 Ketik /help untuk melihat daftar perintah lengkap.');
        } else if (text.includes('token')) {
            await ctx.reply('🔐 Untuk mendapatkan access token, gunakan perintah `/getaccess`');
        } else if (text.includes('ping')) {
            await ctx.reply('🏓 Pong! Gunakan `/ping` untuk response time test.');
        } else {
            await ctx.reply('🤔 Maaf, saya tidak mengerti pesan tersebut.\n\nKetik /help untuk melihat perintah yang tersedia.');
        }
    });

    // Error handling
    bot.catch((err, ctx) => {
        logger.error('❌ Bot error occurred:', err);
        if (ctx) {
            ctx.reply('❌ Terjadi kesalahan internal. Silakan coba lagi.').catch(() => {});
        }
    });

    return bot;
}

// ====================================
// EXPRESS API SETUP
// ====================================
function setupExpressApp() {
    logger.info('🌐 Setting up Express server...');
    
    app = express();

    // Middleware
    app.use(express.json({ limit: '10mb' }));
    app.use(express.urlencoded({ extended: true }));
    app.use(cors());

    // Rate limiting
    const limiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 100,
        message: 'Too many requests, please try again later.'
    });
    app.use('/api/', limiter);

    // Health check
    app.get('/', (req, res) => {
        res.json({
            status: 'ok',
            bot_status: botStarted ? 'running' : 'stopped',
            database: db ? 'connected' : 'disconnected',
            timestamp: new Date().toISOString(),
            uptime: process.uptime(),
            memory: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB'
        });
    });

    // API token verification
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

            // Check in database
            let user = null;
            if (db) {
                user = await db.collection('users').findOne({ accessToken: token });
                if (!user) {
                    return res.status(401).json({ error: 'Token not found or revoked' });
                }
            }

            res.json({
                valid: true,
                telegram_id: decoded.userId,
                expires_at: new Date(decoded.exp * 1000).toISOString(),
                user_info: user ? {
                    username: user.username,
                    first_name: user.firstName,
                    created_at: user.createdAt
                } : null
            });

        } catch (error) {
            logger.error('❌ Token verification error:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    });

    // Send notification endpoint
    app.post('/send-notification', async (req, res) => {
        try {
            const { 
                data = {}, 
                screenshot, 
                username = 'Anonymous', 
                userTelegramId, 
                tgForwardEnabled = true 
            } = req.body;

            // Create notification message
            const businessUrl = data.businessUrl || '';
            const successUrl = data.successUrl || '';
            const amount = data.amount || 'Unknown';

            let message = `🔔 **Payment Notification**\n\n`;
            message += `👤 **User:** ${username}\n`;
            if (businessUrl) message += `🏢 **Business:** ${businessUrl}\n`;
            if (successUrl) message += `✅ **Success Page:** ${successUrl}\n`;
            if (amount !== 'Unknown') message += `💰 **Amount:** ${amount}\n`;
            message += `⏰ **Time:** ${new Date().toLocaleString('id-ID')}`;

            // Send to user's personal chat
            if (userTelegramId && tgForwardEnabled && bot) {
                try {
                    await bot.telegram.sendMessage(userTelegramId, message, { 
                        parse_mode: 'Markdown' 
                    });
                } catch (botError) {
                    logger.error('❌ Error sending to user:', botError);
                }
            }

            // Send to group chat
            if (GROUP_CHAT_ID && bot) {
                try {
                    await bot.telegram.sendMessage(GROUP_CHAT_ID, message, { 
                        parse_mode: 'Markdown' 
                    });
                } catch (botError) {
                    logger.error('❌ Error sending to group:', botError);
                }
            }

            // Save notification to database
            if (db) {
                await saveNotification({
                    userId: userTelegramId,
                    username,
                    data,
                    status: 'sent'
                });
            }

            res.json({
                success: true,
                message: 'Notification sent successfully',
                timestamp: new Date().toISOString()
            });

            logger.info(`📬 Notification sent for user: ${username}`);

        } catch (error) {
            logger.error('❌ Send notification error:', error);
            res.status(500).json({ 
                success: false, 
                error: 'Failed to send notification',
                message: error.message 
            });
        }
    });

    // API stats
    app.get('/api/stats', async (req, res) => {
        try {
            let stats = {
                bot_status: botStarted ? 'running' : 'stopped',
                database_status: db ? 'connected' : 'disconnected',
                uptime: process.uptime(),
                memory_usage: process.memoryUsage(),
                timestamp: new Date().toISOString()
            };

            if (db) {
                const totalUsers = await db.collection('users').countDocuments({});
                const activeTokens = await db.collection('users').countDocuments({ 
                    accessToken: { $exists: true } 
                });
                const totalNotifications = await db.collection('notifications').countDocuments({});

                stats.database_stats = {
                    total_users: totalUsers,
                    active_tokens: activeTokens,
                    total_notifications: totalNotifications
                };
            }

            res.json(stats);

        } catch (error) {
            logger.error('❌ Stats error:', error);
            res.status(500).json({ error: 'Error retrieving statistics' });
        }
    });

    return app;
}

// ====================================
// MAIN APPLICATION
// ====================================
async function startApplication() {
    try {
        logger.info('🚀 Starting Telegram Bot Application...');
        
        // Connect to database with retry
        let dbConnected = false;
        const maxRetries = 3;
        
        for (let attempt = 1; attempt <= maxRetries; attempt++) {
            logger.info(`🔄 Database connection attempt ${attempt}/${maxRetries}`);
            dbConnected = await connectMongoDB();
            
            if (dbConnected) {
                break;
            } else if (attempt < maxRetries) {
                logger.info(`⏳ Retrying in 5 seconds...`);
                await new Promise(resolve => setTimeout(resolve, 5000));
            }
        }
        
        if (!dbConnected) {
            logger.warn('⚠️  Starting without database after all attempts failed');
        }
        
        // Setup Telegram bot
        bot = setupTelegramBot();
        
        // Setup Express app
        app = setupExpressApp();
        
        // Start bot
        logger.info('🤖 Launching Telegram bot...');
        await bot.launch();
        botStarted = true;
        logger.info('✅ Telegram bot launched successfully!');
        
        // Start Express server
        app.listen(PORT, () => {
            logger.info(`🌐 Express server running on port ${PORT}`);
            logger.info('📱 Bot is ready! Test with /start command');
            
            // Print final status
            logger.info('🎉 Application started successfully!');
            logger.info(`📊 Database: ${dbConnected ? '✅ Connected' : '❌ Disconnected'}`);
            logger.info(`🤖 Bot: @pixelhitter_bot`);
            logger.info(`🌐 API: http://localhost:${PORT}`);
        });
        
    } catch (error) {
        logger.error('❌ Application startup failed:', error);
        process.exit(1);
    }
}

// ====================================
// GRACEFUL SHUTDOWN
// ====================================
async function gracefulShutdown(signal) {
    if (isShuttingDown) return;
    isShuttingDown = true;
    
    logger.info(`🛑 Received ${signal}. Starting graceful shutdown...`);
    
    try {
        // Stop bot
        if (bot) {
            logger.info('🤖 Stopping Telegram bot...');
            await bot.stop(signal);
            botStarted = false;
            logger.info('✅ Telegram bot stopped');
        }
        
        // Close database connection
        if (mongoClient) {
            logger.info('🗄️ Closing database connection...');
            await mongoClient.close();
            logger.info('✅ Database connection closed');
        }
        
        logger.info('✅ Graceful shutdown completed');
        process.exit(0);
        
    } catch (error) {
        logger.error('❌ Error during shutdown:', error);
        process.exit(1);
    }
}

// Signal handlers
process.once('SIGINT', () => gracefulShutdown('SIGINT'));
process.once('SIGTERM', () => gracefulShutdown('SIGTERM'));

// Unhandled rejection handler
process.on('unhandledRejection', (reason, promise) => {
    logger.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

// Uncaught exception handler
process.on('uncaughtException', (error) => {
    logger.error('❌ Uncaught Exception:', error);
    gracefulShutdown('UNCAUGHT_EXCEPTION');
});

// ====================================
// START APPLICATION
// ====================================
if (require.main === module) {
    startApplication();
}

module.exports = { startApplication, gracefulShutdown };
