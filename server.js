const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Joi = require('joi');
const path = require('path');
const nodemailer = require('nodemailer');
const multer = require('multer');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const InstagramStrategy = require('passport-instagram').Strategy;
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';

// Email configuration
const EMAIL_USER = process.env.EMAIL_USER || 'your-email@gmail.com';
const EMAIL_PASS = process.env.EMAIL_PASS || 'your-app-password';
const EMAIL_FROM = process.env.EMAIL_FROM || EMAIL_USER || 'noreply@tabletennis.com';
const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '465', 10);
const SMTP_SECURE = (process.env.SMTP_SECURE || 'true').toLowerCase() === 'true';

// Social login configuration
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'your-google-client-id';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || 'your-google-client-secret';
const FACEBOOK_APP_ID = process.env.FACEBOOK_APP_ID || 'your-facebook-app-id';
const FACEBOOK_APP_SECRET = process.env.FACEBOOK_APP_SECRET || 'your-facebook-app-secret';
const INSTAGRAM_CLIENT_ID = process.env.INSTAGRAM_CLIENT_ID || 'your-instagram-client-id';
const INSTAGRAM_CLIENT_SECRET = process.env.INSTAGRAM_CLIENT_SECRET || 'your-instagram-client-secret';

// Email transporter setup with dev-safe fallback
const EMAIL_ENABLED = process.env.EMAIL_ENABLED !== 'false' && EMAIL_USER !== 'your-email@gmail.com' && EMAIL_PASS !== 'your-app-password';
const transporter = EMAIL_ENABLED ? nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_SECURE,
    auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASS
    }
}) : null;

// File upload configuration
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/avatars/')
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'avatar-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: function (req, file, cb) {
        const allowedTypes = /jpeg|jpg|png|gif/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'));
        }
    }
});

// Security middleware
app.use(helmet());
app.use(cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:3000', 'file://'],
    credentials: true
}));

// Session configuration for social login
app.use(session({
    secret: JWT_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// Passport serialization
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    db.get('SELECT * FROM users WHERE id = ?', [id], (err, user) => {
        done(err, user);
    });
});

// Google OAuth Strategy
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: "/api/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        // Check if user already exists
        db.get('SELECT * FROM users WHERE social_id = ? AND social_provider = ?', [profile.id, 'google'], (err, existingUser) => {
            if (err) return done(err);
            
            if (existingUser) {
                return done(null, existingUser);
            }
            
            // Check if email already exists
            db.get('SELECT * FROM users WHERE email = ?', [profile.emails[0].value], (err, emailUser) => {
                if (err) return done(err);
                
                if (emailUser) {
                    // Link social account to existing user
                    db.run('UPDATE users SET social_provider = ?, social_id = ? WHERE id = ?', 
                           ['google', profile.id, emailUser.id], function(err) {
                        if (err) return done(err);
                        emailUser.social_provider = 'google';
                        emailUser.social_id = profile.id;
                        return done(null, emailUser);
                    });
                } else {
                    // Create new user
                    db.run('INSERT INTO users (name, email, social_provider, social_id, is_verified) VALUES (?, ?, ?, ?, ?)',
                           [profile.displayName, profile.emails[0].value, 'google', profile.id, 1], function(err) {
                        if (err) return done(err);
                        
                        const newUser = {
                            id: this.lastID,
                            name: profile.displayName,
                            email: profile.emails[0].value,
                            social_provider: 'google',
                            social_id: profile.id,
                            is_verified: 1
                        };
                        return done(null, newUser);
                    });
                }
            });
        });
    } catch (error) {
        return done(error);
    }
}));

// Facebook OAuth Strategy
passport.use(new FacebookStrategy({
    clientID: FACEBOOK_APP_ID,
    clientSecret: FACEBOOK_APP_SECRET,
    callbackURL: "/api/auth/facebook/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        // Check if user already exists
        db.get('SELECT * FROM users WHERE social_id = ? AND social_provider = ?', [profile.id, 'facebook'], (err, existingUser) => {
            if (err) return done(err);
            
            if (existingUser) {
                return done(null, existingUser);
            }
            
            // Check if email already exists
            db.get('SELECT * FROM users WHERE email = ?', [profile.emails[0].value], (err, emailUser) => {
                if (err) return done(err);
                
                if (emailUser) {
                    // Link social account to existing user
                    db.run('UPDATE users SET social_provider = ?, social_id = ? WHERE id = ?', 
                           ['facebook', profile.id, emailUser.id], function(err) {
                        if (err) return done(err);
                        emailUser.social_provider = 'facebook';
                        emailUser.social_id = profile.id;
                        return done(null, emailUser);
                    });
                } else {
                    // Create new user
                    db.run('INSERT INTO users (name, email, social_provider, social_id, is_verified) VALUES (?, ?, ?, ?, ?)',
                           [profile.displayName, profile.emails[0].value, 'facebook', profile.id, 1], function(err) {
                        if (err) return done(err);
                        
                        const newUser = {
                            id: this.lastID,
                            name: profile.displayName,
                            email: profile.emails[0].value,
                            social_provider: 'facebook',
                            social_id: profile.id,
                            is_verified: 1
                        };
                        return done(null, newUser);
                    });
                }
            });
        });
    } catch (error) {
        return done(error);
    }
}));

// Instagram OAuth Strategy
passport.use(new InstagramStrategy({
    clientID: INSTAGRAM_CLIENT_ID,
    clientSecret: INSTAGRAM_CLIENT_SECRET,
    callbackURL: "/api/auth/instagram/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        // Check if user already exists
        db.get('SELECT * FROM users WHERE social_id = ? AND social_provider = ?', [profile.id, 'instagram'], (err, existingUser) => {
            if (err) return done(err);
            
            if (existingUser) {
                return done(null, existingUser);
            }
            
            // Instagram doesn't always provide email, so we'll use username
            const email = profile.emails && profile.emails[0] ? profile.emails[0].value : `${profile.username}@instagram.local`;
            
            // Check if email already exists
            db.get('SELECT * FROM users WHERE email = ?', [email], (err, emailUser) => {
                if (err) return done(err);
                
                if (emailUser) {
                    // Link social account to existing user
                    db.run('UPDATE users SET social_provider = ?, social_id = ? WHERE id = ?', 
                           ['instagram', profile.id, emailUser.id], function(err) {
                        if (err) return done(err);
                        emailUser.social_provider = 'instagram';
                        emailUser.social_id = profile.id;
                        return done(null, emailUser);
                    });
                } else {
                    // Create new user
                    db.run('INSERT INTO users (name, email, social_provider, social_id, is_verified) VALUES (?, ?, ?, ?, ?)',
                           [profile.displayName || profile.username, email, 'instagram', profile.id, 1], function(err) {
                        if (err) return done(err);
                        
                        const newUser = {
                            id: this.lastID,
                            name: profile.displayName || profile.username,
                            email: email,
                            social_provider: 'instagram',
                            social_id: profile.id,
                            is_verified: 1
                        };
                        return done(null, newUser);
                    });
                }
            });
        });
    } catch (error) {
        return done(error);
    }
}));

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());

// Rate limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    message: 'Too many authentication attempts, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

const emailLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 3, // limit each IP to 3 email requests per minute
    message: 'Too many email requests, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
});

// Middleware
app.use(express.json());
app.use(express.static('.')); // Serve static files from current directory
app.use('/uploads', express.static('uploads')); // Serve uploaded files

// Database setup
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        console.error('Error opening database:', err.message);
    } else {
        console.log('Connected to SQLite database');
        initializeDatabase();
    }
});

function initializeDatabase() {
    // Create users table with enhanced fields
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT,
            avatar_url TEXT,
            phone TEXT,
            date_of_birth DATE,
            skill_level TEXT DEFAULT 'beginner',
            role TEXT DEFAULT 'user',
            is_verified BOOLEAN DEFAULT 0,
            is_2fa_enabled BOOLEAN DEFAULT 0,
            two_factor_secret TEXT,
            social_provider TEXT,
            social_id TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME
        )
    `, (err) => {
        if (err) {
            console.error('Error creating users table:', err.message);
        } else {
            console.log('Users table ready');
            migrateUsersTable();
        }
    });

    // Create email verification tokens table
    db.run(`
        CREATE TABLE IF NOT EXISTS email_verification_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token TEXT UNIQUE NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    `, (err) => {
        if (err) {
            console.error('Error creating email_verification_tokens table:', err.message);
        } else {
            console.log('Email verification tokens table ready');
        }
    });

    // Create password reset tokens table
    db.run(`
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token TEXT UNIQUE NOT NULL,
            expires_at DATETIME NOT NULL,
            used BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    `, (err) => {
        if (err) {
            console.error('Error creating password_reset_tokens table:', err.message);
        } else {
            console.log('Password reset tokens table ready');
        }
    });

    // Create tournaments table
    db.run(`
        CREATE TABLE IF NOT EXISTS tournaments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            location TEXT NOT NULL,
            start_date DATETIME NOT NULL,
            end_date DATETIME NOT NULL,
            max_participants INTEGER DEFAULT 32,
            entry_fee DECIMAL(10,2) DEFAULT 0.00,
            skill_level TEXT DEFAULT 'all',
            status TEXT DEFAULT 'upcoming',
            created_by INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
    `, (err) => {
        if (err) {
            console.error('Error creating tournaments table:', err.message);
        } else {
            console.log('Tournaments table ready');
        }
    });

    // Create tournament registrations table
    db.run(`
        CREATE TABLE IF NOT EXISTS tournament_registrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tournament_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            registration_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'registered',
            payment_status TEXT DEFAULT 'pending',
            FOREIGN KEY (tournament_id) REFERENCES tournaments (id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            UNIQUE(tournament_id, user_id)
        )
    `, (err) => {
        if (err) {
            console.error('Error creating tournament_registrations table:', err.message);
        } else {
            console.log('Tournament registrations table ready');
        }
    });

    // Create admin roles table
    db.run(`
        CREATE TABLE IF NOT EXISTS admin_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            permission TEXT NOT NULL,
            granted_by INTEGER,
            granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (granted_by) REFERENCES users (id)
        )
    `, (err) => {
        if (err) {
            console.error('Error creating admin_permissions table:', err.message);
        } else {
            console.log('Admin permissions table ready');
        }
    });
}

// Ensure existing databases get required columns without data loss
function migrateUsersTable() {
    try {
        db.all('PRAGMA table_info(users)', [], (err, rows) => {
            if (err) {
                console.error('Error reading users schema:', err.message);
                return;
            }

            const existingColumns = new Set(rows.map(r => r.name));
            const migrations = [];

            const addColumnIfMissing = (name, type, defaultValueSql) => {
                if (!existingColumns.has(name)) {
                    const defaultClause = defaultValueSql ? ` DEFAULT ${defaultValueSql}` : '';
                    migrations.push(`ALTER TABLE users ADD COLUMN ${name} ${type}${defaultClause}`);
                }
            };

            addColumnIfMissing('is_verified', 'BOOLEAN', '0');
            addColumnIfMissing('is_2fa_enabled', 'BOOLEAN', '0');
            addColumnIfMissing('two_factor_secret', 'TEXT', null);
            addColumnIfMissing('social_provider', 'TEXT', null);
            addColumnIfMissing('social_id', 'TEXT', null);
            addColumnIfMissing('role', 'TEXT', `'user'`);
            addColumnIfMissing('avatar_url', 'TEXT', null);
            addColumnIfMissing('phone', 'TEXT', null);
            addColumnIfMissing('date_of_birth', 'DATE', null);
            addColumnIfMissing('skill_level', 'TEXT', `'beginner'`);
            addColumnIfMissing('created_at', 'DATETIME', 'CURRENT_TIMESTAMP');
            addColumnIfMissing('updated_at', 'DATETIME', 'CURRENT_TIMESTAMP');
            addColumnIfMissing('last_login', 'DATETIME', null);

            if (migrations.length === 0) {
                console.log('Users table schema already up to date');
                return;
            }

            db.serialize(() => {
                migrations.forEach(sql => {
                    db.run(sql, (alterErr) => {
                        if (alterErr) {
                            console.error('Migration error:', alterErr.message, 'SQL:', sql);
                        } else {
                            console.log('Applied migration:', sql);
                        }
                    });
                });
            });
        });
    } catch (e) {
        console.error('Migration failed:', e);
    }
}

// Validation schemas
const signupSchema = Joi.object({
    name: Joi.string().min(2).max(50).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    confirmPassword: Joi.string().valid(Joi.ref('password')).required()
});

const signinSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Helper function to send verification email
async function sendVerificationEmail(email, token) {
    const verificationUrl = `http://localhost:3000/verify-email?token=${token}`;
    
    const mailOptions = {
        from: EMAIL_FROM,
        to: email,
        subject: 'Verify Your Email - Table Tennis Tracker',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #333;">Welcome to Table Tennis Tracker!</h2>
                <p>Thank you for signing up. Please verify your email address to complete your registration.</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="${verificationUrl}" 
                       style="background-color: #4CAF50; color: white; padding: 12px 30px; 
                              text-decoration: none; border-radius: 5px; display: inline-block;">
                        Verify Email Address
                    </a>
                </div>
                <p>If the button doesn't work, copy and paste this link into your browser:</p>
                <p style="word-break: break-all; color: #666;">${verificationUrl}</p>
                <p style="color: #666; font-size: 12px; margin-top: 30px;">
                    This link will expire in 24 hours. If you didn't create an account, please ignore this email.
                </p>
            </div>
        `
    };

    try {
        if (EMAIL_ENABLED && transporter) {
            await transporter.sendMail(mailOptions);
        } else {
            console.log('DEV MODE: Email disabled. Verification link:', verificationUrl);
        }
        return true;
    } catch (error) {
        console.error('Email sending error:', error);
        return false;
    }
}

// Helper function to send password reset email
async function sendPasswordResetEmail(email, token) {
    const resetUrl = `http://localhost:3000/reset-password?token=${token}`;
    
    const mailOptions = {
        from: EMAIL_FROM,
        to: email,
        subject: 'Password Reset - Table Tennis Tracker',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #333;">Password Reset Request</h2>
                <p>You requested to reset your password. Click the button below to create a new password.</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="${resetUrl}" 
                       style="background-color: #f44336; color: white; padding: 12px 30px; 
                              text-decoration: none; border-radius: 5px; display: inline-block;">
                        Reset Password
                    </a>
                </div>
                <p>If the button doesn't work, copy and paste this link into your browser:</p>
                <p style="word-break: break-all; color: #666;">${resetUrl}</p>
                <p style="color: #666; font-size: 12px; margin-top: 30px;">
                    This link will expire in 1 hour. If you didn't request a password reset, please ignore this email.
                </p>
            </div>
        `
    };

    try {
        if (EMAIL_ENABLED && transporter) {
            await transporter.sendMail(mailOptions);
        } else {
            console.log('DEV MODE: Email disabled. Password reset link:', resetUrl);
        }
        return true;
    } catch (error) {
        console.error('Email sending error:', error);
        return false;
    }
}

// Sign up route with email verification
app.post('/api/auth/signup', authLimiter, async (req, res) => {
    try {
        // Validate input
        const { error, value } = signupSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ message: error.details[0].message });
        }

        const { name, email, password } = value;

        // Check if user already exists
        db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }

            if (row) {
                return res.status(400).json({ message: 'User with this email already exists' });
            }

            // Hash password
            const saltRounds = 12;
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            // Generate verification token
            const verificationToken = uuidv4();
            const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

            // Insert new user (not verified)
            db.run(
                'INSERT INTO users (name, email, password, is_verified) VALUES (?, ?, ?, 0)',
                [name, email, hashedPassword],
                function(err) {
                    if (err) {
                        console.error('Error inserting user:', err);
                        return res.status(500).json({ message: 'Error creating user' });
                    }

                    const userId = this.lastID;

                    // Store verification token
                    db.run(
                        'INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
                        [userId, verificationToken, expiresAt.toISOString()],
                        async (err) => {
                            if (err) {
                                console.error('Error storing verification token:', err);
                                return res.status(500).json({ message: 'Error creating verification token' });
                            }

                            // Send verification email
                            const emailSent = await sendVerificationEmail(email, verificationToken);
                            
                            if (emailSent) {
                                res.status(201).json({
                                    message: 'Account created successfully! Please check your email to verify your account.',
                                    user: {
                                        id: userId,
                                        name: name,
                                        email: email,
                                        is_verified: false
                                    }
                                });
                            } else {
                                res.status(500).json({ message: 'Account created but failed to send verification email. Please contact support.' });
                            }
                        }
                    );
                }
            );
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Email verification route
app.get('/api/auth/verify-email', async (req, res) => {
    try {
        const { token } = req.query;

        if (!token) {
            return res.status(400).json({ message: 'Verification token is required' });
        }

        // Find and validate token
        db.get(
            `SELECT evt.*, u.email, u.name 
             FROM email_verification_tokens evt 
             JOIN users u ON evt.user_id = u.id 
             WHERE evt.token = ? AND evt.expires_at > datetime('now')`,
            [token],
            (err, row) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ message: 'Database error' });
                }

                if (!row) {
                    return res.status(400).json({ message: 'Invalid or expired verification token' });
                }

                // Mark user as verified
                db.run(
                    'UPDATE users SET is_verified = 1 WHERE id = ?',
                    [row.user_id],
                    (err) => {
                        if (err) {
                            console.error('Error updating user verification:', err);
                            return res.status(500).json({ message: 'Error verifying user' });
                        }

                        // Delete used token
                        db.run('DELETE FROM email_verification_tokens WHERE token = ?', [token]);

                        res.json({
                            message: 'Email verified successfully! You can now sign in.',
                            user: {
                                id: row.user_id,
                                name: row.name,
                                email: row.email,
                                is_verified: true
                            }
                        });
                    }
                );
            }
        );
    } catch (error) {
        console.error('Email verification error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Resend verification email route
app.post('/api/auth/resend-verification', emailLimiter, async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ message: 'Email is required' });
        }

        // Check if user exists and is not verified
        db.get(
            'SELECT id, name, email, is_verified FROM users WHERE email = ?',
            [email],
            async (err, user) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ message: 'Database error' });
                }

                if (!user) {
                    return res.status(404).json({ message: 'User not found' });
                }

                if (user.is_verified) {
                    return res.status(400).json({ message: 'Email is already verified' });
                }

                // Generate new verification token
                const verificationToken = uuidv4();
                const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

                // Store new verification token
                db.run(
                    'INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
                    [user.id, verificationToken, expiresAt.toISOString()],
                    async (err) => {
                        if (err) {
                            console.error('Error storing verification token:', err);
                            return res.status(500).json({ message: 'Error creating verification token' });
                        }

                        // Send verification email
                        const emailSent = await sendVerificationEmail(email, verificationToken);
                        
                        if (emailSent) {
                            res.json({ message: 'Verification email sent successfully!' });
                        } else {
                            res.status(500).json({ message: 'Failed to send verification email' });
                        }
                    }
                );
            }
        );
    } catch (error) {
        console.error('Resend verification error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Sign in route with email verification check
app.post('/api/auth/signin', authLimiter, async (req, res) => {
    try {
        // Validate input
        const { error, value } = signinSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ message: error.details[0].message });
        }

        const { email, password } = value;

        // Find user by email
        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }

            if (!user) {
                return res.status(401).json({ message: 'Invalid email or password' });
            }

            // Check if user has a password (not social login)
            if (user.password) {
                // Verify password
                const isValidPassword = await bcrypt.compare(password, user.password);
                if (!isValidPassword) {
                    return res.status(401).json({ message: 'Invalid email or password' });
                }
            } else {
                return res.status(401).json({ message: 'Please sign in with your social account' });
            }

            // Check if email is verified
            if (!user.is_verified) {
                return res.status(403).json({ 
                    message: 'Please verify your email before signing in. Check your inbox for a verification link.',
                    requiresVerification: true,
                    email: user.email
                });
            }

            // Update last login
            db.run('UPDATE users SET last_login = datetime("now") WHERE id = ?', [user.id]);

            // Generate JWT token
            const token = jwt.sign(
                { userId: user.id, email: user.email },
                JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.json({
                message: 'Sign in successful',
                token: token,
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    is_verified: user.is_verified,
                    role: user.role,
                    avatar_url: user.avatar_url
                }
            });
        });
    } catch (error) {
        console.error('Signin error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Password reset request route
app.post('/api/auth/forgot-password', emailLimiter, async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ message: 'Email is required' });
        }

        // Check if user exists
        db.get('SELECT id, name, email FROM users WHERE email = ?', [email], async (err, user) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }

            if (!user) {
                // Don't reveal if email exists or not for security
                return res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
            }

            // Generate reset token
            const resetToken = uuidv4();
            const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

            // Store reset token
            db.run(
                'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
                [user.id, resetToken, expiresAt.toISOString()],
                async (err) => {
                    if (err) {
                        console.error('Error storing reset token:', err);
                        return res.status(500).json({ message: 'Error creating reset token' });
                    }

                    // Send reset email
                    const emailSent = await sendPasswordResetEmail(email, resetToken);
                    
                    if (emailSent) {
                        res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
                    } else {
                        res.status(500).json({ message: 'Failed to send reset email' });
                    }
                }
            );
        });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Password reset route
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { token, password } = req.body;

        if (!token || !password) {
            return res.status(400).json({ message: 'Token and new password are required' });
        }

        if (password.length < 6) {
            return res.status(400).json({ message: 'Password must be at least 6 characters long' });
        }

        // Find and validate reset token
        db.get(
            `SELECT prt.*, u.email 
             FROM password_reset_tokens prt 
             JOIN users u ON prt.user_id = u.id 
             WHERE prt.token = ? AND prt.expires_at > datetime('now') AND prt.used = 0`,
            [token],
            async (err, row) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ message: 'Database error' });
                }

                if (!row) {
                    return res.status(400).json({ message: 'Invalid or expired reset token' });
                }

                // Hash new password
                const saltRounds = 12;
                const hashedPassword = await bcrypt.hash(password, saltRounds);

                // Update password and mark token as used
                db.run(
                    'UPDATE users SET password = ? WHERE id = ?',
                    [hashedPassword, row.user_id],
                    (err) => {
                        if (err) {
                            console.error('Error updating password:', err);
                            return res.status(500).json({ message: 'Error updating password' });
                        }

                        // Mark token as used
                        db.run('UPDATE password_reset_tokens SET used = 1 WHERE token = ?', [token]);

                        res.json({ message: 'Password reset successfully! You can now sign in with your new password.' });
                    }
                );
            }
        );
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Verify token route
app.get('/api/auth/verify', authenticateToken, (req, res) => {
    res.json({
        message: 'Token is valid',
        user: req.user
    });
});

// Logout route (optional - mainly for server-side session management)
app.post('/api/auth/logout', (req, res) => {
    // Stateless logout; always succeed. Client clears tokens.
    try {
        if (req.session) {
            req.session.destroy(() => {});
        }
    } catch (e) {
        // ignore session errors
    }
    res.json({ message: 'Logged out successfully' });
});

// User profile routes
app.get('/api/user/profile', authenticateToken, (req, res) => {
    db.get('SELECT id, name, email, avatar_url, phone, date_of_birth, skill_level, role, is_verified, created_at, last_login FROM users WHERE id = ?', [req.user.userId], (err, user) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ message: 'Database error' });
        }

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({ user });
    });
});

// Update user profile
app.put('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const { name, phone, date_of_birth, skill_level } = req.body;

        // Validate input
        const updateSchema = Joi.object({
            name: Joi.string().min(2).max(50),
            phone: Joi.string().pattern(/^[\+]?[1-9][\d]{0,15}$/).allow(''),
            date_of_birth: Joi.date().max('now'),
            skill_level: Joi.string().valid('beginner', 'intermediate', 'advanced', 'professional')
        });

        const { error, value } = updateSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ message: error.details[0].message });
        }

        // Build update query dynamically
        const updates = [];
        const values = [];

        if (value.name !== undefined) {
            updates.push('name = ?');
            values.push(value.name);
        }
        if (value.phone !== undefined) {
            updates.push('phone = ?');
            values.push(value.phone || null);
        }
        if (value.date_of_birth !== undefined) {
            updates.push('date_of_birth = ?');
            values.push(value.date_of_birth || null);
        }
        if (value.skill_level !== undefined) {
            updates.push('skill_level = ?');
            values.push(value.skill_level);
        }

        if (updates.length === 0) {
            return res.status(400).json({ message: 'No valid fields to update' });
        }

        updates.push('updated_at = datetime("now")');
        values.push(req.user.userId);

        const query = `UPDATE users SET ${updates.join(', ')} WHERE id = ?`;
        
        db.run(query, values, function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }

            // Return updated user data
            db.get('SELECT id, name, email, avatar_url, phone, date_of_birth, skill_level, role, is_verified, created_at, last_login FROM users WHERE id = ?', [req.user.userId], (err, user) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ message: 'Database error' });
                }

                res.json({
                    message: 'Profile updated successfully',
                    user: user
                });
            });
        });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Upload avatar
app.post('/api/user/avatar', authenticateToken, upload.single('avatar'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded' });
        }

        const avatarUrl = `/uploads/avatars/${req.file.filename}`;

        // Update user avatar in database
        db.run('UPDATE users SET avatar_url = ?, updated_at = datetime("now") WHERE id = ?', [avatarUrl, req.user.userId], function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }

            res.json({
                message: 'Avatar uploaded successfully',
                avatar_url: avatarUrl
            });
        });
    } catch (error) {
        console.error('Avatar upload error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Change password
app.post('/api/user/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ message: 'Current password and new password are required' });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ message: 'New password must be at least 6 characters long' });
        }

        // Get current user
        db.get('SELECT password FROM users WHERE id = ?', [req.user.userId], async (err, user) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }

            if (!user || !user.password) {
                return res.status(404).json({ message: 'User not found or no password set' });
            }

            // Verify current password
            const isValidPassword = await bcrypt.compare(currentPassword, user.password);
            if (!isValidPassword) {
                return res.status(401).json({ message: 'Current password is incorrect' });
            }

            // Hash new password
            const saltRounds = 12;
            const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

            // Update password
            db.run('UPDATE users SET password = ?, updated_at = datetime("now") WHERE id = ?', [hashedPassword, req.user.userId], function(err) {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ message: 'Database error' });
                }

                res.json({ message: 'Password changed successfully' });
            });
        });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Tournament routes
app.get('/api/tournaments', (req, res) => {
    const { status = 'upcoming', skill_level, limit = 20, offset = 0 } = req.query;
    
    let query = `
        SELECT t.*, u.name as creator_name,
               COUNT(tr.id) as registered_count
        FROM tournaments t
        LEFT JOIN users u ON t.created_by = u.id
        LEFT JOIN tournament_registrations tr ON t.id = tr.tournament_id AND tr.status = 'registered'
        WHERE 1=1
    `;
    
    const params = [];
    
    if (status) {
        query += ' AND t.status = ?';
        params.push(status);
    }
    
    if (skill_level && skill_level !== 'all') {
        query += ' AND (t.skill_level = ? OR t.skill_level = "all")';
        params.push(skill_level);
    }
    
    query += ' GROUP BY t.id ORDER BY t.start_date ASC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    
    db.all(query, params, (err, tournaments) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ message: 'Database error' });
        }
        
        res.json({ tournaments });
    });
});

app.get('/api/tournaments/:id', (req, res) => {
    const tournamentId = req.params.id;
    
    const query = `
        SELECT t.*, u.name as creator_name,
               COUNT(tr.id) as registered_count
        FROM tournaments t
        LEFT JOIN users u ON t.created_by = u.id
        LEFT JOIN tournament_registrations tr ON t.id = tr.tournament_id AND tr.status = 'registered'
        WHERE t.id = ?
        GROUP BY t.id
    `;
    
    db.get(query, [tournamentId], (err, tournament) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ message: 'Database error' });
        }
        
        if (!tournament) {
            return res.status(404).json({ message: 'Tournament not found' });
        }
        
        res.json({ tournament });
    });
});

app.post('/api/tournaments', authenticateToken, async (req, res) => {
    try {
        const { name, description, location, start_date, end_date, max_participants, entry_fee, skill_level } = req.body;
        
        // Validate input
        const tournamentSchema = Joi.object({
            name: Joi.string().min(3).max(100).required(),
            description: Joi.string().max(1000),
            location: Joi.string().min(3).max(200).required(),
            start_date: Joi.date().min('now').required(),
            end_date: Joi.date().min(Joi.ref('start_date')).required(),
            max_participants: Joi.number().integer().min(2).max(128).default(32),
            entry_fee: Joi.number().min(0).default(0),
            skill_level: Joi.string().valid('beginner', 'intermediate', 'advanced', 'professional', 'all').default('all')
        });
        
        const { error, value } = tournamentSchema.validate(req.body);
        if (error) {
            return res.status(400).json({ message: error.details[0].message });
        }
        
        // Create tournament
        const query = `
            INSERT INTO tournaments (name, description, location, start_date, end_date, max_participants, entry_fee, skill_level, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        
        db.run(query, [
            value.name, value.description, value.location, value.start_date, value.end_date,
            value.max_participants, value.entry_fee, value.skill_level, req.user.userId
        ], function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }
            
            res.status(201).json({
                message: 'Tournament created successfully',
                tournament_id: this.lastID
            });
        });
    } catch (error) {
        console.error('Create tournament error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/tournaments/:id/register', authenticateToken, async (req, res) => {
    try {
        const tournamentId = req.params.id;
        
        // Check if tournament exists and is open for registration
        db.get(
            'SELECT * FROM tournaments WHERE id = ? AND status = "upcoming" AND start_date > datetime("now")',
            [tournamentId],
            (err, tournament) => {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ message: 'Database error' });
                }
                
                if (!tournament) {
                    return res.status(404).json({ message: 'Tournament not found or registration closed' });
                }
                
                // Check current registration count
                db.get(
                    'SELECT COUNT(*) as count FROM tournament_registrations WHERE tournament_id = ? AND status = "registered"',
                    [tournamentId],
                    (err, result) => {
                        if (err) {
                            console.error('Database error:', err);
                            return res.status(500).json({ message: 'Database error' });
                        }
                        
                        if (result.count >= tournament.max_participants) {
                            return res.status(400).json({ message: 'Tournament is full' });
                        }
                        
                        // Check if user is already registered
                        db.get(
                            'SELECT id FROM tournament_registrations WHERE tournament_id = ? AND user_id = ?',
                            [tournamentId, req.user.userId],
                            (err, existing) => {
                                if (err) {
                                    console.error('Database error:', err);
                                    return res.status(500).json({ message: 'Database error' });
                                }
                                
                                if (existing) {
                                    return res.status(400).json({ message: 'You are already registered for this tournament' });
                                }
                                
                                // Register user
                                db.run(
                                    'INSERT INTO tournament_registrations (tournament_id, user_id, status) VALUES (?, ?, "registered")',
                                    [tournamentId, req.user.userId],
                                    function(err) {
                                        if (err) {
                                            console.error('Database error:', err);
                                            return res.status(500).json({ message: 'Database error' });
                                        }
                                        
                                        res.status(201).json({
                                            message: 'Successfully registered for tournament',
                                            registration_id: this.lastID
                                        });
                                    }
                                );
                            }
                        );
                    }
                );
            }
        );
    } catch (error) {
        console.error('Tournament registration error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.delete('/api/tournaments/:id/register', authenticateToken, async (req, res) => {
    try {
        const tournamentId = req.params.id;
        
        // Remove registration
        db.run(
            'DELETE FROM tournament_registrations WHERE tournament_id = ? AND user_id = ?',
            [tournamentId, req.user.userId],
            function(err) {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ message: 'Database error' });
                }
                
                if (this.changes === 0) {
                    return res.status(404).json({ message: 'Registration not found' });
                }
                
                res.json({ message: 'Successfully unregistered from tournament' });
            }
        );
    } catch (error) {
        console.error('Tournament unregistration error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/user/tournaments', authenticateToken, (req, res) => {
    const { status = 'upcoming' } = req.query;
    
    const query = `
        SELECT t.*, tr.registration_date, tr.status as registration_status, tr.payment_status,
               u.name as creator_name
        FROM tournament_registrations tr
        JOIN tournaments t ON tr.tournament_id = t.id
        LEFT JOIN users u ON t.created_by = u.id
        WHERE tr.user_id = ?
        ORDER BY t.start_date ASC
    `;
    
    db.all(query, [req.user.userId], (err, tournaments) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ message: 'Database error' });
        }
        
        res.json({ tournaments });
    });
});

// Admin middleware
const requireAdmin = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({ message: 'Authentication required' });
    }
    
    // Check if user is admin
    db.get('SELECT role FROM users WHERE id = ?', [req.user.userId], (err, user) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ message: 'Database error' });
        }
        
        if (!user || user.role !== 'admin') {
            return res.status(403).json({ message: 'Admin access required' });
        }
        
        next();
    });
};

// Admin routes
app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
    const { limit = 20, offset = 0, search = '', role = '' } = req.query;
    
    let query = `
        SELECT id, name, email, role, is_verified, is_2fa_enabled, 
               skill_level, created_at, last_login
        FROM users 
        WHERE 1=1
    `;
    
    const params = [];
    
    if (search) {
        query += ' AND (name LIKE ? OR email LIKE ?)';
        params.push(`%${search}%`, `%${search}%`);
    }
    
    if (role) {
        query += ' AND role = ?';
        params.push(role);
    }
    
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    
    db.all(query, params, (err, users) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ message: 'Database error' });
        }
        
        res.json({ users });
    });
});

app.put('/api/admin/users/:id/role', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const userId = req.params.id;
        const { role } = req.body;
        
        if (!role || !['user', 'admin', 'moderator'].includes(role)) {
            return res.status(400).json({ message: 'Invalid role' });
        }
        
        if (userId == req.user.userId && role !== 'admin') {
            return res.status(400).json({ message: 'Cannot change your own admin role' });
        }
        
        db.run('UPDATE users SET role = ?, updated_at = datetime("now") WHERE id = ?', [role, userId], function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }
            
            if (this.changes === 0) {
                return res.status(404).json({ message: 'User not found' });
            }
            
            res.json({ message: 'User role updated successfully' });
        });
    } catch (error) {
        console.error('Update user role error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const userId = req.params.id;
        
        if (userId == req.user.userId) {
            return res.status(400).json({ message: 'Cannot delete your own account' });
        }
        
        db.run('DELETE FROM users WHERE id = ?', [userId], function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }
            
            if (this.changes === 0) {
                return res.status(404).json({ message: 'User not found' });
            }
            
            res.json({ message: 'User deleted successfully' });
        });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/admin/tournaments', authenticateToken, requireAdmin, (req, res) => {
    const { limit = 20, offset = 0, status = '', search = '' } = req.query;
    
    let query = `
        SELECT t.*, u.name as creator_name,
               COUNT(tr.id) as registered_count
        FROM tournaments t
        LEFT JOIN users u ON t.created_by = u.id
        LEFT JOIN tournament_registrations tr ON t.id = tr.tournament_id AND tr.status = 'registered'
        WHERE 1=1
    `;
    
    const params = [];
    
    if (status) {
        query += ' AND t.status = ?';
        params.push(status);
    }
    
    if (search) {
        query += ' AND (t.name LIKE ? OR t.location LIKE ?)';
        params.push(`%${search}%`, `%${search}%`);
    }
    
    query += ' GROUP BY t.id ORDER BY t.created_at DESC LIMIT ? OFFSET ?';
    params.push(parseInt(limit), parseInt(offset));
    
    db.all(query, params, (err, tournaments) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ message: 'Database error' });
        }
        
        res.json({ tournaments });
    });
});

app.put('/api/admin/tournaments/:id/status', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const tournamentId = req.params.id;
        const { status } = req.body;
        
        if (!status || !['upcoming', 'ongoing', 'completed', 'cancelled'].includes(status)) {
            return res.status(400).json({ message: 'Invalid status' });
        }
        
        db.run('UPDATE tournaments SET status = ?, updated_at = datetime("now") WHERE id = ?', [status, tournamentId], function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }
            
            if (this.changes === 0) {
                return res.status(404).json({ message: 'Tournament not found' });
            }
            
            res.json({ message: 'Tournament status updated successfully' });
        });
    } catch (error) {
        console.error('Update tournament status error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.delete('/api/admin/tournaments/:id', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const tournamentId = req.params.id;
        
        db.run('DELETE FROM tournaments WHERE id = ?', [tournamentId], function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }
            
            if (this.changes === 0) {
                return res.status(404).json({ message: 'Tournament not found' });
            }
            
            res.json({ message: 'Tournament deleted successfully' });
        });
    } catch (error) {
        console.error('Delete tournament error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/admin/stats', authenticateToken, requireAdmin, (req, res) => {
    const queries = {
        totalUsers: 'SELECT COUNT(*) as count FROM users',
        verifiedUsers: 'SELECT COUNT(*) as count FROM users WHERE is_verified = 1',
        totalTournaments: 'SELECT COUNT(*) as count FROM tournaments',
        activeTournaments: 'SELECT COUNT(*) as count FROM tournaments WHERE status = "upcoming" OR status = "ongoing"',
        totalRegistrations: 'SELECT COUNT(*) as count FROM tournament_registrations WHERE status = "registered"',
        usersByRole: 'SELECT role, COUNT(*) as count FROM users GROUP BY role',
        tournamentsByStatus: 'SELECT status, COUNT(*) as count FROM tournaments GROUP BY status'
    };
    
    const stats = {};
    let completedQueries = 0;
    const totalQueries = Object.keys(queries).length;
    
    Object.keys(queries).forEach(key => {
        db.get(queries[key], (err, result) => {
            if (err) {
                console.error(`Database error for ${key}:`, err);
                stats[key] = 0;
            } else {
                stats[key] = result.count || result;
            }
            
            completedQueries++;
            if (completedQueries === totalQueries) {
                res.json({ stats });
            }
        });
    });
});

// Social login routes
app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/api/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/?authError=social' }),
    (req, res) => {
        // Generate JWT token for the authenticated user
        const token = jwt.sign(
            { userId: req.user.id, email: req.user.email },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        // Redirect to frontend with token
        res.redirect(`/?token=${token}&user=${encodeURIComponent(JSON.stringify({
            id: req.user.id,
            name: req.user.name,
            email: req.user.email,
            avatar_url: req.user.avatar_url,
            role: req.user.role,
            is_verified: req.user.is_verified
        }))}`);
    }
);

app.get('/api/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));

app.get('/api/auth/facebook/callback',
    passport.authenticate('facebook', { failureRedirect: '/?authError=social' }),
    (req, res) => {
        // Generate JWT token for the authenticated user
        const token = jwt.sign(
            { userId: req.user.id, email: req.user.email },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        // Redirect to frontend with token
        res.redirect(`/?token=${token}&user=${encodeURIComponent(JSON.stringify({
            id: req.user.id,
            name: req.user.name,
            email: req.user.email,
            avatar_url: req.user.avatar_url,
            role: req.user.role,
            is_verified: req.user.is_verified
        }))}`);
    }
);

app.get('/api/auth/instagram', passport.authenticate('instagram'));

app.get('/api/auth/instagram/callback',
    passport.authenticate('instagram', { failureRedirect: '/?authError=social' }),
    (req, res) => {
        // Generate JWT token for the authenticated user
        const token = jwt.sign(
            { userId: req.user.id, email: req.user.email },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        // Redirect to frontend with token
        res.redirect(`/?token=${token}&user=${encodeURIComponent(JSON.stringify({
            id: req.user.id,
            name: req.user.name,
            email: req.user.email,
            avatar_url: req.user.avatar_url,
            role: req.user.role,
            is_verified: req.user.is_verified
        }))}`);
    }
);

// Two-Factor Authentication routes
app.post('/api/auth/2fa/setup', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        
        // Generate 2FA secret
        const secret = speakeasy.generateSecret({
            name: `Table Tennis Tracker (${req.user.email})`,
            issuer: 'Table Tennis Tracker'
        });
        
        // Store secret temporarily (not enabled yet)
        db.run('UPDATE users SET two_factor_secret = ? WHERE id = ?', [secret.base32, userId], function(err) {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }
            
            // Generate QR code
            QRCode.toDataURL(secret.otpauth_url, (err, qrCodeUrl) => {
                if (err) {
                    console.error('QR code generation error:', err);
                    return res.status(500).json({ message: 'Failed to generate QR code' });
                }
                
                res.json({
                    secret: secret.base32,
                    qrCode: qrCodeUrl,
                    manualEntryKey: secret.base32
                });
            });
        });
    } catch (error) {
        console.error('2FA setup error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/auth/2fa/verify', authenticateToken, async (req, res) => {
    try {
        const { token } = req.body;
        const userId = req.user.userId;
        
        if (!token) {
            return res.status(400).json({ message: 'Verification token is required' });
        }
        
        // Get user's 2FA secret
        db.get('SELECT two_factor_secret, is_2fa_enabled FROM users WHERE id = ?', [userId], (err, user) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }
            
            if (!user || !user.two_factor_secret) {
                return res.status(400).json({ message: '2FA not set up for this user' });
            }
            
            // Verify the token
            const verified = speakeasy.totp.verify({
                secret: user.two_factor_secret,
                encoding: 'base32',
                token: token,
                window: 2 // Allow 2 time steps (60 seconds) of tolerance
            });
            
            if (!verified) {
                return res.status(400).json({ message: 'Invalid verification token' });
            }
            
            // Enable 2FA if not already enabled
            if (!user.is_2fa_enabled) {
                db.run('UPDATE users SET is_2fa_enabled = 1 WHERE id = ?', [userId], function(err) {
                    if (err) {
                        console.error('Database error:', err);
                        return res.status(500).json({ message: 'Database error' });
                    }
                    
                    res.json({ 
                        message: '2FA enabled successfully',
                        enabled: true
                    });
                });
            } else {
                res.json({ 
                    message: 'Token verified successfully',
                    enabled: true
                });
            }
        });
    } catch (error) {
        console.error('2FA verification error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/auth/2fa/disable', authenticateToken, async (req, res) => {
    try {
        const { password, token } = req.body;
        const userId = req.user.userId;
        
        // Verify password first
        db.get('SELECT password, two_factor_secret FROM users WHERE id = ?', [userId], async (err, user) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }
            
            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }
            
            // Verify password
            const isValidPassword = await bcrypt.compare(password, user.password);
            if (!isValidPassword) {
                return res.status(401).json({ message: 'Invalid password' });
            }
            
            // Verify 2FA token if provided
            if (token && user.two_factor_secret) {
                const verified = speakeasy.totp.verify({
                    secret: user.two_factor_secret,
                    encoding: 'base32',
                    token: token,
                    window: 2
                });
                
                if (!verified) {
                    return res.status(400).json({ message: 'Invalid 2FA token' });
                }
            }
            
            // Disable 2FA
            db.run('UPDATE users SET is_2fa_enabled = 0, two_factor_secret = NULL WHERE id = ?', [userId], function(err) {
                if (err) {
                    console.error('Database error:', err);
                    return res.status(500).json({ message: 'Database error' });
                }
                
                res.json({ message: '2FA disabled successfully' });
            });
        });
    } catch (error) {
        console.error('2FA disable error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Enhanced sign-in with 2FA support
app.post('/api/auth/signin-2fa', authLimiter, async (req, res) => {
    try {
        const { email, password, token } = req.body;
        
        // Validate input
        const { error, value } = signinSchema.validate({ email, password });
        if (error) {
            return res.status(400).json({ message: error.details[0].message });
        }
        
        // Find user by email
        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ message: 'Database error' });
            }
            
            if (!user) {
                return res.status(401).json({ message: 'Invalid email or password' });
            }
            
            // Check if user has a password (not social login)
            if (user.password) {
                // Verify password
                const isValidPassword = await bcrypt.compare(password, user.password);
                if (!isValidPassword) {
                    return res.status(401).json({ message: 'Invalid email or password' });
                }
            } else {
                return res.status(401).json({ message: 'Please sign in with your social account' });
            }
            
            // Check if email is verified
            if (!user.is_verified) {
                return res.status(403).json({ 
                    message: 'Please verify your email before signing in. Check your inbox for a verification link.',
                    requiresVerification: true,
                    email: user.email
                });
            }
            
            // Check if 2FA is enabled
            if (user.is_2fa_enabled) {
                if (!token) {
                    return res.status(200).json({
                        message: '2FA token required',
                        requires2FA: true,
                        userId: user.id
                    });
                }
                
                // Verify 2FA token
                const verified = speakeasy.totp.verify({
                    secret: user.two_factor_secret,
                    encoding: 'base32',
                    token: token,
                    window: 2
                });
                
                if (!verified) {
                    return res.status(401).json({ message: 'Invalid 2FA token' });
                }
            }
            
            // Update last login
            db.run('UPDATE users SET last_login = datetime("now") WHERE id = ?', [user.id]);
            
            // Generate JWT token
            const jwtToken = jwt.sign(
                { userId: user.id, email: user.email },
                JWT_SECRET,
                { expiresIn: '24h' }
            );
            
            res.json({
                message: 'Sign in successful',
                token: jwtToken,
                user: {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    is_verified: user.is_verified,
                    role: user.role,
                    avatar_url: user.avatar_url,
                    is_2fa_enabled: user.is_2fa_enabled
                }
            });
        });
    } catch (error) {
        console.error('Signin 2FA error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ message: 'Route not found' });
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\nShutting down server...');
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err.message);
        } else {
            console.log('Database connection closed.');
        }
        process.exit(0);
    });
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('Authentication system ready!');
});
