# Table Tennis Website with Authentication

A modern table tennis community website with a complete authentication system.

## Features

- **User Authentication**: Sign up, sign in, and logout functionality
- **Secure Password Handling**: Passwords are hashed using bcrypt
- **JWT Tokens**: Secure session management with JSON Web Tokens
- **Responsive Design**: Beautiful modal forms that match your existing design
- **Database Storage**: SQLite database for user data
- **Security Features**: Rate limiting, input validation, and security headers

## Prerequisites

Before you begin, ensure you have the following installed:
- [Node.js](https://nodejs.org/) (version 14 or higher)
- npm (comes with Node.js)

## Installation & Setup

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Start the Development Server**
   ```bash
   npm run dev
   ```
   
   Or for production:
   ```bash
   npm start
   ```

3. **Access the Website**
   Open your browser and go to: `http://localhost:3000`

## Project Structure

```
TableTennis/
├── index.html          # Main page with authentication modals
├── script.js           # Frontend authentication logic
├── styles.css          # Styling including modal designs
├── server.js           # Backend Express server
├── package.json        # Dependencies and scripts
├── users.db           # SQLite database (created automatically)
└── pages/             # Additional website pages
    ├── about.html
    ├── contact-us.html
    ├── news.html
    └── tournament.html
```

## API Endpoints

### Authentication Routes
- `POST /api/auth/signup` - Create a new user account (requires email verification)
- `POST /api/auth/signin` - Sign in with email and password
- `POST /api/auth/signin-2fa` - Sign in with 2FA support
- `GET /api/auth/verify` - Verify JWT token
- `POST /api/auth/logout` - Logout (client-side token removal)
- `GET /api/auth/verify-email?token=` - Verify email address
- `POST /api/auth/resend-verification` - Resend verification email
- `POST /api/auth/forgot-password` - Request password reset
- `POST /api/auth/reset-password` - Reset password with token

### Social Login Routes
- `GET /api/auth/google` - Google OAuth login
- `GET /api/auth/google/callback` - Google OAuth callback
- `GET /api/auth/facebook` - Facebook OAuth login
- `GET /api/auth/facebook/callback` - Facebook OAuth callback
- `GET /api/auth/instagram` - Instagram OAuth login
- `GET /api/auth/instagram/callback` - Instagram OAuth callback

### Two-Factor Authentication
- `POST /api/auth/2fa/setup` - Setup 2FA (generate QR code)
- `POST /api/auth/2fa/verify` - Verify 2FA token
- `POST /api/auth/2fa/disable` - Disable 2FA

### User Profile Routes
- `GET /api/user/profile` - Get user profile (requires authentication)
- `PUT /api/user/profile` - Update user profile
- `POST /api/user/avatar` - Upload avatar image
- `POST /api/user/change-password` - Change password

### Tournament Routes
- `GET /api/tournaments` - List tournaments (with filtering)
- `GET /api/tournaments/:id` - Get tournament details
- `POST /api/tournaments` - Create tournament (requires authentication)
- `POST /api/tournaments/:id/register` - Register for tournament
- `DELETE /api/tournaments/:id/register` - Unregister from tournament
- `GET /api/user/tournaments` - Get user's tournament registrations

### Admin Routes (Admin only)
- `GET /api/admin/users` - List all users (with search/filter)
- `PUT /api/admin/users/:id/role` - Change user role
- `DELETE /api/admin/users/:id` - Delete user
- `GET /api/admin/tournaments` - List all tournaments (admin view)
- `PUT /api/admin/tournaments/:id/status` - Update tournament status
- `DELETE /api/admin/tournaments/:id` - Delete tournament
- `GET /api/admin/stats` - Get system statistics

## Security Features

- **Password Hashing**: Uses bcrypt with 12 salt rounds
- **JWT Tokens**: Secure token-based authentication
- **Rate Limiting**: Prevents brute force attacks (5 attempts per 15 minutes)
- **Input Validation**: Uses Joi for request validation
- **Security Headers**: Helmet.js for security headers
- **CORS Protection**: Configured for your domain

## Environment Variables

For production, set these environment variables:

```bash
# Server Configuration
JWT_SECRET=your-super-secret-jwt-key-here
PORT=3000

# Email Configuration (for email verification and password reset)
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password
EMAIL_FROM=noreply@tabletennis.com

# Social Login Configuration
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
FACEBOOK_APP_ID=your-facebook-app-id
FACEBOOK_APP_SECRET=your-facebook-app-secret
INSTAGRAM_CLIENT_ID=your-instagram-client-id
INSTAGRAM_CLIENT_SECRET=your-instagram-client-secret
```

### Setting up Social Login

1. **Google OAuth:**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create a new project or select existing one
   - Enable Google+ API
   - Create OAuth 2.0 credentials
   - Add authorized redirect URI: `http://localhost:3000/api/auth/google/callback`

2. **Facebook OAuth:**
   - Go to [Facebook Developers](https://developers.facebook.com/)
   - Create a new app
   - Add Facebook Login product
   - Set valid OAuth redirect URI: `http://localhost:3000/api/auth/facebook/callback`

3. **Instagram OAuth:**
   - Go to [Facebook Developers](https://developers.facebook.com/)
   - Create a new app
   - Add Instagram Basic Display product
   - Set valid OAuth redirect URI: `http://localhost:3000/api/auth/instagram/callback`

### Setting up Email (Gmail)

1. Enable 2-factor authentication on your Gmail account
2. Generate an "App Password" for this application
3. Use the app password as `EMAIL_PASS`

## Usage

1. **Sign Up**: Click "Sign Up" button to create a new account
2. **Sign In**: Click "Sign In" button to access your account
3. **User Profile**: Once logged in, you'll see your profile in the navigation
4. **Logout**: Click the logout button to sign out

## Database

The application uses SQLite for simplicity. The database file (`users.db`) is created automatically when you first run the server.

### User Table Schema
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## Development

- **Frontend**: Pure HTML, CSS, and JavaScript (no frameworks required)
- **Backend**: Node.js with Express.js
- **Database**: SQLite3
- **Authentication**: JWT tokens with bcrypt password hashing

## Production Deployment

For production deployment, consider:

1. **Environment Variables**: Set secure JWT secrets
2. **Database**: Consider PostgreSQL or MongoDB for better performance
3. **HTTPS**: Use SSL certificates for secure communication
4. **Process Manager**: Use PM2 for process management
5. **Reverse Proxy**: Use Nginx for serving static files and load balancing

## Troubleshooting

### Common Issues

1. **Port Already in Use**: Change the PORT in server.js or kill the process using the port
2. **Database Errors**: Delete `users.db` file and restart the server
3. **CORS Issues**: Check the CORS configuration in server.js

### Logs

Check the console output for detailed error messages and debugging information.

## New Features Implemented

### ✅ Email Verification
- **Automatic email verification** for new accounts
- **Resend verification email** functionality
- **Email verification page** with user-friendly interface
- **Secure verification tokens** with 24-hour expiration

### ✅ Password Reset
- **Forgot password** functionality with email reset links
- **Secure reset tokens** with 1-hour expiration
- **Password reset page** with token validation
- **One-time use tokens** for security

### ✅ User Profile Management
- **Complete profile editing** (name, phone, date of birth, skill level)
- **Avatar upload** with image validation (5MB limit)
- **Profile page** with tabbed interface
- **Password change** functionality
- **Real-time profile updates**

### ✅ Tournament Registration System
- **Create tournaments** with full details (name, location, dates, fees, skill levels)
- **Tournament browsing** with filtering by status and skill level
- **User registration** for tournaments with capacity limits
- **Registration management** (view, cancel registrations)
- **Tournament status tracking** (upcoming, ongoing, completed, cancelled)

### ✅ Admin Panel
- **Comprehensive user management** (view, edit roles, delete users)
- **Tournament management** (create, edit, delete, change status)
- **Admin statistics dashboard** with key metrics
- **Role-based access control** (user, moderator, admin)
- **Search and filtering** capabilities
- **Pagination** for large datasets

### ✅ Social Login Integration
- **Google OAuth 2.0** integration
- **Facebook OAuth** integration  
- **Instagram OAuth** integration
- **Automatic account linking** for existing users
- **Social profile data** import
- **Seamless authentication flow**

### ✅ Two-Factor Authentication (2FA)
- **TOTP-based 2FA** using Google Authenticator or similar apps
- **QR code generation** for easy setup
- **Manual key entry** option
- **2FA enforcement** during login
- **Easy enable/disable** functionality
- **Secure secret storage**

## Enhanced Security Features

- **Rate limiting** on authentication endpoints
- **Email rate limiting** to prevent spam
- **Input validation** with Joi schemas
- **SQL injection protection** with parameterized queries
- **Password hashing** with bcrypt (12 salt rounds)
- **JWT token security** with configurable secrets
- **CORS protection** and security headers
- **File upload validation** and size limits

## Support

If you encounter any issues, check the console logs for error messages and ensure all dependencies are properly installed.
