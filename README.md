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
- `POST /api/auth/signup` - Create a new user account
- `POST /api/auth/signin` - Sign in with email and password
- `GET /api/auth/verify` - Verify JWT token
- `POST /api/auth/logout` - Logout (client-side token removal)

### Protected Routes
- `GET /api/user/profile` - Get user profile (requires authentication)

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
JWT_SECRET=your-super-secret-jwt-key-here
PORT=3000
```

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

## Next Steps

Consider adding these features:
- Email verification for new accounts
- Password reset functionality
- User profile management
- Tournament registration system
- Admin panel for managing users and tournaments
- Social login (Google, Facebook)
- Two-factor authentication

## Support

If you encounter any issues, check the console logs for error messages and ensure all dependencies are properly installed.
