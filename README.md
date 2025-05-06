# Secure Flask Web Application

A secure Flask web application that implements user authentication and digital asset transfers with comprehensive security measures.

## Features

- User authentication with JWT stored in secure HTTP-only cookies
- Digital asset (gems) transfer system between users
- Password hashing using PBKDF2
- SQLite database for user storage
- Secure session management
- Comprehensive security measures against common web vulnerabilities

## How It Works

### User Authentication
1. Users can sign up with a username and password
2. Passwords are hashed using PBKDF2 before storage
3. New users receive 100 gems by default
4. Login uses JWT tokens stored in secure HTTP-only cookies
5. Sessions expire after 24 hours

### Asset Transfer System
1. Users can transfer gems to other users
2. Each transfer is validated for:
   - Sufficient balance
   - Valid recipient
   - Positive amount
   - Non-self-transfer
3. Transfers are atomic (using database transactions)
4. Real-time balance updates

## Security Measures

### Cross-Site Scripting (XSS) Protection
1. **Jinja2 Auto-escaping**: All template variables are automatically escaped
2. **Content Security Policy**: Implemented through meta tags:
   ```html
   <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'">
   ```
3. **Additional Security Headers**:
   - X-Content-Type-Options: nosniff
   - X-Frame-Options: DENY

### Cross-Site Request Forgery (CSRF) Protection
1. **Flask-WTF Integration**: CSRF tokens on all forms
2. **Token Validation**: Server-side validation of CSRF tokens
3. **Secure Cookie Settings**:
   - HttpOnly flag
   - Secure flag
   - SameSite=Strict

### SQL Injection Prevention
1. **Parameterized Queries**: All database operations use ? placeholders
   ```python
   c.execute('SELECT id, password FROM users WHERE username = ?', (username,))
   ```
2. **Input Validation**: All user inputs are validated before processing
3. **Database Transactions**: Atomic operations for transfers

### User Enumeration Prevention
1. **Generic Error Messages**: Login failures return the same message regardless of cause
   ```python
   return render_template('login.html', error='Login failed')
   ```
2. **Consistent Response Times**: No timing differences between valid/invalid usernames
3. **Secure Password Reset**: (If implemented) Would use email verification

### Additional Security Features
1. **Password Security**:
   - PBKDF2 hashing with SHA256
   - Secure password storage
2. **Session Security**:
   - JWT tokens with expiration
   - Secure cookie settings
3. **Database Security**:
   - SQLite with proper indexing
   - Transaction support
4. **Input Validation**:
   - Type checking
   - Range validation
   - Format validation

## Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Update the `.env` file with secure keys:
```
SECRET_KEY=your-secure-secret-key
JWT_SECRET_KEY=your-secure-jwt-key
```

4. Run the application:
```bash
python app.py
```

## Security Best Practices

1. **Environment Variables**:
   - Never commit `.env` file
   - Use strong, unique keys in production
   - Rotate keys periodically

2. **Database**:
   - Regular backups
   - Monitor for suspicious activity
   - Use proper indexing

3. **Application**:
   - Keep dependencies updated
   - Monitor error logs
   - Implement rate limiting
   - Use HTTPS in production

4. **User Management**:
   - Implement password complexity requirements
   - Add email verification
   - Implement account lockout
   - Add 2FA support

## Production Considerations

1. Use a production-grade WSGI server (e.g., Gunicorn)
2. Set up proper logging
3. Implement rate limiting
4. Use HTTPS with proper SSL/TLS configuration
5. Set up monitoring and alerting
6. Regular security audits
7. Backup strategy
8. Error handling and logging
