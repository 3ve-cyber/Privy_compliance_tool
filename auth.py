# auth.py - Authentication Server
# This server runs on port 8001 and handles:
# - User login
# - User registration (creates regular users)
# - Password changes
# - Password reset
# - User management (admin only)
# - Pre-creates admin account on first run

import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import jwt
import os

# ============ CONFIGURATION ============
SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

# ============ DATABASE FUNCTIONS ============
def get_user_db():
    """Connect to SQLite database"""
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_user_db():
    """Create database tables and pre-create admin account"""
    conn = get_user_db()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            role TEXT DEFAULT 'user',
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create sessions table (for active logins)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create password reset tokens table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            used INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # ========== PRE-CREATE ADMIN ACCOUNT ==========
    # This runs every time auth.py starts
    # If admin doesn't exist, it creates one
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        salt = secrets.token_hex(16)
        pwd_hash = hashlib.sha256((salt + 'admin123').encode()).hexdigest()
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, full_name, role)
            VALUES (?, ?, ?, ?, ?)
        ''', ('admin', 'admin@privy.com', f"{salt}:{pwd_hash}", 'System Administrator', 'admin'))
        print("✅ Admin account created: admin / admin123")
    
    # Also pre-create a regular user for testing
    cursor.execute("SELECT * FROM users WHERE username = 'user'")
    if not cursor.fetchone():
        salt = secrets.token_hex(16)
        pwd_hash = hashlib.sha256((salt + 'user123').encode()).hexdigest()
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, full_name, role)
            VALUES (?, ?, ?, ?, ?)
        ''', ('user', 'user@privy.com', f"{salt}:{pwd_hash}", 'Regular User', 'user'))
        print("✅ Regular user created: user / user123")
    
    conn.commit()
    conn.close()
    print("✅ Database initialized")

def verify_password(password: str, password_hash: str) -> bool:
    """Check if entered password matches stored hash"""
    if ':' not in password_hash:
        return False
    salt, hash_value = password_hash.split(':')
    new_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    return new_hash == hash_value

def hash_password(password: str) -> str:
    """Create secure password hash with random salt"""
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{pwd_hash}"

def create_token(data: dict) -> str:
    """Create JWT token for authenticated user"""
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> dict:
    """Verify JWT token and return user data"""
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ============ PYDANTIC MODELS ============
class UserLogin(BaseModel):
    username: str
    password: str

class UserRegister(BaseModel):
    username: str
    email: str
    password: str
    full_name: Optional[str] = ""

class PasswordChange(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str

class PasswordResetRequest(BaseModel):
    email: str

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str
    confirm_password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

# ============ FASTAPI APP ============
app = FastAPI(title="Privy Authentication")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    """Root endpoint - shows API status"""
    return {
        "message": "Privy Authentication API running on port 8001",
        "status": "healthy",
        "default_users": ["admin", "user"]
    }

@app.post("/api/auth/register")
async def register(user_data: UserRegister):
    """
    Register a new user account
    - Anyone can register
    - New users get role='user' (not admin)
    - Admin role can only be assigned by existing admin
    """
    conn = get_user_db()
    cursor = conn.cursor()
    
    # Check if username already exists
    cursor.execute("SELECT id FROM users WHERE username = ?", (user_data.username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Check if email already exists
    cursor.execute("SELECT id FROM users WHERE email = ?", (user_data.email,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Email already exists")
    
    # Hash password and create user with role='user'
    password_hash = hash_password(user_data.password)
    cursor.execute('''
        INSERT INTO users (username, email, password_hash, full_name, role)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_data.username, user_data.email, password_hash, user_data.full_name, 'user'))
    
    conn.commit()
    conn.close()
    
    return {"message": "User registered successfully"}

@app.post("/api/auth/login")
async def login(login_data: UserLogin):
    """
    Login user and return access token
    - Checks username exists and is active
    - Verifies password
    - Returns JWT token for authentication
    """
    conn = get_user_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (login_data.username,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    if not verify_password(login_data.password, user['password_hash']):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    # Create JWT token
    token = create_token({
        "user_id": user['id'],
        "username": user['username'],
        "role": user['role']
    })
    
    # Store session in database
    expires_at = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    cursor.execute('''
        INSERT INTO sessions (user_id, token, expires_at)
        VALUES (?, ?, ?)
    ''', (user['id'], token, expires_at))
    conn.commit()
    conn.close()
    
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse(
            id=user['id'],
            username=user['username'],
            email=user['email'],
            full_name=user['full_name'] or '',
            role=user['role'],
            is_active=bool(user['is_active']),
            created_at=user['created_at']
        )
    )

@app.post("/api/auth/logout")
async def logout(request: Request):
    """
    Logout user - invalidates their session token
    """
    auth = request.headers.get('Authorization')
    if not auth:
        raise HTTPException(status_code=401, detail="No token")
    
    token = auth.split(' ')[1]
    conn = get_user_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
    conn.commit()
    conn.close()
    
    return {"message": "Logged out successfully"}

@app.get("/api/auth/me")
async def get_current_user(request: Request):
    """
    Get current user information from token
    """
    auth = request.headers.get('Authorization')
    if not auth:
        raise HTTPException(status_code=401, detail="No token")
    
    token = auth.split(' ')[1]
    payload = verify_token(token)
    
    conn = get_user_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ? AND is_active = 1", (payload['user_id'],))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return UserResponse(
        id=user['id'],
        username=user['username'],
        email=user['email'],
        full_name=user['full_name'] or '',
        role=user['role'],
        is_active=bool(user['is_active']),
        created_at=user['created_at']
    )

@app.post("/api/auth/change-password")
async def change_password(request: Request, password_data: PasswordChange):
    """
    Change password for logged-in user
    - Requires current password for verification
    - Invalidates all sessions (forces re-login)
    """
    auth = request.headers.get('Authorization')
    if not auth:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    token = auth.split(' ')[1]
    payload = verify_token(token)
    user_id = payload.get('user_id')
    
    if password_data.new_password != password_data.confirm_password:
        raise HTTPException(status_code=400, detail="New passwords do not match")
    
    if len(password_data.new_password) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")
    
    conn = get_user_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    
    if not verify_password(password_data.current_password, user['password_hash']):
        conn.close()
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    
    # Update password
    new_password_hash = hash_password(password_data.new_password)
    cursor.execute('''
        UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP 
        WHERE id = ?
    ''', (new_password_hash, user_id))
    
    # Invalidate all sessions (force re-login)
    cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    
    conn.commit()
    conn.close()
    
    return {"message": "Password changed successfully. Please login again."}

@app.post("/api/auth/reset-password-request")
async def reset_password_request(reset_data: PasswordResetRequest):
    """
    Request password reset
    - Generates a reset token
    - In production, sends email with reset link
    - For demo, returns the token
    """
    conn = get_user_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM users WHERE email = ? AND is_active = 1", (reset_data.email,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return {"message": "If the email exists, a reset link has been sent"}
    
    # Generate reset token
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=24)
    
    cursor.execute('''
        INSERT INTO password_resets (user_id, token, expires_at)
        VALUES (?, ?, ?)
    ''', (user['id'], token, expires_at))
    conn.commit()
    conn.close()
    
    # In production, send email with reset link
    print(f"🔑 Password reset token for {reset_data.email}: {token}")
    
    return {
        "message": "If the email exists, a reset link has been sent",
        "token": token  # Only for demo - remove in production!
    }

@app.post("/api/auth/reset-password-confirm")
async def reset_password_confirm(reset_data: PasswordResetConfirm):
    """
    Confirm password reset with token
    - Verifies token is valid and not expired
    - Updates user password
    - Invalidates all sessions
    """
    if reset_data.new_password != reset_data.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    
    if len(reset_data.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    
    conn = get_user_db()
    cursor = conn.cursor()
    
    # Find valid reset token
    cursor.execute('''
        SELECT * FROM password_resets 
        WHERE token = ? AND used = 0 AND expires_at > CURRENT_TIMESTAMP
    ''', (reset_data.token,))
    reset = cursor.fetchone()
    
    if not reset:
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    
    # Update password
    new_password_hash = hash_password(reset_data.new_password)
    cursor.execute('''
        UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP 
        WHERE id = ?
    ''', (new_password_hash, reset['user_id']))
    
    # Mark token as used
    cursor.execute('UPDATE password_resets SET used = 1 WHERE id = ?', (reset['id'],))
    
    # Invalidate all sessions
    cursor.execute("DELETE FROM sessions WHERE user_id = ?", (reset['user_id'],))
    
    conn.commit()
    conn.close()
    
    return {"message": "Password reset successfully. Please login."}

@app.get("/api/auth/users")
async def list_users(request: Request):
    """
    List all users - ADMIN ONLY
    Regular users cannot access this endpoint
    """
    auth = request.headers.get('Authorization')
    if not auth:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    token = auth.split(' ')[1]
    payload = verify_token(token)
    
    # Check if user is admin
    if payload.get('role') != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    conn = get_user_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, full_name, role, is_active, created_at FROM users")
    users = cursor.fetchall()
    conn.close()
    
    return [UserResponse(
        id=u['id'],
        username=u['username'],
        email=u['email'],
        full_name=u['full_name'] or '',
        role=u['role'],
        is_active=bool(u['is_active']),
        created_at=u['created_at']
    ) for u in users]

@app.put("/api/auth/users/{user_id}/role")
async def update_user_role(user_id: int, request: Request, role: str):
    """
    Update user role - ADMIN ONLY
    Can change a user to 'admin' or 'user'
    """
    auth = request.headers.get('Authorization')
    if not auth:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    token = auth.split(' ')[1]
    payload = verify_token(token)
    
    if payload.get('role') != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if role not in ['admin', 'user']:
        raise HTTPException(status_code=400, detail="Invalid role")
    
    conn = get_user_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (role, user_id))
    conn.commit()
    conn.close()
    
    return {"message": f"User role updated to {role}"}

# Initialize database on startup
init_user_db()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="localhost", port=8001)