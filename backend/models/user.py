"""
User Model and Authentication System
===================================

SQLite-based user management with role-based authentication for digital forensics application.
Supports Admin, Forensic Investigator, and Viewer roles with appropriate permissions.
"""

import sqlite3
import hashlib
import secrets
import jwt
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, List, Dict, Any
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class UserRole(Enum):
    """User roles with hierarchical permissions"""
    ADMIN = "admin"
    FORENSIC_INVESTIGATOR = "forensic_investigator"
    VIEWER = "viewer"

class UserStatus(Enum):
    """User account status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"

class Permission(Enum):
    """System permissions"""
    # Case management
    CREATE_CASE = "create_case"
    VIEW_CASE = "view_case"
    EDIT_CASE = "edit_case"
    DELETE_CASE = "delete_case"
    
    # Evidence management
    UPLOAD_EVIDENCE = "upload_evidence"
    VIEW_EVIDENCE = "view_evidence"
    MODIFY_EVIDENCE = "modify_evidence"
    DELETE_EVIDENCE = "delete_evidence"
    
    # Analysis operations
    PERFORM_ANALYSIS = "perform_analysis"
    VIEW_ANALYSIS = "view_analysis"
    EXPORT_RESULTS = "export_results"
    
    # System administration
    MANAGE_USERS = "manage_users"
    VIEW_LOGS = "view_logs"
    SYSTEM_CONFIG = "system_config"
    
    # Integrity operations
    VERIFY_INTEGRITY = "verify_integrity"
    MANAGE_INTEGRITY = "manage_integrity"

# Role-based permission matrix
ROLE_PERMISSIONS = {
    UserRole.ADMIN: [
        # Full system access
        Permission.CREATE_CASE, Permission.VIEW_CASE, Permission.EDIT_CASE, Permission.DELETE_CASE,
        Permission.UPLOAD_EVIDENCE, Permission.VIEW_EVIDENCE, Permission.MODIFY_EVIDENCE, Permission.DELETE_EVIDENCE,
        Permission.PERFORM_ANALYSIS, Permission.VIEW_ANALYSIS, Permission.EXPORT_RESULTS,
        Permission.MANAGE_USERS, Permission.VIEW_LOGS, Permission.SYSTEM_CONFIG,
        Permission.VERIFY_INTEGRITY, Permission.MANAGE_INTEGRITY
    ],
    UserRole.FORENSIC_INVESTIGATOR: [
        # Investigation and analysis capabilities
        Permission.CREATE_CASE, Permission.VIEW_CASE, Permission.EDIT_CASE,
        Permission.UPLOAD_EVIDENCE, Permission.VIEW_EVIDENCE, Permission.MODIFY_EVIDENCE,
        Permission.PERFORM_ANALYSIS, Permission.VIEW_ANALYSIS, Permission.EXPORT_RESULTS,
        Permission.VIEW_LOGS, Permission.VERIFY_INTEGRITY
    ],
    UserRole.VIEWER: [
        # Read-only access
        Permission.VIEW_CASE, Permission.VIEW_EVIDENCE, Permission.VIEW_ANALYSIS
    ]
}

class User:
    """User model for authentication and authorization"""
    
    def __init__(self, user_id: int = None, username: str = None, email: str = None, 
                 password_hash: str = None, salt: str = None, role: UserRole = None,
                 status: UserStatus = UserStatus.ACTIVE, created_at: datetime = None,
                 last_login: datetime = None, login_attempts: int = 0,
                 full_name: str = None, department: str = None):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.salt = salt
        self.role = role
        self.status = status
        self.created_at = created_at or datetime.utcnow()
        self.last_login = last_login
        self.login_attempts = login_attempts
        self.full_name = full_name
        self.department = department
    
    def has_permission(self, permission: Permission) -> bool:
        """Check if user has specific permission"""
        if self.status != UserStatus.ACTIVE:
            return False
        
        role_perms = ROLE_PERMISSIONS.get(self.role, [])
        return permission in role_perms
    
    @property
    def is_active(self) -> bool:
        """Check if user account is active"""
        return self.status == UserStatus.ACTIVE
    
    def get_permissions(self) -> List[Permission]:
        """Get all permissions for user's role"""
        if self.status != UserStatus.ACTIVE:
            return []
        
        return ROLE_PERMISSIONS.get(self.role, [])
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert user to dictionary representation"""
        user_dict = {
            'user_id': self.user_id,
            'username': self.username,
            'email': self.email,
            'role': self.role.value if self.role else None,
            'status': self.status.value if self.status else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'full_name': self.full_name,
            'department': self.department,
            'permissions': [p.value for p in self.get_permissions()]
        }
        
        if include_sensitive:
            user_dict.update({
                'login_attempts': self.login_attempts,
                'password_hash': self.password_hash,
                'salt': self.salt
            })
        
        return user_dict

class UserManager:
    """Database manager for user operations"""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.path.join(os.path.dirname(__file__), '..', 'database', 'users.db')
        self.secret_key = self._get_or_create_secret_key()
        self._initialize_database()
        self._create_default_admin()
    
    def _get_or_create_secret_key(self) -> str:
        """Get or create JWT secret key"""
        secret_file = os.path.join(os.path.dirname(self.db_path), 'jwt_secret.key')
        
        if os.path.exists(secret_file):
            with open(secret_file, 'r') as f:
                return f.read().strip()
        else:
            # Create new secret key
            secret = secrets.token_urlsafe(32)
            os.makedirs(os.path.dirname(secret_file), exist_ok=True)
            with open(secret_file, 'w') as f:
                f.write(secret)
            return secret
    
    def initialize_database(self):
        """Public method to initialize user database tables"""
        return self._initialize_database()
    
    def _initialize_database(self):
        """Initialize user database tables"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role TEXT NOT NULL,
                    status TEXT DEFAULT 'active',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    login_attempts INTEGER DEFAULT 0,
                    full_name TEXT,
                    department TEXT
                )
            ''')
            
            # User sessions table for JWT token management
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    token_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    ip_address TEXT,
                    user_agent TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (user_id)
                )
            ''')
            
            # User activity log
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_activity (
                    activity_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN DEFAULT 1,
                    details TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (user_id)
                )
            ''')
            
            conn.commit()
            logger.info("User database initialized successfully")
    
    def _create_default_admin(self):
        """Create default admin user if none exists"""
        try:
            if not self.get_user_by_username('admin'):
                admin_user = self.create_user(
                    username='admin',
                    email='admin@forensics.local',
                    password='ForensicsAdmin2024!',
                    role=UserRole.ADMIN,
                    full_name='System Administrator',
                    department='IT Security'
                )
                logger.info(f"Default admin user created: {admin_user.username}")
            
            # Create demo user
            if not self.get_user_by_username('hellohacker'):
                demo_user = self.create_user(
                    username='hellohacker',
                    email='demo@forensics.local',
                    password='HACKME184',
                    role=UserRole.FORENSIC_INVESTIGATOR,
                    full_name='Demo User',
                    department='Demo Department'
                )
                logger.info(f"Demo user created: {demo_user.username}")
        except Exception as e:
            logger.error(f"Failed to create default users: {e}")
    
    def _hash_password(self, password: str, salt: str = None) -> tuple[str, str]:
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        
        # Use PBKDF2 with SHA-256
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return password_hash.hex(), salt
    
    def create_user(self, username: str, email: str, password: str, role: UserRole,
                   full_name: str = None, department: str = None) -> Optional[User]:
        """Create new user"""
        try:
            password_hash, salt = self._hash_password(password)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (username, email, password_hash, salt, role, full_name, department)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (username, email, password_hash, salt, role.value, full_name, department))
                
                user_id = cursor.lastrowid
                conn.commit()
                
                logger.info(f"User created: {username} (ID: {user_id}, Role: {role.value})")
                return self.get_user_by_id(user_id)
        
        except sqlite3.IntegrityError as e:
            logger.error(f"Failed to create user {username}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error creating user {username}: {e}")
            return None
    
    def authenticate_user(self, username: str, password: str, ip_address: str = None) -> Optional[User]:
        """Authenticate user credentials"""
        user = self.get_user_by_username(username)
        
        if not user:
            self._log_activity(None, 'login_failed', f'Unknown username: {username}', ip_address, success=False)
            return None
        
        # Check if account is locked
        if user.login_attempts >= 5:
            self._log_activity(user.user_id, 'login_blocked', 'Account locked due to failed attempts', ip_address, success=False)
            return None
        
        # Verify password
        password_hash, _ = self._hash_password(password, user.salt)
        if password_hash == user.password_hash and user.status == UserStatus.ACTIVE:
            # Reset login attempts on successful login
            self._reset_login_attempts(user.user_id)
            self._update_last_login(user.user_id)
            self._log_activity(user.user_id, 'login_success', None, ip_address, success=True)
            return user
        else:
            # Increment login attempts
            self._increment_login_attempts(user.user_id)
            self._log_activity(user.user_id, 'login_failed', 'Invalid credentials', ip_address, success=False)
            return None
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE user_id = ?', (user_id,))
            row = cursor.fetchone()
            
            if row:
                return self._row_to_user(row)
            return None
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            
            if row:
                return self._row_to_user(row)
            return None
    
    def get_all_users(self) -> List[User]:
        """Get all users"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users ORDER BY created_at DESC')
            rows = cursor.fetchall()
            
            return [self._row_to_user(row) for row in rows]
    
    def update_user(self, user_id: int, **kwargs) -> bool:
        """Update user information"""
        try:
            allowed_fields = ['email', 'role', 'status', 'full_name', 'department']
            updates = []
            values = []
            
            for field, value in kwargs.items():
                if field in allowed_fields:
                    updates.append(f"{field} = ?")
                    if field == 'role' and isinstance(value, UserRole):
                        values.append(value.value)
                    elif field == 'status' and isinstance(value, UserStatus):
                        values.append(value.value)
                    else:
                        values.append(value)
            
            if not updates:
                return False
            
            values.append(user_id)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(f'UPDATE users SET {", ".join(updates)} WHERE user_id = ?', values)
                conn.commit()
                
                if cursor.rowcount > 0:
                    logger.info(f"User {user_id} updated: {kwargs}")
                    return True
                return False
        
        except Exception as e:
            logger.error(f"Failed to update user {user_id}: {e}")
            return False
    
    def change_password(self, user_id: int, old_password: str, new_password: str) -> bool:
        """Change user password"""
        user = self.get_user_by_id(user_id)
        if not user:
            return False
        
        # Verify old password
        old_hash, _ = self._hash_password(old_password, user.salt)
        if old_hash != user.password_hash:
            return False
        
        # Set new password
        new_hash, new_salt = self._hash_password(new_password)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE users SET password_hash = ?, salt = ? WHERE user_id = ?',
                             (new_hash, new_salt, user_id))
                conn.commit()
                
                logger.info(f"Password changed for user {user_id}")
                return True
        except Exception as e:
            logger.error(f"Failed to change password for user {user_id}: {e}")
            return False
    
    def generate_jwt_token(self, user: User, expires_hours: int = 24) -> str:
        """Generate JWT token for user"""
        payload = {
            'user_id': user.user_id,
            'username': user.username,
            'role': user.role.value,
            'exp': datetime.utcnow() + timedelta(hours=expires_hours),
            'iat': datetime.utcnow()
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm='HS256')
        
        # Store session information
        session_id = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        expires_at = datetime.utcnow() + timedelta(hours=expires_hours)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO user_sessions (session_id, user_id, token_hash, expires_at)
                    VALUES (?, ?, ?, ?)
                ''', (session_id, user.user_id, token_hash, expires_at))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to store session for user {user.user_id}: {e}")
        
        return token
    
    def verify_jwt_token(self, token: str) -> Optional[User]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            user_id = payload.get('user_id')
            
            # Check if session is still active
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM user_sessions 
                    WHERE token_hash = ? AND is_active = 1 AND expires_at > CURRENT_TIMESTAMP
                ''', (token_hash,))
                
                if not cursor.fetchone():
                    return None
            
            return self.get_user_by_id(user_id)
        
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid JWT token")
            return None
        except Exception as e:
            logger.error(f"JWT verification error: {e}")
            return None
    
    def logout_user(self, token: str) -> bool:
        """Logout user by deactivating session"""
        try:
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('UPDATE user_sessions SET is_active = 0 WHERE token_hash = ?', (token_hash,))
                conn.commit()
                
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Logout error: {e}")
            return False
    
    def _row_to_user(self, row) -> User:
        """Convert database row to User object"""
        return User(
            user_id=row[0],
            username=row[1],
            email=row[2],
            password_hash=row[3],
            salt=row[4],
            role=UserRole(row[5]),
            status=UserStatus(row[6]) if row[6] else UserStatus.ACTIVE,
            created_at=datetime.fromisoformat(row[7]) if row[7] else None,
            last_login=datetime.fromisoformat(row[8]) if row[8] else None,
            login_attempts=row[9] or 0,
            full_name=row[10],
            department=row[11]
        )
    
    def _increment_login_attempts(self, user_id: int):
        """Increment failed login attempts"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET login_attempts = login_attempts + 1 WHERE user_id = ?', (user_id,))
            conn.commit()
    
    def _reset_login_attempts(self, user_id: int):
        """Reset login attempts to 0"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET login_attempts = 0 WHERE user_id = ?', (user_id,))
            conn.commit()
    
    def _update_last_login(self, user_id: int):
        """Update last login timestamp"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?', (user_id,))
            conn.commit()
    
    def _log_activity(self, user_id: int, action: str, resource: str = None, 
                     ip_address: str = None, success: bool = True, details: str = None):
        """Log user activity"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO user_activity (user_id, action, resource, ip_address, success, details)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (user_id, action, resource, ip_address, success, details))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to log activity: {e}")

# Global user manager instance
user_manager = UserManager()

# Authentication decorator
def require_auth(min_role='Viewer'):
    """
    Decorator to require authentication and minimum role for API endpoints
    
    Args:
        min_role (str): Minimum role required ('Viewer', 'Forensic Investigator', 'Admin')
    """
    from functools import wraps
    from flask import request, jsonify, g
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Role hierarchy for permission checking
            role_hierarchy = {
                'viewer': 1,
                'forensic_investigator': 2,
                'admin': 3,
                # Also support capitalized versions for compatibility
                'Viewer': 1,
                'Forensic Investigator': 2,
                'Admin': 3
            }
            
            try:
                # Get token from Authorization header
                token = None
                auth_header = request.headers.get('Authorization')
                if auth_header and auth_header.startswith('Bearer '):
                    token = auth_header.split(' ')[1]
                
                # Fallback to cookie if no header token
                if not token:
                    token = request.cookies.get('auth_token')
                
                if not token:
                    return jsonify({'error': 'Authentication token required'}), 401
                
                # Verify token and get user
                current_user = user_manager.verify_jwt_token(token)
                if not current_user:
                    return jsonify({'error': 'Invalid or expired token'}), 401
                
                # Check if user is active
                if not current_user.is_active:
                    return jsonify({'error': 'Account is disabled'}), 403
                
                # Check role permission
                user_role_value = current_user.role.value if hasattr(current_user.role, 'value') else current_user.role
                user_role_level = role_hierarchy.get(user_role_value, 0)
                min_role_level = role_hierarchy.get(min_role, 1)
                
                if user_role_level < min_role_level:
                    return jsonify({
                        'error': 'Insufficient permissions',
                        'required_role': min_role,
                        'user_role': user_role_value
                    }), 403
                
                # Add user to request context
                request.current_user = current_user
                g.current_user = current_user
                
                # Log API access
                user_manager._log_activity(
                    user_id=current_user.user_id,
                    action='API_ACCESS',
                    resource=request.endpoint,
                    ip_address=request.remote_addr,
                    success=True,
                    details=f"Accessed {request.method} {request.path}"
                )
                
                return f(*args, **kwargs)
                
            except Exception as e:
                logger.error(f"Authentication error in {f.__name__}: {e}")
                return jsonify({'error': 'Authentication failed'}), 401
        
        return decorated_function
    return decorator