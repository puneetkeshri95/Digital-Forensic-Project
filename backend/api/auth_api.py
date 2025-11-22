"""
Authentication API Endpoints
============================

Flask API endpoints for user authentication, registration, and session management
with JWT token-based authentication and role-based access control.
"""

from flask import Blueprint, request, jsonify, current_app
from functools import wraps
import jwt
from datetime import datetime
import logging

# Import user models
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.user import user_manager, UserRole, UserStatus, Permission

# Create authentication blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_client_ip():
    """Get client IP address"""
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return request.environ['REMOTE_ADDR']
    else:
        return request.environ['HTTP_X_FORWARDED_FOR']

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(' ')[1]  # Bearer <token>
            except IndexError:
                return jsonify({'error': 'Invalid authorization header format'}), 401
        
        # Get token from cookie (fallback)
        if not token:
            token = request.cookies.get('auth_token')
        
        if not token:
            return jsonify({'error': 'Authentication token is missing'}), 401
        
        try:
            current_user = user_manager.verify_jwt_token(token)
            if not current_user:
                return jsonify({'error': 'Token is invalid or expired'}), 401
            
            # Add current user to request context
            request.current_user = current_user
            return f(*args, **kwargs)
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return jsonify({'error': 'Authentication failed'}), 401
    
    return decorated_function

def require_permission(permission: Permission):
    """Decorator to require specific permission"""
    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated_function(*args, **kwargs):
            if not request.current_user.has_permission(permission):
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_role(required_role: UserRole):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated_function(*args, **kwargs):
            if request.current_user.role != required_role:
                return jsonify({'error': f'Role {required_role.value} required'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@auth_bp.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        
        if not data or not data.get('username') or not data.get('password'):
            return jsonify({'error': 'Username and password are required'}), 400
        
        username = data['username'].strip()
        password = data['password']
        remember_me = data.get('remember_me', False)
        
        # Get client information
        ip_address = get_client_ip()
        user_agent = request.headers.get('User-Agent', '')
        
        # Authenticate user
        user = user_manager.authenticate_user(username, password, ip_address)
        
        if not user:
            return jsonify({
                'success': False,
                'error': 'Invalid credentials or account locked'
            }), 401
        
        # Generate JWT token
        expires_hours = 24 * 7 if remember_me else 24  # 7 days if remember me, otherwise 24 hours
        token = user_manager.generate_jwt_token(user, expires_hours)
        
        # Prepare response
        response_data = {
            'success': True,
            'message': 'Login successful',
            'token': token,
            'user': user.to_dict(),
            'expires_in': expires_hours * 3600  # seconds
        }
        
        response = jsonify(response_data)
        
        # Set secure HTTP-only cookie
        response.set_cookie(
            'auth_token',
            token,
            max_age=expires_hours * 3600,
            httponly=True,
            secure=request.is_secure,
            samesite='Lax'
        )
        
        logger.info(f"User {username} logged in successfully from {ip_address}")
        return response
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

@auth_bp.route('/logout', methods=['POST'])
@require_auth
def logout():
    """User logout endpoint"""
    try:
        # Get token
        auth_header = request.headers.get('Authorization')
        token = None
        
        if auth_header:
            token = auth_header.split(' ')[1]
        else:
            token = request.cookies.get('auth_token')
        
        if token:
            user_manager.logout_user(token)
        
        response = jsonify({
            'success': True,
            'message': 'Logout successful'
        })
        
        # Clear auth cookie
        response.set_cookie('auth_token', '', expires=0)
        
        logger.info(f"User {request.current_user.username} logged out")
        return response
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'error': 'Logout failed'}), 500

@auth_bp.route('/register', methods=['POST'])
@require_permission(Permission.MANAGE_USERS)
def register():
    """User registration endpoint (Admin only)"""
    try:
        data = request.get_json()
        
        required_fields = ['username', 'email', 'password', 'role']
        if not data or not all(field in data for field in required_fields):
            return jsonify({
                'error': f'Missing required fields: {", ".join(required_fields)}'
            }), 400
        
        username = data['username'].strip()
        email = data['email'].strip()
        password = data['password']
        role_str = data['role']
        full_name = data.get('full_name', '').strip()
        department = data.get('department', '').strip()
        
        # Validate role
        try:
            role = UserRole(role_str)
        except ValueError:
            return jsonify({
                'error': f'Invalid role. Must be one of: {[r.value for r in UserRole]}'
            }), 400
        
        # Validate password strength
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters long'}), 400
        
        # Create user
        new_user = user_manager.create_user(
            username=username,
            email=email,
            password=password,
            role=role,
            full_name=full_name if full_name else None,
            department=department if department else None
        )
        
        if not new_user:
            return jsonify({'error': 'Failed to create user. Username or email may already exist.'}), 400
        
        logger.info(f"User {username} registered by {request.current_user.username}")
        
        return jsonify({
            'success': True,
            'message': 'User registered successfully',
            'user': new_user.to_dict()
        })
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@auth_bp.route('/profile', methods=['GET'])
@require_auth
def get_profile():
    """Get current user profile"""
    try:
        return jsonify({
            'success': True,
            'user': request.current_user.to_dict()
        })
    except Exception as e:
        logger.error(f"Profile retrieval error: {e}")
        return jsonify({'error': 'Failed to retrieve profile'}), 500

@auth_bp.route('/profile', methods=['PUT'])
@require_auth
def update_profile():
    """Update current user profile"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        user_id = request.current_user.user_id
        
        # Users can only update certain fields
        allowed_updates = {}
        if 'email' in data:
            allowed_updates['email'] = data['email'].strip()
        if 'full_name' in data:
            allowed_updates['full_name'] = data['full_name'].strip()
        if 'department' in data:
            allowed_updates['department'] = data['department'].strip()
        
        if not allowed_updates:
            return jsonify({'error': 'No valid fields to update'}), 400
        
        success = user_manager.update_user(user_id, **allowed_updates)
        
        if success:
            updated_user = user_manager.get_user_by_id(user_id)
            return jsonify({
                'success': True,
                'message': 'Profile updated successfully',
                'user': updated_user.to_dict()
            })
        else:
            return jsonify({'error': 'Failed to update profile'}), 400
        
    except Exception as e:
        logger.error(f"Profile update error: {e}")
        return jsonify({'error': 'Profile update failed'}), 500

@auth_bp.route('/change-password', methods=['POST'])
@require_auth
def change_password():
    """Change user password"""
    try:
        data = request.get_json()
        
        if not data or not data.get('current_password') or not data.get('new_password'):
            return jsonify({'error': 'Current password and new password are required'}), 400
        
        current_password = data['current_password']
        new_password = data['new_password']
        
        # Validate new password
        if len(new_password) < 8:
            return jsonify({'error': 'New password must be at least 8 characters long'}), 400
        
        success = user_manager.change_password(
            request.current_user.user_id, 
            current_password, 
            new_password
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Password changed successfully'
            })
        else:
            return jsonify({'error': 'Current password is incorrect'}), 400
        
    except Exception as e:
        logger.error(f"Password change error: {e}")
        return jsonify({'error': 'Password change failed'}), 500

@auth_bp.route('/dashboard-stats', methods=['GET'])
@require_auth
def get_dashboard_stats():
    """Get dashboard statistics for the current user"""
    try:
        # In a real application, this would fetch from database
        # For now, return placeholder stats that frontend can override with localStorage
        stats = {
            'files_analyzed': 0,
            'integrity_checks': 0,
            'active_users': 1,
            'last_updated': datetime.now().isoformat()
        }
        
        return jsonify({
            'success': True,
            'stats': stats,
            'message': 'Statistics are currently tracked in client-side storage'
        })
    except Exception as e:
        logger.error(f"Dashboard stats error: {e}")
        return jsonify({'error': 'Failed to retrieve dashboard statistics'}), 500

@auth_bp.route('/users', methods=['GET'])
@require_permission(Permission.MANAGE_USERS)
def get_users():
    """Get all users (Admin only)"""
    try:
        users = user_manager.get_all_users()
        return jsonify({
            'success': True,
            'users': [user.to_dict() for user in users]
        })
    except Exception as e:
        logger.error(f"Users retrieval error: {e}")
        return jsonify({'error': 'Failed to retrieve users'}), 500

@auth_bp.route('/users/<int:user_id>', methods=['GET'])
@require_permission(Permission.MANAGE_USERS)
def get_user(user_id):
    """Get specific user (Admin only)"""
    try:
        user = user_manager.get_user_by_id(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'success': True,
            'user': user.to_dict()
        })
    except Exception as e:
        logger.error(f"User retrieval error: {e}")
        return jsonify({'error': 'Failed to retrieve user'}), 500

@auth_bp.route('/users/<int:user_id>', methods=['PUT'])
@require_permission(Permission.MANAGE_USERS)
def update_user(user_id):
    """Update user (Admin only)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate role if provided
        if 'role' in data:
            try:
                data['role'] = UserRole(data['role'])
            except ValueError:
                return jsonify({
                    'error': f'Invalid role. Must be one of: {[r.value for r in UserRole]}'
                }), 400
        
        # Validate status if provided
        if 'status' in data:
            try:
                data['status'] = UserStatus(data['status'])
            except ValueError:
                return jsonify({
                    'error': f'Invalid status. Must be one of: {[s.value for s in UserStatus]}'
                }), 400
        
        success = user_manager.update_user(user_id, **data)
        
        if success:
            updated_user = user_manager.get_user_by_id(user_id)
            logger.info(f"User {user_id} updated by {request.current_user.username}")
            return jsonify({
                'success': True,
                'message': 'User updated successfully',
                'user': updated_user.to_dict()
            })
        else:
            return jsonify({'error': 'Failed to update user'}), 400
        
    except Exception as e:
        logger.error(f"User update error: {e}")
        return jsonify({'error': 'User update failed'}), 500

@auth_bp.route('/validate-token', methods=['GET'])
@require_auth
def validate_token():
    """Validate current token and return user info"""
    try:
        return jsonify({
            'success': True,
            'valid': True,
            'user': request.current_user.to_dict()
        })
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        return jsonify({'error': 'Token validation failed'}), 500

@auth_bp.route('/permissions', methods=['GET'])
@require_auth
def get_permissions():
    """Get current user's permissions"""
    try:
        permissions = request.current_user.get_permissions()
        return jsonify({
            'success': True,
            'permissions': [p.value for p in permissions],
            'role': request.current_user.role.value
        })
    except Exception as e:
        logger.error(f"Permissions retrieval error: {e}")
        return jsonify({'error': 'Failed to retrieve permissions'}), 500

@auth_bp.route('/system-info', methods=['GET'])
@require_auth
def get_system_info():
    """Get system information and user stats"""
    try:
        # Get basic system info
        all_users = user_manager.get_all_users()
        
        # Count users by role
        role_counts = {}
        status_counts = {}
        
        for user in all_users:
            role_counts[user.role.value] = role_counts.get(user.role.value, 0) + 1
            status_counts[user.status.value] = status_counts.get(user.status.value, 0) + 1
        
        return jsonify({
            'success': True,
            'system_info': {
                'total_users': len(all_users),
                'role_distribution': role_counts,
                'status_distribution': status_counts,
                'available_roles': [role.value for role in UserRole],
                'available_permissions': [perm.value for perm in Permission]
            },
            'current_user': {
                'username': request.current_user.username,
                'role': request.current_user.role.value,
                'permissions_count': len(request.current_user.get_permissions())
            }
        })
        
    except Exception as e:
        logger.error(f"System info error: {e}")
        return jsonify({'error': 'Failed to retrieve system information'}), 500