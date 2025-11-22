"""
Digital Forensics Application - Main Flask Application
"""
import os
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from config.config import Config
from api.forensic_api import forensic_bp
from api.file_api import file_bp
from api.analysis_api import analysis_bp
from api.deep_scan_api import deep_scan_bp
from api.forensic_analysis_api import forensic_analysis_bp
from api.exif_api import exif_bp
from api.ela_api import ela_bp
from api.clone_noise_api import clone_noise_bp
from api.hex_viewer_api import hex_viewer_bp
from api.logging_api import logging_bp
from api.integrity_api import integrity_bp
from api.auto_integrity_api import auto_integrity_bp
from api.enhanced_ela_api import enhanced_ela_bp
from api.auth_api import auth_bp
import logging
from datetime import datetime

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Set secret key for JWT
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'digital-forensics-secret-key-2024')
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-for-digital-forensics-2024')
    
    # Enable CORS for frontend communication
    CORS(app)
    
    # Setup logging
    setup_logging(app)
    
    # Initialize forensics database
    try:
        from database.forensics_db import ForensicsDatabase
        db = ForensicsDatabase()
        app.logger.info('Forensics database initialized successfully')
    except Exception as e:
        app.logger.warning(f'Failed to initialize forensics database: {e}')
    
    # Initialize user authentication database
    try:
        from models.user import user_manager
        user_manager.initialize_database()
        
        # Create default admin user if none exists
        if not user_manager.get_user_by_username('admin'):
            user_manager.create_user(
                username='admin',
                password='admin123',
                email='admin@forensics.local',
                full_name='System Administrator',
                role='Admin'
            )
            app.logger.info('Default admin user created: admin/admin123')
        
        app.logger.info('User authentication database initialized successfully')
    except Exception as e:
        app.logger.error(f'Failed to initialize user database: {e}')
    
    # Register blueprints
    app.register_blueprint(forensic_bp, url_prefix='/api/forensic')
    app.register_blueprint(file_bp, url_prefix='/api/files')
    app.register_blueprint(analysis_bp, url_prefix='/api/analysis')
    app.register_blueprint(deep_scan_bp, url_prefix='/api/deep-scan')
    app.register_blueprint(forensic_analysis_bp, url_prefix='/api/forensic')
    app.register_blueprint(exif_bp, url_prefix='/api/exif')
    app.register_blueprint(ela_bp)
    app.register_blueprint(clone_noise_bp, url_prefix='/api/clone-noise')
    app.register_blueprint(hex_viewer_bp, url_prefix='/api/hex-viewer')
    app.register_blueprint(logging_bp)
    app.register_blueprint(integrity_bp)
    app.register_blueprint(auto_integrity_bp, url_prefix='/api/auto-integrity')
    app.register_blueprint(enhanced_ela_bp)
    app.register_blueprint(auth_bp)
    
    # Health check endpoint
    @app.route('/api/health')
    def health_check():
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'service': 'Digital Forensics API'
        })
    
    # Serve frontend files
    @app.route('/')
    def serve_frontend():
        # Check if user is authenticated via cookie or header
        from flask import request
        auth_token = request.cookies.get('auth_token') or request.headers.get('Authorization')
        
        if auth_token:
            try:
                if auth_token.startswith('Bearer '):
                    auth_token = auth_token.split(' ')[1]
                
                from models.user import user_manager
                user = user_manager.verify_jwt_token(auth_token)
                if user:
                    # User is authenticated, serve dashboard
                    return send_from_directory('../frontend', 'dashboard.html')
            except Exception:
                pass
        
        # User not authenticated, serve login page
        return send_from_directory('../frontend', 'login.html')
    
    @app.route('/dashboard.html')
    def serve_dashboard():
        # Check if user is authenticated
        from flask import request
        auth_token = request.cookies.get('auth_token') or request.headers.get('Authorization')
        
        if auth_token:
            try:
                if auth_token.startswith('Bearer '):
                    auth_token = auth_token.split(' ')[1]
                
                from models.user import user_manager
                user = user_manager.verify_jwt_token(auth_token)
                if user:
                    # User is authenticated, serve dashboard
                    return send_from_directory('../frontend', 'dashboard.html')
            except Exception as e:
                app.logger.error(f'Dashboard auth error: {e}')
        
        # User not authenticated, redirect to login
        from flask import redirect
        return redirect('/')
    
    @app.route('/<path:path>')
    def serve_static(path):
        return send_from_directory('../frontend', path)
    
    # Authentication middleware for protected routes
    @app.before_request
    def check_auth():
        from models.user import user_manager
        from flask import request, jsonify
        
        # Skip auth check for public routes
        public_routes = [
            '/api/auth/login',
            '/api/auth/system-info',
            '/api/health',
            '/login.html',
            '/index.html',
            '/js/',
            '/css/',
            '/favicon.ico',
            '/images/'
        ]
        
        # Skip auth for static files and public routes
        if any(request.path.startswith(route) for route in public_routes):
            return
        
        # Skip auth for API endpoints that handle their own auth
        if request.path.startswith('/api/auth/'):
            return
        
        # Check for authentication token on API routes
        if request.path.startswith('/api/'):
            token = None
            
            # Get token from Authorization header
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
            
            # Get token from cookie (fallback)
            if not token:
                token = request.cookies.get('auth_token')
            
            if not token:
                return jsonify({'error': 'Authentication required'}), 401
            
            # Verify token
            current_user = user_manager.verify_jwt_token(token)
            if not current_user:
                return jsonify({'error': 'Invalid or expired token'}), 401
            
            # Add user to request context
            request.current_user = current_user
    
    return app

def setup_logging(app):
    """Setup application logging"""
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(name)s %(message)s',
        handlers=[
            logging.FileHandler('logs/app.log'),
            logging.StreamHandler()
        ]
    )
    
    app.logger.info('Digital Forensics Application started')

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)