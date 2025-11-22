"""
Configuration settings for the Digital Forensics Application
"""
import os
from datetime import timedelta

class Config:
    # Basic Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database configuration
    DATABASE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'database', 'forensics.db')
    
    # File upload settings
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB max file size
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
    RECOVERED_FILES_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'recovered_files')
    FORENSIC_RESULTS_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'forensic_results')
    
    # Allowed file extensions for evidence
    ALLOWED_EXTENSIONS = {
        'image': {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff'},
        'document': {'pdf', 'doc', 'docx', 'txt', 'rtf', 'odt'},
        'archive': {'zip', 'rar', '7z', 'tar', 'gz'},
        'disk': {'img', 'dd', 'raw', 'iso', 'vhd', 'vmdk', 'e01', 'ex01', 'ad1'},
        'other': {'log', 'csv', 'json', 'xml'}
    }
    
    # Deep Scan Configuration
    DEEP_SCAN_SECTOR_SIZE = 512
    DEEP_SCAN_BUFFER_SIZE = 1024 * 1024  # 1MB read buffer
    DEEP_SCAN_MAX_FILE_SIZE = 200 * 1024 * 1024  # 200MB max recovered file
    DEEP_SCAN_MAX_SESSIONS = 10  # Maximum concurrent scan sessions
    DEEP_SCAN_SESSION_TIMEOUT = 24 * 3600  # 24 hours
    
    # Supported forensic image formats for deep scanning
    FORENSIC_IMAGE_FORMATS = {
        '.img': 'Raw disk image',
        '.dd': 'Raw disk dump (dd format)',
        '.raw': 'Raw disk image',
        '.e01': 'Expert Witness Format (EnCase)',
        '.ex01': 'Expert Witness Format (Extended)',
        '.ad1': 'AccessData Forensic Image',
        '.aff': 'Advanced Forensic Format',
        '.afd': 'AFD disk image'
    }
    
    # Logging configuration
    LOG_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
    LOG_LEVEL = 'INFO'
    
    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    
    # Security settings
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None

class DevelopmentConfig(Config):
    DEBUG = True
    
class ProductionConfig(Config):
    DEBUG = False
    SECRET_KEY = os.environ.get('SECRET_KEY')
    
class TestingConfig(Config):
    TESTING = True
    DATABASE_PATH = ':memory:'