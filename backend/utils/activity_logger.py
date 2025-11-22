"""
Activity Logger for Digital Forensics Application
==============================================

Provides comprehensive logging capabilities for all forensic activities:
- Automatic activity tracking with timestamps
- Context-aware logging for different forensic operations
- Integration with database for persistent storage
- Performance monitoring and error tracking
"""

import time
import hashlib
import os
from datetime import datetime
from functools import wraps
from typing import Dict, Any, Optional, Callable
from flask import request, g
import logging

from database.forensics_db import ForensicsDatabase
from utils.integrity_checker import FileIntegrityChecker

class ActivityLogger:
    """Centralized activity logger for forensic operations"""
    
    def __init__(self, db_path: str = None):
        self.db = ForensicsDatabase(db_path)
        self.current_session_id = None
        self.current_investigator_id = None
        self.integrity_checker = FileIntegrityChecker()
        
        # Setup file logger as backup
        self.setup_file_logger()
    
    def setup_file_logger(self):
        """Setup file-based logging as backup"""
        logs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
        os.makedirs(logs_dir, exist_ok=True)
        
        log_file = os.path.join(logs_dir, 'forensics_activity.log')
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        self.file_logger = logging.getLogger('forensics_activity')
    
    def set_session_context(self, session_id: str, investigator_id: str = None):
        """Set current session and investigator context"""
        self.current_session_id = session_id
        self.current_investigator_id = investigator_id
    
    def log_activity(self, activity_type: str, description: str, **kwargs) -> int:
        """Log a forensic activity"""
        try:
            # Prepare activity data
            activity_data = {
                'session_id': kwargs.get('session_id') or self.current_session_id,
                'investigator_id': kwargs.get('investigator_id') or self.current_investigator_id,
                'activity_type': activity_type,
                'activity_category': kwargs.get('activity_category'),
                'description': description,
                'file_path': kwargs.get('file_path'),
                'file_name': kwargs.get('file_name'),
                'file_hash': kwargs.get('file_hash'),
                'file_size': kwargs.get('file_size'),
                'operation_details': kwargs.get('operation_details'),
                'result_status': kwargs.get('result_status', 'success'),
                'error_message': kwargs.get('error_message'),
                'ip_address': kwargs.get('ip_address'),
                'user_agent': kwargs.get('user_agent'),
                'duration_ms': kwargs.get('duration_ms')
            }
            
            # Log to database
            activity_id = self.db.log_activity(activity_data)
            
            # Also log to file as backup
            log_message = f"[{activity_type}] {description}"
            if activity_data.get('file_name'):
                log_message += f" - File: {activity_data['file_name']}"
            if activity_data.get('result_status') != 'success':
                log_message += f" - Status: {activity_data['result_status']}"
            
            self.file_logger.info(log_message)
            
            return activity_id
            
        except Exception as e:
            self.file_logger.error(f"Failed to log activity: {str(e)}")
            return -1
    
    def log_file_analysis(self, file_path: str, analysis_type: str, 
                         results: Dict[str, Any], duration_ms: int = None, **kwargs) -> int:
        """Log file analysis activity"""
        file_name = os.path.basename(file_path) if file_path else None
        file_size = None
        file_hash = None
        
        # Get file info if file exists
        if file_path and os.path.exists(file_path):
            try:
                file_size = os.path.getsize(file_path)
                # Calculate hash for important files
                if file_size < 100 * 1024 * 1024:  # Only for files < 100MB
                    with open(file_path, 'rb') as f:
                        file_hash = hashlib.md5(f.read()).hexdigest()
            except Exception:
                pass
        
        return self.log_activity(
            activity_type=analysis_type,
            activity_category='file_analysis',
            description=f"{analysis_type} analysis completed on {file_name or 'unknown file'}",
            file_path=file_path,
            file_name=file_name,
            file_hash=file_hash,
            file_size=file_size,
            operation_details=results,
            duration_ms=duration_ms,
            **kwargs
        )
    
    def log_file_recovery(self, recovery_details: Dict[str, Any], **kwargs) -> int:
        """Log file recovery operation"""
        return self.log_activity(
            activity_type='file_recovery',
            activity_category='data_recovery',
            description=f"File recovery operation: {recovery_details.get('method', 'unknown method')}",
            operation_details=recovery_details,
            **kwargs
        )
    
    def log_evidence_acquisition(self, evidence_path: str, acquisition_method: str, 
                               integrity_verified: bool = False, **kwargs) -> int:
        """Log evidence acquisition"""
        return self.log_activity(
            activity_type='evidence_acquisition',
            activity_category='evidence_handling',
            description=f"Evidence acquired using {acquisition_method}",
            file_path=evidence_path,
            file_name=os.path.basename(evidence_path) if evidence_path else None,
            operation_details={
                'acquisition_method': acquisition_method,
                'integrity_verified': integrity_verified
            },
            **kwargs
        )
    
    def log_system_event(self, event_type: str, event_details: Dict[str, Any], **kwargs) -> int:
        """Log system events"""
        return self.log_activity(
            activity_type='system_event',
            activity_category='system',
            description=f"System event: {event_type}",
            operation_details=event_details,
            **kwargs
        )
    
    def log_user_action(self, action: str, details: Dict[str, Any] = None, **kwargs) -> int:
        """Log user actions"""
        return self.log_activity(
            activity_type='user_action',
            activity_category='user_interface',
            description=f"User action: {action}",
            operation_details=details or {},
            **kwargs
        )
    
    def log_error(self, error_type: str, error_message: str, error_details: Dict[str, Any] = None, **kwargs) -> int:
        """Log errors and exceptions"""
        return self.log_activity(
            activity_type='error',
            activity_category='system',
            description=f"Error occurred: {error_type}",
            result_status='error',
            error_message=error_message,
            operation_details=error_details or {},
            **kwargs
        )
    
    def get_request_context(self) -> Dict[str, Any]:
        """Get current request context for logging"""
        context = {}
        
        try:
            if request:
                context['ip_address'] = request.remote_addr
                context['user_agent'] = request.headers.get('User-Agent', '')
                # Get session info if available
                if hasattr(g, 'session_id'):
                    context['session_id'] = g.session_id
                if hasattr(g, 'investigator_id'):
                    context['investigator_id'] = g.investigator_id
        except RuntimeError:
            # Outside request context
            pass
        
        return context
    
    def log_with_integrity_check(self, file_path: str, activity_type: str, description: str, **kwargs) -> int:
        """Log activity with automatic integrity checking"""
        try:
            # Create pre-operation integrity record
            pre_integrity = self.integrity_checker.create_integrity_record(
                file_path, f"pre_{activity_type}", ['sha256', 'md5']
            )
            
            # Log the activity with integrity info
            log_id = self.log_activity(
                activity_type=activity_type,
                description=description,
                pre_integrity_hash=pre_integrity.get('hashes', {}).get('sha256'),
                file_path=file_path,
                **kwargs
            )
            
            return log_id
            
        except Exception as e:
            self.file_logger.error(f"Error logging with integrity check: {str(e)}")
            # Fallback to regular logging
            return self.log_activity(activity_type, description, **kwargs)
    
    def create_pre_analysis_integrity(self, file_path: str, analysis_type: str) -> Dict[str, Any]:
        """Create integrity record before analysis begins"""
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
            context = f"pre_{analysis_type}_analysis"
            
            # Create comprehensive integrity record
            integrity_record = self.integrity_checker.create_integrity_record(
                file_path, context, ['sha256', 'md5', 'sha1']
            )
            
            # Log the integrity check
            self.log_activity(
                activity_type='integrity_check',
                activity_category='security',
                description=f"Pre-analysis integrity check for {analysis_type}",
                file_path=file_path,
                context=context,
                integrity_record=integrity_record
            )
            
            return integrity_record
            
        except Exception as e:
            self.file_logger.error(f"Error creating pre-analysis integrity: {str(e)}")
            return {}
    
    def verify_post_analysis_integrity(self, file_path: str, original_integrity: Dict, analysis_type: str) -> Dict[str, Any]:
        """Verify file integrity after analysis completion"""
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            
            if not original_integrity:
                self.file_logger.warning("No original integrity record provided for verification")
                return {"verification_status": "no_original_record", "overall_integrity": False}
            
            # Perform integrity verification
            verification_result = self.integrity_checker.verify_integrity(
                original_integrity, file_path
            )
            
            # Log the verification result
            self.log_activity(
                activity_type='integrity_verification',
                activity_category='security',
                description=f"Post-analysis integrity verification for {analysis_type}",
                file_path=file_path,
                original_context=original_integrity.get('context'),
                verification_result=verification_result,
                integrity_maintained=verification_result.get('overall_integrity', False)
            )
            
            # Log warning if integrity failed
            if not verification_result.get('overall_integrity', False):
                self.log_error(
                    error_type='integrity_violation',
                    error_message=f"File integrity compromised during {analysis_type} analysis",
                    error_details={
                        'file_path': file_path,
                        'analysis_type': analysis_type,
                        'verification_status': verification_result.get('verification_status'),
                        'matched_hashes': verification_result.get('matched_hashes', 0),
                        'total_hashes': verification_result.get('total_hashes', 0)
                    }
                )
            
            return verification_result
            
        except Exception as e:
            self.file_logger.error(f"Error verifying post-analysis integrity: {str(e)}")
            return {"verification_status": "error", "overall_integrity": False, "error": str(e)}
    
    def create_integrity_chain(self, file_path: str, contexts: list) -> Dict[str, Any]:
        """Create an integrity chain for tracking file across multiple operations"""
        try:
            chain = self.integrity_checker.create_verification_chain(file_path, contexts)
            
            # Log the chain creation
            self.log_activity(
                activity_type='integrity_chain_created',
                activity_category='security',
                description=f"Integrity chain created with {len(contexts)} contexts",
                file_path=file_path,
                contexts=contexts,
                chain_length=len(chain)
            )
            
            return {
                'success': True,
                'chain': chain,
                'contexts': contexts,
                'file_path': file_path
            }
            
        except Exception as e:
            self.file_logger.error(f"Error creating integrity chain: {str(e)}")
            return {'success': False, 'error': str(e)}

# Decorator for automatic activity logging
def log_activity(activity_type: str, description: str = None, 
                category: str = None, include_result: bool = True):
    """Decorator to automatically log function activities"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            logger = ActivityLogger()
            
            # Get request context
            context = logger.get_request_context()
            
            # Determine description
            desc = description or f"{func.__name__} executed"
            
            try:
                # Execute function
                result = func(*args, **kwargs)
                
                # Calculate duration
                duration_ms = int((time.time() - start_time) * 1000)
                
                # Prepare logging data
                log_data = {
                    'activity_category': category,
                    'duration_ms': duration_ms,
                    'result_status': 'success'
                }
                
                # Include result if requested and not too large
                if include_result and result:
                    if isinstance(result, dict) and len(str(result)) < 5000:
                        log_data['operation_details'] = result
                    elif hasattr(result, '__dict__') and len(str(result.__dict__)) < 5000:
                        log_data['operation_details'] = result.__dict__
                
                # Add request context
                log_data.update(context)
                
                # Log the activity
                logger.log_activity(activity_type, desc, **log_data)
                
                return result
                
            except Exception as e:
                # Calculate duration even for failed operations
                duration_ms = int((time.time() - start_time) * 1000)
                
                # Log the error
                log_data = {
                    'activity_category': category or 'error',
                    'duration_ms': duration_ms,
                    'result_status': 'error',
                    'error_message': str(e)
                }
                log_data.update(context)
                
                logger.log_activity(activity_type, f"{desc} - FAILED", **log_data)
                
                # Re-raise the exception
                raise
        
        return wrapper
    return decorator

# Activity type constants for consistency
class ActivityTypes:
    # File analysis
    ELA_ANALYSIS = 'ela_analysis'
    EXIF_ANALYSIS = 'exif_analysis'
    HEX_ANALYSIS = 'hex_analysis'
    CLONE_DETECTION = 'clone_detection'
    NOISE_ANALYSIS = 'noise_analysis'
    FILE_CARVING = 'file_carving'
    
    # Data operations
    FILE_UPLOAD = 'file_upload'
    FILE_DOWNLOAD = 'file_download'
    FILE_RECOVERY = 'file_recovery'
    DATA_EXPORT = 'data_export'
    
    # Evidence handling
    EVIDENCE_ACQUISITION = 'evidence_acquisition'
    EVIDENCE_VERIFICATION = 'evidence_verification'
    CHAIN_OF_CUSTODY = 'chain_of_custody'
    
    # System operations
    SESSION_START = 'session_start'
    SESSION_END = 'session_end'
    USER_LOGIN = 'user_login'
    USER_LOGOUT = 'user_logout'
    SYSTEM_ERROR = 'system_error'
    
    # Investigation activities
    CASE_CREATED = 'case_created'
    NOTE_ADDED = 'note_added'
    REPORT_GENERATED = 'report_generated'
    ANALYSIS_COMPLETED = 'analysis_completed'

# Global logger instance
forensics_logger = ActivityLogger()

# Convenience functions
def log_file_analysis(file_path: str, analysis_type: str, results: Dict[str, Any], **kwargs):
    """Convenience function for logging file analysis"""
    return forensics_logger.log_file_analysis(file_path, analysis_type, results, **kwargs)

def log_user_action(action: str, details: Dict[str, Any] = None, **kwargs):
    """Convenience function for logging user actions"""
    return forensics_logger.log_user_action(action, details, **kwargs)

def log_system_event(event_type: str, details: Dict[str, Any], **kwargs):
    """Convenience function for logging system events"""
    return forensics_logger.log_system_event(event_type, details, **kwargs)

def log_error(error_type: str, error_message: str, details: Dict[str, Any] = None, **kwargs):
    """Convenience function for logging errors"""
    return forensics_logger.log_error(error_type, error_message, details, **kwargs)

def set_session_context(session_id: str, investigator_id: str = None):
    """Set global session context"""
    return forensics_logger.set_session_context(session_id, investigator_id)

def log_with_integrity_check(file_path: str, activity_type: str, description: str, **kwargs):
    """Log activity with automatic integrity checking"""
    return forensics_logger.log_with_integrity_check(file_path, activity_type, description, **kwargs)

def create_pre_analysis_integrity(file_path: str, analysis_type: str):
    """Create integrity record before analysis"""
    return forensics_logger.create_pre_analysis_integrity(file_path, analysis_type)

def verify_post_analysis_integrity(file_path: str, original_integrity: Dict, analysis_type: str):
    """Verify integrity after analysis"""
    return forensics_logger.verify_post_analysis_integrity(file_path, original_integrity, analysis_type)

def with_integrity_verification(analysis_type: str, file_param_name: str = 'file_path'):
    """Decorator that automatically adds integrity checking to analysis functions"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extract file path from function parameters
            file_path = None
            
            # Try to get file path from kwargs first
            if file_param_name in kwargs:
                file_path = kwargs[file_param_name]
            
            # If not in kwargs, try to get from args based on function signature
            if not file_path and args:
                import inspect
                sig = inspect.signature(func)
                param_names = list(sig.parameters.keys())
                
                if file_param_name in param_names:
                    param_index = param_names.index(file_param_name)
                    if param_index < len(args):
                        file_path = args[param_index]
            
            # Create pre-analysis integrity if file path found
            pre_integrity = None
            if file_path and os.path.exists(file_path):
                pre_integrity = create_pre_analysis_integrity(file_path, analysis_type)
            
            try:
                # Execute the analysis function
                result = func(*args, **kwargs)
                
                # Verify post-analysis integrity if we have pre-integrity
                if file_path and pre_integrity and os.path.exists(file_path):
                    post_verification = verify_post_analysis_integrity(file_path, pre_integrity, analysis_type)
                    
                    # Add integrity information to result if it's a dict
                    if isinstance(result, dict):
                        result['integrity_verification'] = {
                            'pre_analysis_integrity': pre_integrity,
                            'post_analysis_verification': post_verification,
                            'integrity_maintained': post_verification.get('overall_integrity', False)
                        }
                
                return result
                
            except Exception as e:
                # Log error with integrity context if available
                if file_path and pre_integrity:
                    log_error(
                        'analysis_error_with_integrity',
                        f"Analysis failed for {analysis_type}: {str(e)}",
                        {
                            'file_path': file_path,
                            'analysis_type': analysis_type,
                            'pre_analysis_integrity': pre_integrity
                        }
                    )
                raise
        
        return wrapper
    return decorator
    forensics_logger.set_session_context(session_id, investigator_id)