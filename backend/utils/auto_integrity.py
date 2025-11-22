"""
Automatic Integrity Checking Integration
======================================

This module provides seamless integration of hash generation and verification
with existing analysis tools. It automatically calculates SHA256 and MD5 hashes
before and after analysis operations and displays verification status.
"""

import os
import hashlib
import json
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
from utils.integrity_checker import FileIntegrityChecker
from utils.activity_logger import log_user_action

class AutoIntegrityManager:
    """Manages automatic integrity checking for all analysis operations"""
    
    def __init__(self):
        self.integrity_checker = FileIntegrityChecker()
        self.active_operations = {}  # Track ongoing operations
        
    def start_analysis_with_integrity(self, file_path: str, analysis_type: str, 
                                    user_context: str = None) -> Dict[str, Any]:
        """
        Start analysis operation with automatic pre-analysis integrity check
        
        Args:
            file_path: Path to file being analyzed
            analysis_type: Type of analysis (ela, exif, hex, etc.)
            user_context: Additional context information
            
        Returns:
            Dict containing pre-analysis integrity data and operation ID
        """
        if not os.path.exists(file_path):
            return {"error": "File not found", "file_path": file_path}
        
        # Generate unique operation ID
        operation_id = f"{analysis_type}_{int(datetime.now().timestamp() * 1000)}"
        
        # Calculate pre-analysis hashes (SHA256 and MD5 as required)
        pre_hashes = {
            'sha256': self.integrity_checker.calculate_file_hash(file_path, 'sha256'),
            'md5': self.integrity_checker.calculate_file_hash(file_path, 'md5')
        }
        
        # Get file metadata
        file_stat = os.stat(file_path)
        file_size = file_stat.st_size
        modification_time = datetime.fromtimestamp(file_stat.st_mtime)
        
        # Create comprehensive pre-analysis record
        pre_analysis_record = {
            "operation_id": operation_id,
            "file_path": file_path,
            "analysis_type": analysis_type,
            "pre_analysis_hashes": pre_hashes,
            "file_size": file_size,
            "modification_time": modification_time.isoformat(),
            "start_timestamp": datetime.now().isoformat(),
            "user_context": user_context or "automatic_analysis",
            "status": "pre_analysis_complete"
        }
        
        # Store operation data for later verification
        self.active_operations[operation_id] = pre_analysis_record
        
        # Log the pre-analysis integrity check
        log_user_action(
            'pre_analysis_integrity_check',
            {
                'operation_id': operation_id,
                'file_path': file_path,
                'analysis_type': analysis_type,
                'sha256': pre_hashes['sha256'],
                'md5': pre_hashes['md5'],
                'file_size': file_size
            }
        )
        
        return pre_analysis_record
    
    def complete_analysis_with_integrity(self, operation_id: str, 
                                       analysis_results: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Complete analysis operation with post-analysis integrity verification
        
        Args:
            operation_id: ID from start_analysis_with_integrity
            analysis_results: Results from the analysis operation
            
        Returns:
            Dict containing complete integrity verification results
        """
        if operation_id not in self.active_operations:
            return {"error": "Operation ID not found", "operation_id": operation_id}
        
        pre_record = self.active_operations[operation_id]
        file_path = pre_record["file_path"]
        
        if not os.path.exists(file_path):
            return {"error": "File no longer exists", "file_path": file_path}
        
        # Calculate post-analysis hashes
        post_hashes = {
            'sha256': self.integrity_checker.calculate_file_hash(file_path, 'sha256'),
            'md5': self.integrity_checker.calculate_file_hash(file_path, 'md5')
        }
        
        # Get current file metadata
        file_stat = os.stat(file_path)
        current_size = file_stat.st_size
        current_modification_time = datetime.fromtimestamp(file_stat.st_mtime)
        
        # Compare hashes and detect changes
        sha256_match = pre_record["pre_analysis_hashes"]["sha256"] == post_hashes["sha256"]
        md5_match = pre_record["pre_analysis_hashes"]["md5"] == post_hashes["md5"]
        size_match = pre_record["file_size"] == current_size
        
        # Determine overall integrity status
        integrity_maintained = sha256_match and md5_match and size_match
        
        # Create comprehensive verification result
        verification_result = {
            "operation_id": operation_id,
            "file_path": file_path,
            "analysis_type": pre_record["analysis_type"],
            "completion_timestamp": datetime.now().isoformat(),
            "integrity_verification": {
                "overall_status": "VERIFIED" if integrity_maintained else "COMPROMISED",
                "integrity_maintained": integrity_maintained,
                "hash_comparison": {
                    "sha256": {
                        "pre_analysis": pre_record["pre_analysis_hashes"]["sha256"],
                        "post_analysis": post_hashes["sha256"],
                        "matches": sha256_match
                    },
                    "md5": {
                        "pre_analysis": pre_record["pre_analysis_hashes"]["md5"],
                        "post_analysis": post_hashes["md5"],
                        "matches": md5_match
                    }
                },
                "metadata_comparison": {
                    "file_size": {
                        "pre_analysis": pre_record["file_size"],
                        "post_analysis": current_size,
                        "matches": size_match
                    },
                    "modification_time": {
                        "pre_analysis": pre_record["modification_time"],
                        "post_analysis": current_modification_time.isoformat(),
                        "changed": pre_record["modification_time"] != current_modification_time.isoformat()
                    }
                }
            },
            "analysis_results": analysis_results or {}
        }
        
        # Log the verification result
        log_user_action(
            'post_analysis_integrity_verification',
            {
                'operation_id': operation_id,
                'file_path': file_path,
                'analysis_type': pre_record["analysis_type"],
                'integrity_status': verification_result["integrity_verification"]["overall_status"],
                'sha256_matches': sha256_match,
                'md5_matches': md5_match,
                'size_matches': size_match
            }
        )
        
        # Clean up operation data
        del self.active_operations[operation_id]
        
        return verification_result
    
    def get_integrity_status_for_ui(self, verification_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format integrity verification result for UI display
        
        Args:
            verification_result: Result from complete_analysis_with_integrity
            
        Returns:
            Dict formatted for UI consumption
        """
        if "integrity_verification" not in verification_result:
            return {"error": "Invalid verification result"}
        
        integrity_data = verification_result["integrity_verification"]
        
        # Create UI-friendly status
        ui_status = {
            "status": integrity_data["overall_status"],
            "badge_class": "success" if integrity_data["integrity_maintained"] else "danger",
            "icon": "check-circle" if integrity_data["integrity_maintained"] else "exclamation-triangle",
            "message": "File integrity verified - no changes detected" if integrity_data["integrity_maintained"] 
                      else "WARNING: File integrity compromised - changes detected",
            "hashes": {
                "sha256": {
                    "value": integrity_data["hash_comparison"]["sha256"]["post_analysis"],
                    "status": "verified" if integrity_data["hash_comparison"]["sha256"]["matches"] else "changed",
                    "original": integrity_data["hash_comparison"]["sha256"]["pre_analysis"]
                },
                "md5": {
                    "value": integrity_data["hash_comparison"]["md5"]["post_analysis"],
                    "status": "verified" if integrity_data["hash_comparison"]["md5"]["matches"] else "changed",
                    "original": integrity_data["hash_comparison"]["md5"]["pre_analysis"]
                }
            },
            "details": {
                "file_path": verification_result["file_path"],
                "analysis_type": verification_result["analysis_type"],
                "operation_id": verification_result["operation_id"],
                "timestamp": verification_result["completion_timestamp"]
            }
        }
        
        return ui_status

# Global instance for use across the application
auto_integrity_manager = AutoIntegrityManager()

def integrity_protected_analysis(analysis_type: str, user_context: str = None):
    """
    Decorator for automatic integrity checking around analysis functions
    
    Usage:
        @integrity_protected_analysis("ela_analysis")
        def perform_ela_analysis(file_path, quality=90):
            # Your analysis code here
            return analysis_results
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Extract file_path from arguments
            file_path = None
            if args:
                file_path = args[0]  # Assume first argument is file_path
            elif 'file_path' in kwargs:
                file_path = kwargs['file_path']
            
            if not file_path:
                # No file path found, run function normally
                return func(*args, **kwargs)
            
            # Start integrity checking
            pre_analysis = auto_integrity_manager.start_analysis_with_integrity(
                file_path, analysis_type, user_context
            )
            
            if "error" in pre_analysis:
                return {"error": pre_analysis["error"], "integrity_check": "failed"}
            
            try:
                # Execute the original analysis function
                analysis_results = func(*args, **kwargs)
                
                # Complete integrity verification
                verification_result = auto_integrity_manager.complete_analysis_with_integrity(
                    pre_analysis["operation_id"], analysis_results
                )
                
                # Add integrity status to results
                if isinstance(analysis_results, dict):
                    analysis_results["integrity_verification"] = auto_integrity_manager.get_integrity_status_for_ui(verification_result)
                
                return analysis_results
                
            except Exception as e:
                # Clean up on error
                if pre_analysis["operation_id"] in auto_integrity_manager.active_operations:
                    del auto_integrity_manager.active_operations[pre_analysis["operation_id"]]
                raise e
        
        return wrapper
    return decorator