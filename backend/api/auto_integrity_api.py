"""
Enhanced Integrity API with Automatic Verification
================================================

Provides REST endpoints for automatic integrity checking integration
with analysis operations, including real-time status updates.
"""

from flask import Blueprint, request, jsonify, current_app
import os
import json
from utils.auto_integrity import auto_integrity_manager
from utils.activity_logger import log_user_action
from models.user import require_auth

auto_integrity_bp = Blueprint('auto_integrity', __name__)

@auto_integrity_bp.route('/start-protected-analysis', methods=['POST'])
@require_auth(min_role='Forensic Investigator')
def start_protected_analysis():
    """Start analysis with automatic pre-analysis integrity check"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data or 'file_path' not in data or 'analysis_type' not in data:
            return jsonify({
                'error': 'Missing required fields: file_path and analysis_type'
            }), 400
        
        file_path = data['file_path']
        analysis_type = data['analysis_type']
        user_context = data.get('user_context', 'api_request')
        
        # Start integrity-protected analysis
        result = auto_integrity_manager.start_analysis_with_integrity(
            file_path, analysis_type, user_context
        )
        
        if 'error' in result:
            return jsonify(result), 400
        
        return jsonify({
            'success': True,
            'operation_id': result['operation_id'],
            'pre_analysis_integrity': {
                'sha256': result['pre_analysis_hashes']['sha256'],
                'md5': result['pre_analysis_hashes']['md5'],
                'file_size': result['file_size'],
                'timestamp': result['start_timestamp']
            },
            'message': 'Pre-analysis integrity check completed successfully'
        })
        
    except Exception as e:
        current_app.logger.error(f"Error in start_protected_analysis: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@auto_integrity_bp.route('/complete-protected-analysis', methods=['POST'])
@require_auth(min_role='Forensic Investigator')
def complete_protected_analysis():
    """Complete analysis with post-analysis integrity verification"""
    try:
        data = request.get_json()
        
        if not data or 'operation_id' not in data:
            return jsonify({'error': 'Missing required field: operation_id'}), 400
        
        operation_id = data['operation_id']
        analysis_results = data.get('analysis_results', {})
        
        # Complete integrity verification
        result = auto_integrity_manager.complete_analysis_with_integrity(
            operation_id, analysis_results
        )
        
        if 'error' in result:
            return jsonify(result), 400
        
        # Format for UI display
        ui_status = auto_integrity_manager.get_integrity_status_for_ui(result)
        
        return jsonify({
            'success': True,
            'verification_complete': True,
            'integrity_status': ui_status,
            'full_verification': result['integrity_verification'],
            'operation_details': {
                'operation_id': operation_id,
                'file_path': result['file_path'],
                'analysis_type': result['analysis_type'],
                'completion_time': result['completion_timestamp']
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"Error in complete_protected_analysis: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@auto_integrity_bp.route('/quick-integrity-check', methods=['POST'])
@require_auth(min_role='Forensic Investigator')
def quick_integrity_check():
    """Perform quick SHA256 and MD5 hash generation for UI display"""
    try:
        data = request.get_json()
        
        if not data or 'file_path' not in data:
            return jsonify({'error': 'Missing required field: file_path'}), 400
        
        file_path = data['file_path']
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        
        # Calculate hashes
        from utils.integrity_checker import FileIntegrityChecker
        checker = FileIntegrityChecker()
        
        sha256_hash = checker.calculate_file_hash(file_path, 'sha256')
        md5_hash = checker.calculate_file_hash(file_path, 'md5')
        
        # Get file metadata
        file_stat = os.stat(file_path)
        
        return jsonify({
            'success': True,
            'file_path': file_path,
            'hashes': {
                'sha256': sha256_hash,
                'md5': md5_hash
            },
            'metadata': {
                'size': file_stat.st_size,
                'modified': file_stat.st_mtime
            },
            'timestamp': auto_integrity_manager.integrity_checker._get_current_timestamp()
        })
        
    except Exception as e:
        current_app.logger.error(f"Error in quick_integrity_check: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@auto_integrity_bp.route('/active-operations', methods=['GET'])
@require_auth(min_role='Viewer')
def get_active_operations():
    """Get list of currently active integrity-protected operations"""
    try:
        operations = []
        
        for op_id, op_data in auto_integrity_manager.active_operations.items():
            operations.append({
                'operation_id': op_id,
                'file_path': op_data['file_path'],
                'analysis_type': op_data['analysis_type'],
                'start_time': op_data['start_timestamp'],
                'status': op_data['status'],
                'hashes': {
                    'sha256': op_data['pre_analysis_hashes']['sha256'],
                    'md5': op_data['pre_analysis_hashes']['md5']
                }
            })
        
        return jsonify({
            'success': True,
            'active_operations': operations,
            'count': len(operations)
        })
        
    except Exception as e:
        current_app.logger.error(f"Error in get_active_operations: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@auto_integrity_bp.route('/verify-file-integrity', methods=['POST'])
@require_auth(min_role='Forensic Investigator')
def verify_file_integrity():
    """Verify file integrity against known good hashes"""
    try:
        data = request.get_json()
        
        required_fields = ['file_path', 'expected_sha256', 'expected_md5']
        if not data or not all(field in data for field in required_fields):
            return jsonify({
                'error': f'Missing required fields: {", ".join(required_fields)}'
            }), 400
        
        file_path = data['file_path']
        expected_sha256 = data['expected_sha256']
        expected_md5 = data['expected_md5']
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        
        # Calculate current hashes
        from utils.integrity_checker import FileIntegrityChecker
        checker = FileIntegrityChecker()
        
        current_sha256 = checker.calculate_file_hash(file_path, 'sha256')
        current_md5 = checker.calculate_file_hash(file_path, 'md5')
        
        # Compare hashes
        sha256_match = current_sha256.lower() == expected_sha256.lower()
        md5_match = current_md5.lower() == expected_md5.lower()
        integrity_verified = sha256_match and md5_match
        
        # Log verification attempt
        log_user_action('file_integrity_verification', {
            'file_path': file_path,
            'integrity_verified': integrity_verified,
            'sha256_match': sha256_match,
            'md5_match': md5_match
        })
        
        return jsonify({
            'success': True,
            'file_path': file_path,
            'integrity_verified': integrity_verified,
            'verification_details': {
                'sha256': {
                    'expected': expected_sha256,
                    'current': current_sha256,
                    'matches': sha256_match
                },
                'md5': {
                    'expected': expected_md5,
                    'current': current_md5,
                    'matches': md5_match
                }
            },
            'ui_status': {
                'status': 'VERIFIED' if integrity_verified else 'COMPROMISED',
                'badge_class': 'success' if integrity_verified else 'danger',
                'icon': 'check-circle' if integrity_verified else 'exclamation-triangle',
                'message': 'File integrity verified' if integrity_verified else 'File integrity compromised'
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"Error in verify_file_integrity: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@auto_integrity_bp.route('/batch-integrity-status', methods=['POST'])
@require_auth(min_role='Viewer')
def batch_integrity_status():
    """Get integrity status for multiple files"""
    try:
        data = request.get_json()
        
        if not data or 'files' not in data:
            return jsonify({'error': 'Missing required field: files'}), 400
        
        files = data['files']
        if not isinstance(files, list):
            return jsonify({'error': 'Files must be an array'}), 400
        
        results = []
        from utils.integrity_checker import FileIntegrityChecker
        checker = FileIntegrityChecker()
        
        for file_info in files:
            if not isinstance(file_info, dict) or 'file_path' not in file_info:
                results.append({'error': 'Invalid file info format'})
                continue
            
            file_path = file_info['file_path']
            
            if not os.path.exists(file_path):
                results.append({
                    'file_path': file_path,
                    'error': 'File not found'
                })
                continue
            
            try:
                # Calculate hashes
                sha256_hash = checker.calculate_file_hash(file_path, 'sha256')
                md5_hash = checker.calculate_file_hash(file_path, 'md5')
                
                file_stat = os.stat(file_path)
                
                result = {
                    'file_path': file_path,
                    'success': True,
                    'hashes': {
                        'sha256': sha256_hash,
                        'md5': md5_hash
                    },
                    'metadata': {
                        'size': file_stat.st_size,
                        'modified': file_stat.st_mtime
                    }
                }
                
                # If expected hashes provided, verify them
                if 'expected_sha256' in file_info and 'expected_md5' in file_info:
                    sha256_match = sha256_hash.lower() == file_info['expected_sha256'].lower()
                    md5_match = md5_hash.lower() == file_info['expected_md5'].lower()
                    integrity_verified = sha256_match and md5_match
                    
                    result['verification'] = {
                        'integrity_verified': integrity_verified,
                        'sha256_match': sha256_match,
                        'md5_match': md5_match,
                        'status': 'VERIFIED' if integrity_verified else 'COMPROMISED'
                    }
                
                results.append(result)
                
            except Exception as e:
                results.append({
                    'file_path': file_path,
                    'error': f'Hash calculation failed: {str(e)}'
                })
        
        return jsonify({
            'success': True,
            'results': results,
            'processed_count': len(results)
        })
        
    except Exception as e:
        current_app.logger.error(f"Error in batch_integrity_status: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500