"""
Enhanced ELA Analysis with Automatic Integrity Verification
===========================================================

This module provides ELA analysis with automatic SHA256 and MD5 hash generation
before and after analysis, with real-time integrity verification status.
"""

from flask import Blueprint, request, jsonify, current_app
import os
import tempfile
import uuid
from werkzeug.utils import secure_filename
import logging
import time

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensics.ela_analyzer import ErrorLevelAnalyzer
from utils.activity_logger import log_file_analysis, ActivityTypes
from utils.auto_integrity import integrity_protected_analysis, auto_integrity_manager
from models.user import require_auth

# Create Enhanced ELA API blueprint
enhanced_ela_bp = Blueprint('enhanced_ela', __name__, url_prefix='/api/enhanced-ela')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize ELA analyzer
ela_analyzer = ErrorLevelAnalyzer()

# Allowed file extensions
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'bmp', 'tiff', 'gif'}

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@enhanced_ela_bp.route('/analyze-with-integrity', methods=['POST'])
def analyze_with_integrity():
    """
    Perform ELA analysis with automatic integrity verification
    Generates SHA256 and MD5 hashes before and after analysis
    """
    try:
        # Check if file is provided
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({
                'error': 'Invalid file type. Supported: ' + ', '.join(ALLOWED_EXTENSIONS)
            }), 400
        
        # Get analysis parameters
        quality = int(request.form.get('quality', 90))
        brightness_threshold = float(request.form.get('brightness_threshold', 0.3))
        generate_heatmap = request.form.get('generate_heatmap', 'true').lower() == 'true'
        
        # Save file temporarily
        filename = secure_filename(file.filename)
        temp_path = os.path.join(tempfile.gettempdir(), f"ela_integrity_{uuid.uuid4().hex}_{filename}")
        file.save(temp_path)
        
        try:
            # Start integrity-protected analysis
            pre_analysis = auto_integrity_manager.start_analysis_with_integrity(
                temp_path, 'ELA_Analysis', f'Quality: {quality}, Threshold: {brightness_threshold}'
            )
            
            if 'error' in pre_analysis:
                return jsonify(pre_analysis), 400
            
            operation_id = pre_analysis['operation_id']
            
            # Perform ELA analysis
            start_time = time.time()
            
            # Calculate ELA
            ela_result = ela_analyzer.analyze_image(
                temp_path,
                quality=quality,
                brightness_threshold=brightness_threshold
            )
            
            if not ela_result['success']:
                # Clean up operation on failure
                if operation_id in auto_integrity_manager.active_operations:
                    del auto_integrity_manager.active_operations[operation_id]
                return jsonify(ela_result), 400
            
            processing_time = time.time() - start_time
            
            # Generate additional analysis outputs if requested
            analysis_outputs = {}
            
            if generate_heatmap and ela_result.get('ela_image_path'):
                try:
                    # Generate heatmap visualization
                    heatmap_result = ela_analyzer.generate_heatmap(
                        ela_result['ela_image_path'],
                        brightness_threshold
                    )
                    if heatmap_result['success']:
                        analysis_outputs['heatmap'] = heatmap_result
                except Exception as e:
                    logger.warning(f"Failed to generate heatmap: {e}")
            
            # Prepare analysis results
            enhanced_results = {
                'success': True,
                'analysis_type': 'ELA_Analysis',
                'file_info': {
                    'original_filename': filename,
                    'file_size': os.path.getsize(temp_path),
                    'temp_path': temp_path
                },
                'analysis_parameters': {
                    'quality': quality,
                    'brightness_threshold': brightness_threshold,
                    'generate_heatmap': generate_heatmap
                },
                'ela_results': ela_result,
                'additional_outputs': analysis_outputs,
                'performance': {
                    'processing_time_seconds': round(processing_time, 3)
                },
                'operation_id': operation_id
            }
            
            # Complete integrity verification
            verification_result = auto_integrity_manager.complete_analysis_with_integrity(
                operation_id, enhanced_results
            )
            
            if 'error' in verification_result:
                return jsonify(verification_result), 500
            
            # Get UI-friendly integrity status
            ui_integrity_status = auto_integrity_manager.get_integrity_status_for_ui(verification_result)
            
            # Log the analysis
            log_file_analysis(
                temp_path,
                ActivityTypes.ELA_ANALYSIS,
                {
                    'operation_id': operation_id,
                    'quality': quality,
                    'brightness_threshold': brightness_threshold,
                    'processing_time': processing_time,
                    'integrity_status': ui_integrity_status['status'],
                    'sha256_verified': ui_integrity_status['hashes']['sha256']['status'] == 'verified',
                    'md5_verified': ui_integrity_status['hashes']['md5']['status'] == 'verified'
                }
            )
            
            # Prepare final response
            response_data = {
                'success': True,
                'analysis_complete': True,
                'integrity_verification': ui_integrity_status,
                'analysis_results': enhanced_results,
                'verification_details': {
                    'operation_id': operation_id,
                    'pre_analysis_hashes': {
                        'sha256': pre_analysis['pre_analysis_hashes']['sha256'],
                        'md5': pre_analysis['pre_analysis_hashes']['md5']
                    },
                    'post_analysis_hashes': {
                        'sha256': ui_integrity_status['hashes']['sha256']['value'],
                        'md5': ui_integrity_status['hashes']['md5']['value']
                    },
                    'integrity_maintained': ui_integrity_status['status'] == 'VERIFIED'
                },
                'timestamp': verification_result['completion_timestamp']
            }
            
            return jsonify(response_data)
            
        finally:
            # Clean up temporary file
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception as e:
                logger.warning(f"Failed to clean up temporary file: {e}")
    
    except Exception as e:
        logger.error(f"Error in ELA analysis with integrity: {str(e)}")
        return jsonify({
            'error': 'Analysis failed',
            'details': str(e)
        }), 500

@enhanced_ela_bp.route('/batch-analyze-with-integrity', methods=['POST'])
@require_auth(min_role='Forensic Investigator')
def batch_analyze_with_integrity():
    """
    Perform batch ELA analysis with integrity verification on multiple files
    """
    try:
        files = request.files.getlist('files')
        if not files:
            return jsonify({'error': 'No files provided'}), 400
        
        # Get analysis parameters
        quality = int(request.form.get('quality', 90))
        brightness_threshold = float(request.form.get('brightness_threshold', 0.3))
        
        results = []
        total_files = len(files)
        
        for i, file in enumerate(files):
            if file.filename == '' or not allowed_file(file.filename):
                results.append({
                    'filename': file.filename,
                    'success': False,
                    'error': 'Invalid file type or empty filename'
                })
                continue
            
            try:
                # Save file temporarily
                filename = secure_filename(file.filename)
                temp_path = os.path.join(tempfile.gettempdir(), f"batch_ela_{uuid.uuid4().hex}_{filename}")
                file.save(temp_path)
                
                # Start integrity checking
                pre_analysis = auto_integrity_manager.start_analysis_with_integrity(
                    temp_path, 'Batch_ELA_Analysis', f'Batch {i+1}/{total_files}'
                )
                
                if 'error' in pre_analysis:
                    results.append({
                        'filename': filename,
                        'success': False,
                        'error': pre_analysis['error']
                    })
                    continue
                
                # Perform ELA analysis
                ela_result = ela_analyzer.analyze_image(
                    temp_path,
                    quality=quality,
                    brightness_threshold=brightness_threshold
                )
                
                # Complete integrity verification
                verification_result = auto_integrity_manager.complete_analysis_with_integrity(
                    pre_analysis['operation_id'], ela_result
                )
                
                ui_integrity_status = auto_integrity_manager.get_integrity_status_for_ui(verification_result)
                
                results.append({
                    'filename': filename,
                    'success': ela_result['success'],
                    'operation_id': pre_analysis['operation_id'],
                    'ela_results': ela_result if ela_result['success'] else None,
                    'integrity_verification': ui_integrity_status,
                    'error': ela_result.get('error') if not ela_result['success'] else None
                })
                
                # Clean up
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                    
            except Exception as e:
                results.append({
                    'filename': file.filename,
                    'success': False,
                    'error': f'Processing failed: {str(e)}'
                })
        
        # Summary statistics
        successful_analyses = sum(1 for r in results if r['success'])
        verified_integrity = sum(1 for r in results if r.get('integrity_verification', {}).get('status') == 'VERIFIED')
        
        return jsonify({
            'success': True,
            'batch_complete': True,
            'summary': {
                'total_files': total_files,
                'successful_analyses': successful_analyses,
                'verified_integrity': verified_integrity,
                'failed_analyses': total_files - successful_analyses
            },
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Error in batch ELA analysis: {str(e)}")
        return jsonify({
            'error': 'Batch analysis failed',
            'details': str(e)
        }), 500

@enhanced_ela_bp.route('/quick-integrity-preview', methods=['POST'])
@require_auth(min_role='Viewer')
def quick_integrity_preview():
    """
    Generate quick integrity preview (hashes only) without full analysis
    """
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Save file temporarily
        filename = secure_filename(file.filename)
        temp_path = os.path.join(tempfile.gettempdir(), f"preview_{uuid.uuid4().hex}_{filename}")
        file.save(temp_path)
        
        try:
            # Calculate hashes for preview
            from utils.integrity_checker import FileIntegrityChecker
            checker = FileIntegrityChecker()
            
            sha256_hash = checker.calculate_file_hash(temp_path, 'sha256')
            md5_hash = checker.calculate_file_hash(temp_path, 'md5')
            
            file_stat = os.stat(temp_path)
            
            return jsonify({
                'success': True,
                'preview': True,
                'file_info': {
                    'filename': filename,
                    'size': file_stat.st_size,
                    'path': temp_path
                },
                'integrity_hashes': {
                    'sha256': sha256_hash,
                    'md5': md5_hash
                },
                'message': 'Integrity preview generated. Use analyze-with-integrity for full analysis.'
            })
            
        finally:
            # Clean up temporary file
            if os.path.exists(temp_path):
                os.remove(temp_path)
        
    except Exception as e:
        logger.error(f"Error in integrity preview: {str(e)}")
        return jsonify({
            'error': 'Preview generation failed',
            'details': str(e)
        }), 500

@enhanced_ela_bp.route('/status/<operation_id>', methods=['GET'])
@require_auth(min_role='Viewer')
def get_operation_status(operation_id):
    """
    Get the status of a specific integrity-protected operation
    """
    try:
        if operation_id in auto_integrity_manager.active_operations:
            operation_data = auto_integrity_manager.active_operations[operation_id]
            return jsonify({
                'success': True,
                'operation_found': True,
                'status': 'in_progress',
                'operation_data': {
                    'operation_id': operation_id,
                    'file_path': operation_data['file_path'],
                    'analysis_type': operation_data['analysis_type'],
                    'start_time': operation_data['start_timestamp'],
                    'pre_analysis_hashes': operation_data['pre_analysis_hashes']
                }
            })
        else:
            return jsonify({
                'success': True,
                'operation_found': False,
                'status': 'completed_or_not_found',
                'message': 'Operation completed or does not exist'
            })
            
    except Exception as e:
        logger.error(f"Error getting operation status: {str(e)}")
        return jsonify({
            'error': 'Failed to get operation status',
            'details': str(e)
        }), 500