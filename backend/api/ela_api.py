"""
Error Level Analysis (ELA) API Endpoints
=======================================

Flask API endpoints for performing Error Level Analysis on images
to detect tampering through compression artifact analysis.
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

# Create ELA API blueprint
ela_bp = Blueprint('ela', __name__, url_prefix='/api/ela')

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

def save_temp_file(file):
    """Save uploaded file to temporary location"""
    try:
        # Generate secure filename
        filename = secure_filename(file.filename)
        if not filename:
            filename = f"temp_image_{uuid.uuid4().hex[:8]}.jpg"
        
        # Create temporary file path
        temp_dir = tempfile.gettempdir()
        temp_path = os.path.join(temp_dir, f"ela_{uuid.uuid4().hex}_{filename}")
        
        # Save file
        file.save(temp_path)
        
        return temp_path
        
    except Exception as e:
        logger.error(f"Failed to save temporary file: {str(e)}")
        raise

def cleanup_temp_file(filepath):
    """Clean up temporary file"""
    try:
        if os.path.exists(filepath):
            os.unlink(filepath)
    except Exception as e:
        logger.warning(f"Failed to cleanup temporary file {filepath}: {str(e)}")

@ela_bp.route('/analyze', methods=['POST'])
def analyze_image():
    """
    Perform Error Level Analysis on uploaded image.
    
    Expected form data:
    - image: Image file
    - quality: JPEG quality level (optional, default: 95)
    
    Returns:
    - JSON with ELA analysis results
    """
    try:
        # Check if image was uploaded
        if 'image' not in request.files:
            return jsonify({'error': 'No image file provided'}), 400
        
        file = request.files['image']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed. Please upload JPG, PNG, BMP, TIFF, or GIF files.'}), 400
        
        # Get quality parameter
        quality = request.form.get('quality', 95)
        try:
            quality = int(quality)
            if quality < 1 or quality > 100:
                quality = 95
        except:
            quality = 95
        
        # Save temporary file
        temp_path = save_temp_file(file)
        
        try:
            # Start timing
            start_time = time.time()
            
            # Perform ELA analysis
            logger.info(f"Starting ELA analysis on {file.filename} with quality {quality}")
            results = ela_analyzer.perform_ela_analysis(temp_path, quality)
            
            # Calculate duration
            duration_ms = int((time.time() - start_time) * 1000)
            
            if 'error' in results:
                logger.error(f"ELA analysis failed: {results['error']}")
                
                # Log failed analysis
                log_file_analysis(
                    file_path=file.filename,
                    analysis_type=ActivityTypes.ELA_ANALYSIS,
                    results={'error': results['error'], 'quality': quality},
                    duration_ms=duration_ms,
                    result_status='error',
                    error_message=results['error']
                )
                
                return jsonify({'error': f'Analysis failed: {results["error"]}'}), 500
            
            # Add file information
            file_size = len(file.read())
            file.seek(0)  # Reset file pointer
            
            results['file_info'] = {
                'filename': file.filename,
                'original_size': file_size,
                'analysis_quality': quality
            }
            
            # Log successful analysis
            log_file_analysis(
                file_path=file.filename,
                analysis_type=ActivityTypes.ELA_ANALYSIS,
                results={
                    'tampering_detected': results.get('tampering_detected', False),
                    'confidence_score': results.get('confidence_score', 0),
                    'quality': quality,
                    'file_size': file_size
                },
                duration_ms=duration_ms,
                result_status='success'
            )
            
            logger.info(f"ELA analysis completed successfully for {file.filename}")
            return jsonify(results)
            
        finally:
            # Clean up temporary file
            cleanup_temp_file(temp_path)
            
    except Exception as e:
        logger.error(f"ELA analysis endpoint error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@ela_bp.route('/multi-quality-analyze', methods=['POST'])
def multi_quality_analyze():
    """
    Perform Error Level Analysis at multiple quality levels.
    
    Expected form data:
    - image: Image file
    - quality_levels: Comma-separated quality levels (optional)
    
    Returns:
    - JSON with multi-quality ELA analysis results
    """
    try:
        # Check if image was uploaded
        if 'image' not in request.files:
            return jsonify({'error': 'No image file provided'}), 400
        
        file = request.files['image']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed. Please upload JPG, PNG, BMP, TIFF, or GIF files.'}), 400
        
        # Parse quality levels
        quality_levels = None
        if 'quality_levels' in request.form:
            try:
                quality_str = request.form['quality_levels']
                quality_levels = [int(q.strip()) for q in quality_str.split(',') if q.strip().isdigit()]
                quality_levels = [q for q in quality_levels if 1 <= q <= 100]
                if not quality_levels:
                    quality_levels = None
            except:
                quality_levels = None
        
        # Save temporary file
        temp_path = save_temp_file(file)
        
        try:
            # Perform multi-quality ELA analysis
            logger.info(f"Starting multi-quality ELA analysis on {file.filename}")
            results = ela_analyzer.multi_quality_ela_analysis(temp_path, quality_levels)
            
            if 'error' in results:
                logger.error(f"Multi-quality ELA analysis failed: {results['error']}")
                return jsonify({'error': f'Analysis failed: {results["error"]}'}), 500
            
            # Add file information
            results['file_info'] = {
                'filename': file.filename,
                'original_size': len(file.read())
            }
            file.seek(0)  # Reset file pointer
            
            logger.info(f"Multi-quality ELA analysis completed successfully for {file.filename}")
            return jsonify(results)
            
        finally:
            # Clean up temporary file
            cleanup_temp_file(temp_path)
            
    except Exception as e:
        logger.error(f"Multi-quality ELA analysis endpoint error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@ela_bp.route('/quick-scan', methods=['POST'])
def quick_scan():
    """
    Perform quick ELA scan focusing on tampering probability.
    
    Expected form data:
    - image: Image file
    
    Returns:
    - JSON with quick tampering assessment
    """
    try:
        # Check if image was uploaded
        if 'image' not in request.files:
            return jsonify({'error': 'No image file provided'}), 400
        
        file = request.files['image']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed. Please upload JPG, PNG, BMP, TIFF, or GIF files.'}), 400
        
        # Save temporary file
        temp_path = save_temp_file(file)
        
        try:
            # Perform ELA analysis with default quality
            logger.info(f"Starting quick ELA scan on {file.filename}")
            results = ela_analyzer.perform_ela_analysis(temp_path, 95)
            
            if 'error' in results:
                logger.error(f"Quick ELA scan failed: {results['error']}")
                return jsonify({'error': f'Analysis failed: {results["error"]}'}), 500
            
            # Extract key information for quick scan
            quick_results = {
                'file_info': {
                    'filename': file.filename,
                    'analysis_timestamp': results['analysis_timestamp']
                },
                'tampering_assessment': results['tampering_assessment'],
                'overall_assessment': results['analysis_results']['overall_assessment'],
                'suspicious_regions_count': len(results['suspicious_regions']),
                'primary_concerns': results['analysis_results']['overall_assessment']['primary_concerns'],
                'forensic_summary': results['forensic_notes'][:3],  # Top 3 notes
                'recommendation': 'Further detailed analysis recommended' if results['tampering_assessment']['probability'] > 0.3 else 'Image appears authentic'
            }
            
            logger.info(f"Quick ELA scan completed for {file.filename}")
            return jsonify(quick_results)
            
        finally:
            # Clean up temporary file
            cleanup_temp_file(temp_path)
            
    except Exception as e:
        logger.error(f"Quick ELA scan endpoint error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@ela_bp.route('/batch-analyze', methods=['POST'])
def batch_analyze():
    """
    Perform ELA analysis on multiple images.
    
    Expected form data:
    - images: Multiple image files
    - quality: JPEG quality level (optional, default: 95)
    
    Returns:
    - JSON with batch analysis results
    """
    try:
        # Check if images were uploaded
        if 'images' not in request.files:
            return jsonify({'error': 'No image files provided'}), 400
        
        files = request.files.getlist('images')
        if not files or all(f.filename == '' for f in files):
            return jsonify({'error': 'No files selected'}), 400
        
        # Get quality parameter
        quality = request.form.get('quality', 95)
        try:
            quality = int(quality)
            if quality < 1 or quality > 100:
                quality = 95
        except:
            quality = 95
        
        batch_results = {
            'batch_timestamp': ela_analyzer._get_timestamp(),
            'total_files': len(files),
            'quality_used': quality,
            'results': {},
            'summary': {
                'processed': 0,
                'failed': 0,
                'likely_authentic': 0,
                'possibly_manipulated': 0,
                'likely_manipulated': 0
            }
        }
        
        # Process each file
        for i, file in enumerate(files):
            if file.filename == '' or not allowed_file(file.filename):
                batch_results['results'][f'file_{i}'] = {
                    'filename': file.filename,
                    'error': 'Invalid file type or no file selected'
                }
                batch_results['summary']['failed'] += 1
                continue
            
            temp_path = None
            try:
                # Save temporary file
                temp_path = save_temp_file(file)
                
                # Perform ELA analysis
                logger.info(f"Processing batch file {i+1}/{len(files)}: {file.filename}")
                results = ela_analyzer.perform_ela_analysis(temp_path, quality)
                
                if 'error' in results:
                    batch_results['results'][f'file_{i}'] = {
                        'filename': file.filename,
                        'error': results['error']
                    }
                    batch_results['summary']['failed'] += 1
                else:
                    # Store essential results
                    batch_results['results'][f'file_{i}'] = {
                        'filename': file.filename,
                        'tampering_assessment': results['tampering_assessment'],
                        'suspicious_regions_count': len(results['suspicious_regions']),
                        'overall_assessment': results['analysis_results']['overall_assessment']['authenticity_assessment']
                    }
                    
                    # Update summary
                    batch_results['summary']['processed'] += 1
                    assessment = results['analysis_results']['overall_assessment']['authenticity_assessment']
                    if assessment == 'likely_authentic':
                        batch_results['summary']['likely_authentic'] += 1
                    elif assessment in ['possible_authentic', 'uncertain']:
                        batch_results['summary']['possibly_manipulated'] += 1
                    else:
                        batch_results['summary']['likely_manipulated'] += 1
                
            except Exception as e:
                logger.error(f"Error processing batch file {file.filename}: {str(e)}")
                batch_results['results'][f'file_{i}'] = {
                    'filename': file.filename,
                    'error': f'Processing error: {str(e)}'
                }
                batch_results['summary']['failed'] += 1
                
            finally:
                if temp_path:
                    cleanup_temp_file(temp_path)
        
        logger.info(f"Batch ELA analysis completed: {batch_results['summary']['processed']} processed, {batch_results['summary']['failed']} failed")
        return jsonify(batch_results)
        
    except Exception as e:
        logger.error(f"Batch ELA analysis endpoint error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@ela_bp.route('/analyze-regions', methods=['POST'])
def analyze_regions():
    """
    Perform ELA analysis with focus on specific regions.
    
    Expected form data:
    - image: Image file
    - regions: JSON string with region coordinates (optional)
    - quality: JPEG quality level (optional, default: 95)
    
    Returns:
    - JSON with region-focused ELA analysis
    """
    try:
        # Check if image was uploaded
        if 'image' not in request.files:
            return jsonify({'error': 'No image file provided'}), 400
        
        file = request.files['image']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed. Please upload JPG, PNG, BMP, TIFF, or GIF files.'}), 400
        
        # Get quality parameter
        quality = request.form.get('quality', 95)
        try:
            quality = int(quality)
            if quality < 1 or quality > 100:
                quality = 95
        except:
            quality = 95
        
        # Parse regions if provided
        regions = None
        if 'regions' in request.form:
            import json
            try:
                regions = json.loads(request.form['regions'])
            except:
                regions = None
        
        # Save temporary file
        temp_path = save_temp_file(file)
        
        try:
            # Perform standard ELA analysis
            logger.info(f"Starting region-focused ELA analysis on {file.filename}")
            results = ela_analyzer.perform_ela_analysis(temp_path, quality)
            
            if 'error' in results:
                logger.error(f"Region ELA analysis failed: {results['error']}")
                return jsonify({'error': f'Analysis failed: {results["error"]}'}), 500
            
            # If specific regions were provided, focus analysis on those
            if regions:
                results['specified_regions_analysis'] = []
                # This would require additional implementation to analyze specific regions
                # For now, we'll include the region information in the response
                results['requested_regions'] = regions
                results['analysis_note'] = 'Region-specific analysis requested - full image analysis provided with region information'
            
            # Add file information
            results['file_info'] = {
                'filename': file.filename,
                'analysis_quality': quality,
                'regions_specified': regions is not None
            }
            
            logger.info(f"Region ELA analysis completed for {file.filename}")
            return jsonify(results)
            
        finally:
            # Clean up temporary file
            cleanup_temp_file(temp_path)
            
    except Exception as e:
        logger.error(f"Region ELA analysis endpoint error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@ela_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for ELA service"""
    return jsonify({
        'status': 'healthy',
        'service': 'Error Level Analysis API',
        'version': '1.0.0',
        'supported_formats': list(ALLOWED_EXTENSIONS),
        'timestamp': ela_analyzer._get_timestamp()
    })

@ela_bp.route('/info', methods=['GET'])
def get_info():
    """Get information about ELA analysis capabilities"""
    return jsonify({
        'service_name': 'Error Level Analysis (ELA)',
        'description': 'Detects image tampering through JPEG compression artifact analysis',
        'capabilities': {
            'single_image_analysis': 'Comprehensive ELA analysis on single images',
            'multi_quality_analysis': 'Analysis at multiple quality levels for enhanced detection',
            'quick_scan': 'Fast tampering probability assessment',
            'batch_processing': 'Analyze multiple images simultaneously',
            'region_analysis': 'Focus analysis on specific image regions'
        },
        'supported_formats': list(ALLOWED_EXTENSIONS),
        'quality_range': '1-100 (JPEG quality levels)',
        'default_quality': 95,
        'analysis_features': [
            'Tampering probability calculation',
            'Suspicious region detection',
            'Compression consistency analysis',
            'Error level visualization',
            'Forensic notes generation',
            'Comparative quality analysis'
        ],
        'endpoints': {
            '/analyze': 'Single image ELA analysis',
            '/multi-quality-analyze': 'Multi-quality level analysis',
            '/quick-scan': 'Quick tampering assessment',
            '/batch-analyze': 'Batch processing of multiple images',
            '/analyze-regions': 'Region-focused analysis',
            '/health': 'Service health check',
            '/info': 'Service information'
        }
    })

# Error handlers
@ela_bp.errorhandler(413)
def handle_large_file(error):
    """Handle file too large error"""
    return jsonify({'error': 'File too large. Please upload a smaller image.'}), 413

@ela_bp.errorhandler(400)
def handle_bad_request(error):
    """Handle bad request error"""
    return jsonify({'error': 'Bad request. Please check your input parameters.'}), 400

@ela_bp.errorhandler(500)
def handle_internal_error(error):
    """Handle internal server error"""
    logger.error(f"Internal server error in ELA API: {str(error)}")
    return jsonify({'error': 'Internal server error. Please try again later.'}), 500