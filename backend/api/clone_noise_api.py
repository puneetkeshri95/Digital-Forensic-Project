"""
Clone and Noise Detection API Endpoints
======================================

Flask API endpoints for advanced image tampering detection including:
- Copy-move detection
- Block matching analysis  
- Noise consistency analysis
- Statistical anomaly detection
"""

from flask import Blueprint, request, jsonify, current_app
import os
import tempfile
import uuid
from werkzeug.utils import secure_filename
import logging
import json

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from forensics.clone_noise_detector import CloneNoiseDetector

# Create clone/noise detection API blueprint
clone_noise_bp = Blueprint('clone_noise', __name__, url_prefix='/api/clone-noise')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize detector
detector = CloneNoiseDetector()

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
        temp_path = os.path.join(temp_dir, f"clone_noise_{uuid.uuid4().hex}_{filename}")
        
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

@clone_noise_bp.route('/analyze', methods=['POST'])
def analyze_tampering():
    """
    Comprehensive tampering analysis using multiple detection methods.
    
    Expected form data:
    - image: Image file
    - methods: Comma-separated list of methods (optional)
    
    Returns:
    - JSON with comprehensive tampering analysis results
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
        
        # Parse methods parameter
        methods = None
        if 'methods' in request.form:
            methods_str = request.form['methods']
            if methods_str:
                methods = [m.strip() for m in methods_str.split(',')]
                # Validate methods
                valid_methods = ['copy_move', 'block_matching', 'noise_analysis', 'statistical_analysis']
                methods = [m for m in methods if m in valid_methods]
                if not methods:
                    methods = None
        
        # Save temporary file
        temp_path = save_temp_file(file)
        
        try:
            # Perform tampering analysis
            logger.info(f"Starting comprehensive tampering analysis on {file.filename}")
            if methods:
                logger.info(f"Using methods: {', '.join(methods)}")
            
            results = detector.detect_tampering(temp_path, methods)
            
            if 'error' in results:
                logger.error(f"Tampering analysis failed: {results['error']}")
                return jsonify({'error': f'Analysis failed: {results["error"]}'}), 500
            
            # Add file information
            results['file_info'] = {
                'filename': file.filename,
                'original_size': len(file.read()),
                'methods_requested': methods or ['all']
            }
            file.seek(0)  # Reset file pointer
            
            logger.info(f"Tampering analysis completed successfully for {file.filename}")
            return jsonify(results)
            
        finally:
            # Clean up temporary file
            cleanup_temp_file(temp_path)
            
    except Exception as e:
        logger.error(f"Tampering analysis endpoint error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@clone_noise_bp.route('/copy-move', methods=['POST'])
def detect_copy_move():
    """
    Specialized copy-move detection endpoint.
    
    Expected form data:
    - image: Image file
    
    Returns:
    - JSON with copy-move detection results
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
            # Perform copy-move detection only
            logger.info(f"Starting copy-move detection on {file.filename}")
            results = detector.detect_tampering(temp_path, ['copy_move'])
            
            if 'error' in results:
                logger.error(f"Copy-move detection failed: {results['error']}")
                return jsonify({'error': f'Analysis failed: {results["error"]}'}), 500
            
            # Extract copy-move specific results
            copy_move_results = results.get('detection_results', {}).get('copy_move', {})
            
            response = {
                'analysis_timestamp': results['analysis_timestamp'],
                'file_info': {
                    'filename': file.filename,
                    'dimensions': results['image_dimensions']
                },
                'copy_move_detection': copy_move_results,
                'suspicious_regions': [r for r in results['suspicious_regions'] 
                                     if r['detection_type'] == 'copy_move'],
                'overall_assessment': {
                    'regions_found': len([r for r in results['suspicious_regions'] 
                                        if r['detection_type'] == 'copy_move']),
                    'max_confidence': max([r['confidence'] for r in results['suspicious_regions'] 
                                         if r['detection_type'] == 'copy_move'], default=0.0),
                    'assessment': 'Copy-move patterns detected' if any(r['detection_type'] == 'copy_move' 
                                                                     for r in results['suspicious_regions']) 
                                                                   else 'No copy-move patterns found'
                },
                'visualizations': results.get('visualizations', {})
            }
            
            logger.info(f"Copy-move detection completed for {file.filename}")
            return jsonify(response)
            
        finally:
            # Clean up temporary file
            cleanup_temp_file(temp_path)
            
    except Exception as e:
        logger.error(f"Copy-move detection endpoint error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@clone_noise_bp.route('/noise-analysis', methods=['POST'])
def analyze_noise():
    """
    Specialized noise consistency analysis endpoint.
    
    Expected form data:
    - image: Image file
    
    Returns:
    - JSON with noise analysis results
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
            # Perform noise analysis only
            logger.info(f"Starting noise analysis on {file.filename}")
            results = detector.detect_tampering(temp_path, ['noise_analysis'])
            
            if 'error' in results:
                logger.error(f"Noise analysis failed: {results['error']}")
                return jsonify({'error': f'Analysis failed: {results["error"]}'}), 500
            
            # Extract noise analysis specific results
            noise_results = results.get('detection_results', {}).get('noise_analysis', {})
            
            response = {
                'analysis_timestamp': results['analysis_timestamp'],
                'file_info': {
                    'filename': file.filename,
                    'dimensions': results['image_dimensions']
                },
                'noise_analysis': noise_results,
                'suspicious_regions': [r for r in results['suspicious_regions'] 
                                     if r['detection_type'] == 'noise_inconsistency'],
                'overall_assessment': {
                    'inconsistent_regions': len([r for r in results['suspicious_regions'] 
                                               if r['detection_type'] == 'noise_inconsistency']),
                    'max_noise_variance': max([r['noise_variance'] for r in results['suspicious_regions'] 
                                             if r['detection_type'] == 'noise_inconsistency'], default=0.0),
                    'assessment': 'Noise inconsistencies detected' if any(r['detection_type'] == 'noise_inconsistency' 
                                                                         for r in results['suspicious_regions']) 
                                                                    else 'Noise appears consistent'
                },
                'visualizations': results.get('visualizations', {})
            }
            
            logger.info(f"Noise analysis completed for {file.filename}")
            return jsonify(response)
            
        finally:
            # Clean up temporary file
            cleanup_temp_file(temp_path)
            
    except Exception as e:
        logger.error(f"Noise analysis endpoint error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@clone_noise_bp.route('/block-matching', methods=['POST'])
def analyze_blocks():
    """
    Specialized block matching analysis endpoint.
    
    Expected form data:
    - image: Image file
    
    Returns:
    - JSON with block matching results
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
            # Perform block matching analysis only
            logger.info(f"Starting block matching analysis on {file.filename}")
            results = detector.detect_tampering(temp_path, ['block_matching'])
            
            if 'error' in results:
                logger.error(f"Block matching analysis failed: {results['error']}")
                return jsonify({'error': f'Analysis failed: {results["error"]}'}), 500
            
            # Extract block matching specific results
            block_results = results.get('detection_results', {}).get('block_matching', {})
            
            response = {
                'analysis_timestamp': results['analysis_timestamp'],
                'file_info': {
                    'filename': file.filename,
                    'dimensions': results['image_dimensions']
                },
                'block_matching': block_results,
                'suspicious_regions': [r for r in results['suspicious_regions'] 
                                     if r['detection_type'] == 'block_matching'],
                'overall_assessment': {
                    'similar_regions': len([r for r in results['suspicious_regions'] 
                                          if r['detection_type'] == 'block_matching']),
                    'max_similarity': max([r['similarity_score'] for r in results['suspicious_regions'] 
                                         if r['detection_type'] == 'block_matching'], default=0.0),
                    'assessment': 'Suspicious block similarities found' if any(r['detection_type'] == 'block_matching' 
                                                                              for r in results['suspicious_regions']) 
                                                                          else 'No significant block similarities'
                },
                'visualizations': results.get('visualizations', {})
            }
            
            logger.info(f"Block matching analysis completed for {file.filename}")
            return jsonify(response)
            
        finally:
            # Clean up temporary file
            cleanup_temp_file(temp_path)
            
    except Exception as e:
        logger.error(f"Block matching analysis endpoint error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@clone_noise_bp.route('/statistical', methods=['POST'])
def analyze_statistics():
    """
    Specialized statistical analysis endpoint.
    
    Expected form data:
    - image: Image file
    
    Returns:
    - JSON with statistical analysis results
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
            # Perform statistical analysis only
            logger.info(f"Starting statistical analysis on {file.filename}")
            results = detector.detect_tampering(temp_path, ['statistical_analysis'])
            
            if 'error' in results:
                logger.error(f"Statistical analysis failed: {results['error']}")
                return jsonify({'error': f'Analysis failed: {results["error"]}'}), 500
            
            # Extract statistical analysis specific results
            stats_results = results.get('detection_results', {}).get('statistical_analysis', {})
            
            response = {
                'analysis_timestamp': results['analysis_timestamp'],
                'file_info': {
                    'filename': file.filename,
                    'dimensions': results['image_dimensions']
                },
                'statistical_analysis': stats_results,
                'suspicious_regions': [r for r in results['suspicious_regions'] 
                                     if r['detection_type'] == 'statistical_anomaly'],
                'overall_assessment': {
                    'anomalous_regions': len([r for r in results['suspicious_regions'] 
                                            if r['detection_type'] == 'statistical_anomaly']),
                    'max_confidence': max([r['confidence'] for r in results['suspicious_regions'] 
                                         if r['detection_type'] == 'statistical_anomaly'], default=0.0),
                    'assessment': 'Statistical anomalies detected' if any(r['detection_type'] == 'statistical_anomaly' 
                                                                         for r in results['suspicious_regions']) 
                                                                    else 'No statistical anomalies found'
                },
                'visualizations': results.get('visualizations', {})
            }
            
            logger.info(f"Statistical analysis completed for {file.filename}")
            return jsonify(response)
            
        finally:
            # Clean up temporary file
            cleanup_temp_file(temp_path)
            
    except Exception as e:
        logger.error(f"Statistical analysis endpoint error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@clone_noise_bp.route('/batch-analyze', methods=['POST'])
def batch_analyze():
    """
    Batch tampering analysis on multiple images.
    
    Expected form data:
    - images: Multiple image files
    - methods: Comma-separated list of methods (optional)
    
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
        
        # Parse methods parameter
        methods = None
        if 'methods' in request.form:
            methods_str = request.form['methods']
            if methods_str:
                methods = [m.strip() for m in methods_str.split(',')]
                valid_methods = ['copy_move', 'block_matching', 'noise_analysis', 'statistical_analysis']
                methods = [m for m in methods if m in valid_methods]
                if not methods:
                    methods = None
        
        batch_results = {
            'batch_timestamp': detector._get_timestamp(),
            'total_files': len(files),
            'methods_used': methods or ['all'],
            'results': {},
            'summary': {
                'processed': 0,
                'failed': 0,
                'tampering_detected': 0,
                'clean_images': 0,
                'high_risk': 0,
                'medium_risk': 0,
                'low_risk': 0
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
                
                # Perform tampering analysis
                logger.info(f"Processing batch file {i+1}/{len(files)}: {file.filename}")
                results = detector.detect_tampering(temp_path, methods)
                
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
                        'overall_assessment': results['overall_assessment'],
                        'suspicious_regions_count': results['overall_assessment']['total_suspicious_regions'],
                        'tampering_probability': results['overall_assessment']['tampering_probability'],
                        'risk_level': results['overall_assessment']['risk_level'],
                        'primary_concerns': results['overall_assessment']['primary_concerns']
                    }
                    
                    # Update summary
                    batch_results['summary']['processed'] += 1
                    
                    risk_level = results['overall_assessment']['risk_level']
                    if risk_level == 'high':
                        batch_results['summary']['high_risk'] += 1
                        batch_results['summary']['tampering_detected'] += 1
                    elif risk_level == 'medium':
                        batch_results['summary']['medium_risk'] += 1
                        batch_results['summary']['tampering_detected'] += 1
                    else:
                        batch_results['summary']['low_risk'] += 1
                        if results['overall_assessment']['tampering_probability'] < 0.2:
                            batch_results['summary']['clean_images'] += 1
                
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
        
        logger.info(f"Batch tampering analysis completed: {batch_results['summary']['processed']} processed, {batch_results['summary']['failed']} failed")
        return jsonify(batch_results)
        
    except Exception as e:
        logger.error(f"Batch tampering analysis endpoint error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@clone_noise_bp.route('/algorithms', methods=['GET'])
def get_algorithm_info():
    """Get information about available detection algorithms"""
    try:
        info = detector.get_algorithm_info()
        return jsonify(info)
    except Exception as e:
        logger.error(f"Algorithm info endpoint error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@clone_noise_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for clone/noise detection service"""
    return jsonify({
        'status': 'healthy',
        'service': 'Clone and Noise Detection API',
        'version': '1.0.0',
        'supported_formats': list(ALLOWED_EXTENSIONS),
        'available_methods': ['copy_move', 'block_matching', 'noise_analysis', 'statistical_analysis'],
        'timestamp': detector._get_timestamp()
    })

@clone_noise_bp.route('/info', methods=['GET'])
def get_info():
    """Get information about clone/noise detection capabilities"""
    return jsonify({
        'service_name': 'Clone and Noise Detection',
        'description': 'Advanced image tampering detection through multiple analysis methods',
        'capabilities': {
            'copy_move_detection': 'Detect duplicated regions using feature matching',
            'block_matching': 'Analyze image blocks for suspicious similarities',
            'noise_analysis': 'Detect inconsistent noise patterns',
            'statistical_analysis': 'Identify statistical anomalies in image regions',
            'batch_processing': 'Analyze multiple images simultaneously',
            'visualization': 'Generate annotated images and heatmaps'
        },
        'supported_formats': list(ALLOWED_EXTENSIONS),
        'detection_methods': [
            'SIFT/ORB feature matching',
            'Normalized cross-correlation',
            'Noise variance analysis',
            'Statistical property analysis',
            'DBSCAN clustering',
            'Connected component analysis'
        ],
        'output_features': [
            'Suspicious region detection',
            'Confidence scoring',
            'Tampering probability assessment',
            'Method-specific analysis',
            'Visual annotations',
            'Comprehensive reporting'
        ],
        'endpoints': {
            '/analyze': 'Comprehensive tampering analysis using all methods',
            '/copy-move': 'Specialized copy-move detection',
            '/noise-analysis': 'Noise consistency analysis',
            '/block-matching': 'Block similarity analysis',
            '/statistical': 'Statistical anomaly detection',
            '/batch-analyze': 'Batch processing of multiple images',
            '/algorithms': 'Algorithm information and parameters',
            '/health': 'Service health check',
            '/info': 'Service capabilities and information'
        }
    })

# Error handlers
@clone_noise_bp.errorhandler(413)
def handle_large_file(error):
    """Handle file too large error"""
    return jsonify({'error': 'File too large. Please upload a smaller image.'}), 413

@clone_noise_bp.errorhandler(400)
def handle_bad_request(error):
    """Handle bad request error"""
    return jsonify({'error': 'Bad request. Please check your input parameters.'}), 400

@clone_noise_bp.errorhandler(500)
def handle_internal_error(error):
    """Handle internal server error"""
    logger.error(f"Internal server error in clone/noise detection API: {str(error)}")
    return jsonify({'error': 'Internal server error. Please try again later.'}), 500