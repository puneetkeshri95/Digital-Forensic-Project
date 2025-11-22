"""
Forensic Image Analysis API Endpoints
====================================

Flask API endpoints for comprehensive forensic image analysis including
metadata extraction, error-level analysis, noise analysis, clone detection,
and pixel examination tools.
"""

from flask import Blueprint, request, jsonify, current_app, send_file
import os
import json
import base64
from datetime import datetime
from werkzeug.utils import secure_filename
import tempfile
import cv2
import numpy as np
from PIL import Image
import io

# Import our forensic analyzer
try:
    from forensics.image_analysis import ForensicImageAnalyzer
    FORENSIC_ANALYSIS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Forensic image analysis not available: {e}")
    FORENSIC_ANALYSIS_AVAILABLE = False

forensic_bp = Blueprint('forensic_analysis', __name__)

# Initialize the forensic analyzer
if FORENSIC_ANALYSIS_AVAILABLE:
    forensic_analyzer = ForensicImageAnalyzer()
else:
    forensic_analyzer = None

# Store analysis sessions
analysis_sessions = {}

@forensic_bp.route('/analyze-image', methods=['POST'])
def analyze_image():
    """
    Perform comprehensive forensic analysis on an uploaded image
    
    Expected payload:
    - file: Image file (multipart/form-data)
    - analysis_types: JSON array of analysis types to perform
    """
    try:
        if not FORENSIC_ANALYSIS_AVAILABLE:
            return jsonify({
                'success': False,
                'error': 'Forensic analysis libraries not available'
            }), 500
        
        # Check if file is provided
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No image file provided'
            }), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'No file selected'
            }), 400
        
        # Get analysis options
        analysis_types = request.form.get('analysis_types', '["all"]')
        try:
            analysis_types = json.loads(analysis_types)
        except:
            analysis_types = ["all"]
        
        # Save uploaded file temporarily
        filename = secure_filename(file.filename)
        temp_dir = tempfile.mkdtemp()
        temp_path = os.path.join(temp_dir, filename)
        file.save(temp_path)
        
        # Perform forensic analysis
        analysis_result = forensic_analyzer.analyze_image(temp_path)
        
        # Generate session ID for this analysis
        session_id = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(filename) % 10000}"
        
        # Store analysis result
        analysis_sessions[session_id] = {
            'timestamp': datetime.now().isoformat(),
            'filename': filename,
            'temp_path': temp_path,
            'analysis_result': analysis_result,
            'analysis_types': analysis_types
        }
        
        # Clean up the full result for response (remove large data)
        response_result = clean_analysis_result_for_response(analysis_result)
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'filename': filename,
            'analysis_result': response_result,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        current_app.logger.error(f"Error in image analysis: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Analysis failed: {str(e)}'
        }), 500

@forensic_bp.route('/get-analysis/<session_id>', methods=['GET'])
def get_analysis(session_id):
    """Get stored analysis results by session ID"""
    try:
        if session_id not in analysis_sessions:
            return jsonify({
                'success': False,
                'error': 'Analysis session not found'
            }), 404
        
        session_data = analysis_sessions[session_id]
        analysis_result = session_data['analysis_result']
        
        # Clean result for response
        response_result = clean_analysis_result_for_response(analysis_result)
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'filename': session_data['filename'],
            'timestamp': session_data['timestamp'],
            'analysis_result': response_result
        })
        
    except Exception as e:
        current_app.logger.error(f"Error retrieving analysis: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to retrieve analysis: {str(e)}'
        }), 500

@forensic_bp.route('/get-ela-visualization/<session_id>', methods=['GET'])
def get_ela_visualization(session_id):
    """Get ELA visualization for a specific analysis session"""
    try:
        if session_id not in analysis_sessions:
            return jsonify({
                'success': False,
                'error': 'Analysis session not found'
            }), 404
        
        session_data = analysis_sessions[session_id]
        analysis_result = session_data['analysis_result']
        
        if 'ela_analysis' in analysis_result and 'visualization' in analysis_result['ela_analysis']:
            ela_viz = analysis_result['ela_analysis']['visualization']
            
            return jsonify({
                'success': True,
                'visualization': ela_viz,
                'format': 'base64_png'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'ELA visualization not available'
            }), 404
            
    except Exception as e:
        current_app.logger.error(f"Error retrieving ELA visualization: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to retrieve visualization: {str(e)}'
        }), 500

@forensic_bp.route('/get-noise-map/<session_id>', methods=['GET'])
def get_noise_map(session_id):
    """Generate and return noise map visualization"""
    try:
        if session_id not in analysis_sessions:
            return jsonify({
                'success': False,
                'error': 'Analysis session not found'
            }), 404
        
        session_data = analysis_sessions[session_id]
        temp_path = session_data['temp_path']
        
        if not os.path.exists(temp_path):
            return jsonify({
                'success': False,
                'error': 'Original image file not found'
            }), 404
        
        # Generate noise map visualization
        noise_map_b64 = generate_noise_map_visualization(temp_path)
        
        return jsonify({
            'success': True,
            'noise_map': noise_map_b64,
            'format': 'base64_png'
        })
        
    except Exception as e:
        current_app.logger.error(f"Error generating noise map: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to generate noise map: {str(e)}'
        }), 500

@forensic_bp.route('/pixel-examination/<session_id>', methods=['POST'])
def pixel_examination(session_id):
    """
    Perform detailed pixel examination on a specific region
    
    Expected payload:
    {
        "x": int,
        "y": int,
        "width": int,
        "height": int
    }
    """
    try:
        if session_id not in analysis_sessions:
            return jsonify({
                'success': False,
                'error': 'Analysis session not found'
            }), 404
        
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No examination parameters provided'
            }), 400
        
        # Get region parameters
        x = data.get('x', 0)
        y = data.get('y', 0)
        width = data.get('width', 100)
        height = data.get('height', 100)
        
        session_data = analysis_sessions[session_id]
        temp_path = session_data['temp_path']
        
        # Load image and extract region
        image = cv2.imread(temp_path)
        if image is None:
            return jsonify({
                'success': False,
                'error': 'Could not load image'
            }), 500
        
        # Extract region of interest
        roi = image[y:y+height, x:x+width]
        
        # Perform detailed analysis on the region
        region_analysis = analyze_image_region(roi, x, y)
        
        return jsonify({
            'success': True,
            'region': {
                'x': x,
                'y': y,
                'width': width,
                'height': height
            },
            'analysis': region_analysis
        })
        
    except Exception as e:
        current_app.logger.error(f"Error in pixel examination: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Pixel examination failed: {str(e)}'
        }), 500

@forensic_bp.route('/metadata-extraction/<session_id>', methods=['GET'])
def get_detailed_metadata(session_id):
    """Get detailed metadata extraction results"""
    try:
        if session_id not in analysis_sessions:
            return jsonify({
                'success': False,
                'error': 'Analysis session not found'
            }), 404
        
        session_data = analysis_sessions[session_id]
        analysis_result = session_data['analysis_result']
        
        if 'metadata' in analysis_result:
            return jsonify({
                'success': True,
                'metadata': analysis_result['metadata'],
                'basic_info': analysis_result.get('basic_info', {}),
                'forensic_hash': analysis_result.get('forensic_hash', {})
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Metadata not available'
            }), 404
            
    except Exception as e:
        current_app.logger.error(f"Error retrieving metadata: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to retrieve metadata: {str(e)}'
        }), 500

@forensic_bp.route('/clone-detection-details/<session_id>', methods=['GET'])
def get_clone_detection_details(session_id):
    """Get detailed clone detection results with visualizations"""
    try:
        if session_id not in analysis_sessions:
            return jsonify({
                'success': False,
                'error': 'Analysis session not found'
            }), 404
        
        session_data = analysis_sessions[session_id]
        analysis_result = session_data['analysis_result']
        temp_path = session_data['temp_path']
        
        if 'clone_detection' in analysis_result:
            clone_data = analysis_result['clone_detection']
            
            # Generate clone visualization
            clone_viz = generate_clone_visualization(temp_path, clone_data)
            
            return jsonify({
                'success': True,
                'clone_detection': clone_data,
                'visualization': clone_viz
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Clone detection results not available'
            }), 404
            
    except Exception as e:
        current_app.logger.error(f"Error retrieving clone detection: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to retrieve clone detection: {str(e)}'
        }), 500

@forensic_bp.route('/export-analysis/<session_id>', methods=['GET'])
def export_analysis(session_id):
    """Export complete analysis results as JSON"""
    try:
        if session_id not in analysis_sessions:
            return jsonify({
                'success': False,
                'error': 'Analysis session not found'
            }), 404
        
        session_data = analysis_sessions[session_id]
        
        # Create comprehensive export data
        export_data = {
            'forensic_analysis_report': {
                'session_id': session_id,
                'filename': session_data['filename'],
                'analysis_timestamp': session_data['timestamp'],
                'analysis_types': session_data['analysis_types'],
                'results': session_data['analysis_result'],
                'export_timestamp': datetime.now().isoformat()
            }
        }
        
        # Create temporary file for export
        temp_export = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        json.dump(export_data, temp_export, indent=2, default=str)
        temp_export.close()
        
        return send_file(
            temp_export.name,
            as_attachment=True,
            download_name=f'forensic_analysis_{session_id}.json',
            mimetype='application/json'
        )
        
    except Exception as e:
        current_app.logger.error(f"Error exporting analysis: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Export failed: {str(e)}'
        }), 500

@forensic_bp.route('/list-sessions', methods=['GET'])
def list_analysis_sessions():
    """List all available analysis sessions"""
    try:
        sessions_list = []
        
        for session_id, session_data in analysis_sessions.items():
            sessions_list.append({
                'session_id': session_id,
                'filename': session_data['filename'],
                'timestamp': session_data['timestamp'],
                'analysis_types': session_data['analysis_types']
            })
        
        # Sort by timestamp (newest first)
        sessions_list.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return jsonify({
            'success': True,
            'sessions': sessions_list,
            'total_sessions': len(sessions_list)
        })
        
    except Exception as e:
        current_app.logger.error(f"Error listing sessions: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Failed to list sessions: {str(e)}'
        }), 500

# Helper functions

def clean_analysis_result_for_response(analysis_result):
    """Remove large binary data from analysis result for API response"""
    cleaned_result = analysis_result.copy()
    
    # Remove large visualization data (keep only references)
    if 'ela_analysis' in cleaned_result and 'visualization' in cleaned_result['ela_analysis']:
        # Keep only a flag that visualization is available
        cleaned_result['ela_analysis']['has_visualization'] = True
        # Remove the actual base64 data to reduce response size
        del cleaned_result['ela_analysis']['visualization']
    
    return cleaned_result

def generate_noise_map_visualization(image_path):
    """Generate noise map visualization as base64 encoded image"""
    try:
        # Load image
        image = cv2.imread(image_path)
        if image is None:
            return ""
        
        # Convert to grayscale
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        
        # Create simple noise map using local variance
        noise_map = np.zeros_like(gray, dtype=np.float32)
        window_size = 16
        
        h, w = gray.shape
        for y in range(0, h - window_size, window_size // 2):
            for x in range(0, w - window_size, window_size // 2):
                window = gray[y:y+window_size, x:x+window_size]
                local_variance = np.var(window.astype(np.float32))
                noise_map[y:y+window_size, x:x+window_size] = local_variance
        
        # Normalize and convert to visualization
        noise_map_norm = cv2.normalize(noise_map, None, 0, 255, cv2.NORM_MINMAX).astype(np.uint8)
        noise_map_colored = cv2.applyColorMap(noise_map_norm, cv2.COLORMAP_JET)
        
        # Convert to base64
        pil_img = Image.fromarray(cv2.cvtColor(noise_map_colored, cv2.COLOR_BGR2RGB))
        buffer = io.BytesIO()
        pil_img.save(buffer, format='PNG')
        
        return base64.b64encode(buffer.getvalue()).decode('utf-8')
        
    except Exception as e:
        current_app.logger.error(f"Error generating noise map: {str(e)}")
        return ""

def analyze_image_region(roi, x, y):
    """Perform detailed analysis on a specific image region"""
    try:
        analysis = {}
        
        # Basic statistics
        analysis['pixel_statistics'] = {
            'mean': float(np.mean(roi)),
            'std': float(np.std(roi)),
            'min': float(np.min(roi)),
            'max': float(np.max(roi))
        }
        
        # Color analysis
        if len(roi.shape) == 3:
            analysis['color_analysis'] = {
                'blue_mean': float(np.mean(roi[:, :, 0])),
                'green_mean': float(np.mean(roi[:, :, 1])),
                'red_mean': float(np.mean(roi[:, :, 2]))
            }
        
        # Edge density
        gray_roi = cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY) if len(roi.shape) == 3 else roi
        edges = cv2.Canny(gray_roi, 50, 150)
        analysis['edge_density'] = float(np.sum(edges > 0) / edges.size)
        
        # Local noise estimate
        laplacian = cv2.Laplacian(gray_roi, cv2.CV_64F)
        analysis['noise_estimate'] = float(np.var(laplacian))
        
        # Texture complexity
        analysis['texture_complexity'] = float(np.std(gray_roi))
        
        return analysis
        
    except Exception as e:
        return {'error': str(e)}

def generate_clone_visualization(image_path, clone_data):
    """Generate visualization of detected clone regions"""
    try:
        # Load original image
        image = cv2.imread(image_path)
        if image is None:
            return ""
        
        # Draw clone regions if any detected
        viz_image = image.copy()
        
        if 'clone_regions' in clone_data:
            for i, region in enumerate(clone_data['clone_regions'][:10]):  # Limit to 10 regions
                # Draw rectangle around clone region
                color = (0, 255, 0) if i % 2 == 0 else (255, 0, 0)  # Alternate colors
                cv2.rectangle(viz_image, 
                             (region.get('x', 0), region.get('y', 0)), 
                             (region.get('x', 0) + region.get('width', 50), 
                              region.get('y', 0) + region.get('height', 50)), 
                             color, 2)
                
                # Add label
                cv2.putText(viz_image, f'Clone {i+1}', 
                           (region.get('x', 0), region.get('y', 0) - 10),
                           cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 1)
        
        # Convert to base64
        pil_img = Image.fromarray(cv2.cvtColor(viz_image, cv2.COLOR_BGR2RGB))
        buffer = io.BytesIO()
        pil_img.save(buffer, format='PNG')
        
        return base64.b64encode(buffer.getvalue()).decode('utf-8')
        
    except Exception as e:
        current_app.logger.error(f"Error generating clone visualization: {str(e)}")
        return ""

# Error handlers

@forensic_bp.errorhandler(413)
def file_too_large(error):
    """Handle file too large error"""
    return jsonify({
        'success': False,
        'error': 'File too large. Maximum size allowed is 16MB.'
    }), 413

@forensic_bp.errorhandler(415)
def unsupported_media_type(error):
    """Handle unsupported media type error"""
    return jsonify({
        'success': False,
        'error': 'Unsupported file type. Please upload a valid image file.'
    }), 415


# Export the blueprint for app registration
forensic_analysis_bp = forensic_bp