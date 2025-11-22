"""
EXIF Metadata Extraction API Endpoints
======================================

Flask API endpoints for comprehensive EXIF metadata extraction and analysis.
Provides endpoints for uploading images and extracting detailed metadata
including camera info, GPS data, timestamps, and forensic analysis.
"""

from flask import Blueprint, request, jsonify, send_file
import os
import tempfile
import uuid
from datetime import datetime
import logging
import time
from werkzeug.utils import secure_filename
from forensics.exif_extractor import EXIFMetadataExtractor
from utils.activity_logger import log_file_analysis, ActivityTypes
import json

# Create blueprint
exif_bp = Blueprint('exif_metadata', __name__)

# Initialize extractor
extractor = EXIFMetadataExtractor()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.tiff', '.tif', '.bmp', '.gif'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB

def allowed_file(filename):
    """Check if file extension is allowed"""
    return os.path.splitext(filename.lower())[1] in ALLOWED_EXTENSIONS

def validate_file_size(file):
    """Check if file size is within limits"""
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)
    return size <= MAX_FILE_SIZE


@exif_bp.route('/extract-metadata', methods=['POST'])
def extract_metadata():
    """
    Extract comprehensive EXIF metadata from uploaded image
    
    Returns:
        JSON response with organized metadata including:
        - Camera information
        - GPS location data
        - Capture settings
        - Timestamps
        - Technical details
        - Forensic analysis notes
    """
    try:
        # Check if file is present
        if 'image' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No image file provided'
            }), 400
        
        file = request.files['image']
        
        # Check if file is selected
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'No file selected'
            }), 400
        
        # Validate file type
        if not allowed_file(file.filename):
            return jsonify({
                'success': False,
                'error': 'Invalid file type. Supported formats: JPG, PNG, TIFF, BMP, GIF'
            }), 400
        
        # Validate file size
        if not validate_file_size(file):
            return jsonify({
                'success': False,
                'error': f'File too large. Maximum size: {MAX_FILE_SIZE // (1024*1024)}MB'
            }), 400
        
        # Generate session ID
        session_id = str(uuid.uuid4())
        
        # Create temporary file
        temp_dir = tempfile.gettempdir()
        original_filename = secure_filename(file.filename)
        temp_filename = f"exif_{session_id}_{original_filename}"
        temp_path = os.path.join(temp_dir, temp_filename)
        
        try:
            # Save uploaded file
            file.save(temp_path)
            
            # Start timing
            start_time = time.time()
            
            # Extract metadata
            logger.info(f"Extracting metadata from {original_filename}")
            metadata = extractor.extract_comprehensive_metadata(temp_path)
            
            # Calculate duration
            duration_ms = int((time.time() - start_time) * 1000)
            
            if 'error' in metadata:
                # Log failed analysis
                log_file_analysis(
                    file_path=original_filename,
                    analysis_type=ActivityTypes.EXIF_ANALYSIS,
                    results={'error': metadata['error']},
                    duration_ms=duration_ms,
                    result_status='error',
                    error_message=metadata['error']
                )
                
                return jsonify({
                    'success': False,
                    'error': f'Metadata extraction failed: {metadata["error"]}'
                }), 500
            
            # Get summary for quick overview
            summary = extractor.get_metadata_summary(metadata)
            
            # Log successful analysis
            file_size = os.path.getsize(temp_path) if os.path.exists(temp_path) else 0
            metadata_count = len(metadata.get('exif_data', {}))
            
            log_file_analysis(
                file_path=original_filename,
                analysis_type=ActivityTypes.EXIF_ANALYSIS,
                results={
                    'metadata_fields_extracted': metadata_count,
                    'has_gps_data': bool(metadata.get('gps_data')),
                    'camera_make': metadata.get('camera_info', {}).get('make'),
                    'camera_model': metadata.get('camera_info', {}).get('model'),
                    'file_size': file_size
                },
                duration_ms=duration_ms,
                result_status='success'
            )
            
            # Prepare response
            response_data = {
                'success': True,
                'session_id': session_id,
                'filename': original_filename,
                'extraction_timestamp': datetime.now().isoformat(),
                'summary': summary,
                'metadata': metadata,
                'metadata_count': metadata_count
            }
            
            logger.info(f"Successfully extracted {metadata_count} metadata fields")
            
            return jsonify(response_data)
            
        finally:
            # Clean up temporary file
            try:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
            except Exception as e:
                logger.warning(f"Failed to cleanup temp file: {str(e)}")
    
    except Exception as e:
        logger.error(f"EXIF extraction error: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}'
        }), 500


@exif_bp.route('/metadata-summary', methods=['POST'])
def get_metadata_summary():
    """
    Get a concise summary of key metadata fields
    
    Returns:
        JSON response with key information like camera, date, location, software
    """
    try:
        # Check if file is present
        if 'image' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No image file provided'
            }), 400
        
        file = request.files['image']
        
        if file.filename == '' or not allowed_file(file.filename):
            return jsonify({
                'success': False,
                'error': 'Invalid file'
            }), 400
        
        # Create temporary file
        temp_dir = tempfile.gettempdir()
        original_filename = secure_filename(file.filename)
        temp_filename = f"summary_{uuid.uuid4()}_{original_filename}"
        temp_path = os.path.join(temp_dir, temp_filename)
        
        try:
            file.save(temp_path)
            
            # Extract metadata
            metadata = extractor.extract_comprehensive_metadata(temp_path)
            
            if 'error' in metadata:
                return jsonify({
                    'success': False,
                    'error': metadata['error']
                }), 500
            
            # Get summary
            summary = extractor.get_metadata_summary(metadata)
            
            return jsonify({
                'success': True,
                'filename': original_filename,
                'summary': summary
            })
            
        finally:
            # Clean up
            try:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
            except Exception as e:
                logger.warning(f"Cleanup error: {str(e)}")
    
    except Exception as e:
        logger.error(f"Summary extraction error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@exif_bp.route('/export-metadata/<session_id>', methods=['GET'])
def export_metadata_report(session_id):
    """
    Export metadata as downloadable JSON report
    
    Args:
        session_id: Session identifier from previous extraction
        
    Returns:
        JSON file download or error response
    """
    try:
        # This would typically retrieve stored session data
        # For now, return error as we'd need to implement session storage
        return jsonify({
            'success': False,
            'error': 'Session export not implemented. Please extract metadata again.'
        }), 501
        
    except Exception as e:
        logger.error(f"Export error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@exif_bp.route('/analyze-timestamps', methods=['POST'])
def analyze_timestamps():
    """
    Analyze timestamp consistency for forensic purposes
    
    Returns:
        JSON response with timestamp analysis and potential inconsistencies
    """
    try:
        if 'image' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No image file provided'
            }), 400
        
        file = request.files['image']
        
        if file.filename == '' or not allowed_file(file.filename):
            return jsonify({
                'success': False,
                'error': 'Invalid file'
            }), 400
        
        # Create temporary file
        temp_dir = tempfile.gettempdir()
        original_filename = secure_filename(file.filename)
        temp_filename = f"timestamp_{uuid.uuid4()}_{original_filename}"
        temp_path = os.path.join(temp_dir, temp_filename)
        
        try:
            file.save(temp_path)
            
            # Extract metadata
            metadata = extractor.extract_comprehensive_metadata(temp_path)
            
            if 'error' in metadata:
                return jsonify({
                    'success': False,
                    'error': metadata['error']
                }), 500
            
            # Analyze timestamps
            timestamps = metadata.get('timestamps', {})
            file_info = metadata.get('file_info', {})
            
            analysis = {
                'exif_timestamps': timestamps,
                'file_timestamps': {
                    'creation_time': file_info.get('creation_time'),
                    'modification_time': file_info.get('modification_time'),
                    'access_time': file_info.get('access_time')
                },
                'consistency_check': {
                    'total_timestamps': len(timestamps),
                    'unique_timestamps': len(set(timestamps.values())) if timestamps else 0,
                    'has_inconsistencies': len(timestamps) > 0 and len(set(timestamps.values())) != len(timestamps)
                },
                'forensic_notes': []
            }
            
            # Add forensic analysis
            if analysis['consistency_check']['has_inconsistencies']:
                analysis['forensic_notes'].append("⚠️ Multiple EXIF timestamps with different values detected")
            
            if timestamps.get('DateTimeOriginal') != timestamps.get('DateTime'):
                analysis['forensic_notes'].append("ℹ️ Original capture time differs from last modification time")
            
            if not timestamps:
                analysis['forensic_notes'].append("⚠️ No EXIF timestamp data found")
            
            return jsonify({
                'success': True,
                'filename': original_filename,
                'timestamp_analysis': analysis
            })
            
        finally:
            # Clean up
            try:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
            except Exception as e:
                logger.warning(f"Cleanup error: {str(e)}")
    
    except Exception as e:
        logger.error(f"Timestamp analysis error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@exif_bp.route('/extract-gps', methods=['POST'])
def extract_gps_data():
    """
    Extract and process GPS location data from image
    
    Returns:
        JSON response with GPS coordinates, location info, and map links
    """
    try:
        if 'image' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No image file provided'
            }), 400
        
        file = request.files['image']
        
        if file.filename == '' or not allowed_file(file.filename):
            return jsonify({
                'success': False,
                'error': 'Invalid file'
            }), 400
        
        # Create temporary file
        temp_dir = tempfile.gettempdir()
        original_filename = secure_filename(file.filename)
        temp_filename = f"gps_{uuid.uuid4()}_{original_filename}"
        temp_path = os.path.join(temp_dir, temp_filename)
        
        try:
            file.save(temp_path)
            
            # Extract metadata
            metadata = extractor.extract_comprehensive_metadata(temp_path)
            
            if 'error' in metadata:
                return jsonify({
                    'success': False,
                    'error': metadata['error']
                }), 500
            
            # Get GPS data
            gps_data = metadata.get('gps_data', {})
            
            response = {
                'success': True,
                'filename': original_filename,
                'has_gps_data': bool(gps_data),
                'gps_data': gps_data
            }
            
            # Add location analysis
            if gps_data.get('decimal_latitude') and gps_data.get('decimal_longitude'):
                response['location_summary'] = {
                    'coordinates': gps_data.get('coordinates_string'),
                    'google_maps_link': gps_data.get('google_maps_link'),
                    'has_altitude': 'GPSAltitude' in gps_data,
                    'has_timestamp': 'GPSTimeStamp' in gps_data or 'GPSDateStamp' in gps_data,
                    'forensic_value': 'high'  # GPS data is highly valuable for forensics
                }
            else:
                response['location_summary'] = {
                    'forensic_value': 'none',
                    'note': 'No GPS coordinates found in image metadata'
                }
            
            return jsonify(response)
            
        finally:
            # Clean up
            try:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
            except Exception as e:
                logger.warning(f"Cleanup error: {str(e)}")
    
    except Exception as e:
        logger.error(f"GPS extraction error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@exif_bp.route('/camera-info', methods=['POST'])
def extract_camera_info():
    """
    Extract detailed camera and lens information
    
    Returns:
        JSON response with camera make, model, lens info, and capture settings
    """
    try:
        if 'image' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No image file provided'
            }), 400
        
        file = request.files['image']
        
        if file.filename == '' or not allowed_file(file.filename):
            return jsonify({
                'success': False,
                'error': 'Invalid file'
            }), 400
        
        # Create temporary file
        temp_dir = tempfile.gettempdir()
        original_filename = secure_filename(file.filename)
        temp_filename = f"camera_{uuid.uuid4()}_{original_filename}"
        temp_path = os.path.join(temp_dir, temp_filename)
        
        try:
            file.save(temp_path)
            
            # Extract metadata
            metadata = extractor.extract_comprehensive_metadata(temp_path)
            
            if 'error' in metadata:
                return jsonify({
                    'success': False,
                    'error': metadata['error']
                }), 500
            
            # Get camera and capture information
            camera_info = metadata.get('camera_info', {})
            capture_settings = metadata.get('capture_settings', {})
            
            # Organize camera data
            camera_data = {
                'camera_identification': {
                    'make': camera_info.get('Make', 'Unknown'),
                    'model': camera_info.get('Model', 'Unknown'),
                    'serial_number': camera_info.get('SerialNumber') or camera_info.get('BodySerialNumber'),
                    'lens_model': camera_info.get('LensModel'),
                    'lens_make': camera_info.get('LensMake'),
                    'lens_serial': camera_info.get('LensSerialNumber')
                },
                'capture_settings': {
                    'exposure_time': capture_settings.get('ExposureTime'),
                    'f_number': capture_settings.get('FNumber'),
                    'iso': capture_settings.get('ISO') or capture_settings.get('ISOSpeedRatings'),
                    'focal_length': capture_settings.get('FocalLength'),
                    'flash': capture_settings.get('Flash'),
                    'white_balance': capture_settings.get('WhiteBalance'),
                    'metering_mode': capture_settings.get('MeteringMode'),
                    'exposure_mode': capture_settings.get('ExposureMode')
                },
                'technical_details': metadata.get('technical_info', {}),
                'forensic_assessment': {
                    'camera_identified': bool(camera_info.get('Make') and camera_info.get('Model')),
                    'professional_equipment': self._assess_equipment_type(camera_info, capture_settings),
                    'metadata_completeness': self._assess_metadata_completeness(metadata)
                }
            }
            
            return jsonify({
                'success': True,
                'filename': original_filename,
                'camera_data': camera_data
            })
            
        finally:
            # Clean up
            try:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
            except Exception as e:
                logger.warning(f"Cleanup error: {str(e)}")
    
    except Exception as e:
        logger.error(f"Camera info extraction error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


def _assess_equipment_type(camera_info, capture_settings):
    """Assess if equipment appears to be professional grade"""
    make = camera_info.get('Make', '').lower()
    model = camera_info.get('Model', '').lower()
    
    professional_indicators = [
        'canon eos' in f"{make} {model}",
        'nikon d' in f"{make} {model}",
        'sony a7' in f"{make} {model}",
        'professional' in model,
        'pro' in model,
        camera_info.get('LensModel') is not None,
        capture_settings.get('ExposureMode') == 'Manual'
    ]
    
    return sum(professional_indicators) >= 2


def _assess_metadata_completeness(metadata):
    """Assess how complete the metadata is"""
    essential_fields = [
        metadata.get('camera_info', {}).get('Make'),
        metadata.get('camera_info', {}).get('Model'),
        metadata.get('timestamps', {}).get('DateTimeOriginal'),
        metadata.get('capture_settings', {}).get('ExposureTime'),
        metadata.get('capture_settings', {}).get('FNumber')
    ]
    
    completeness = sum(1 for field in essential_fields if field) / len(essential_fields)
    
    if completeness >= 0.8:
        return 'high'
    elif completeness >= 0.5:
        return 'medium'
    else:
        return 'low'


# Error handlers
@exif_bp.errorhandler(413)
def too_large(error):
    """Handle file too large error"""
    return jsonify({
        'success': False,
        'error': f'File too large. Maximum size: {MAX_FILE_SIZE // (1024*1024)}MB'
    }), 413


@exif_bp.errorhandler(415)
def unsupported_media_type(error):
    """Handle unsupported media type error"""
    return jsonify({
        'success': False,
        'error': 'Unsupported file type. Please upload a valid image file.'
    }), 415