"""
Hex Viewer API - Flask endpoints for byte-level file analysis
===========================================================

Provides RESTful API endpoints for:
- File hex analysis and visualization
- Byte pattern searching
- File comparison at binary level
- Anomaly detection in file structure
- Hash calculation and validation
"""

from flask import Blueprint, request, jsonify, current_app
import os
import tempfile
from werkzeug.utils import secure_filename
from forensics.hex_analyzer import HexAnalyzer
import logging

# Create blueprint
hex_viewer_bp = Blueprint('hex_viewer', __name__)

# Initialize analyzer
hex_analyzer = HexAnalyzer()

# Configure logging
logger = logging.getLogger(__name__)

# Allowed file extensions (all types for forensic analysis)
ALLOWED_EXTENSIONS = {
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp', 'ico',  # Images
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',        # Documents
    'exe', 'dll', 'sys', 'bin',                                 # Executables
    'zip', 'rar', '7z', 'tar', 'gz',                           # Archives
    'mp3', 'mp4', 'avi', 'mov', 'wav',                         # Media
    'txt', 'log', 'xml', 'json', 'csv',                        # Text
    'dat', 'tmp', 'bak'                                         # Generic/Unknown
}

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB limit for hex analysis

def allowed_file(filename):
    """Check if file extension is allowed"""
    if '.' not in filename:
        return True  # Allow files without extensions for forensic analysis
    return filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@hex_viewer_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'Hex Viewer API',
        'version': '1.0.0'
    }), 200

@hex_viewer_bp.route('/info', methods=['GET'])
def get_info():
    """Get API information and supported features"""
    return jsonify({
        'service': 'Hex Viewer & Byte-Level Inspector',
        'version': '1.0.0',
        'description': 'Advanced binary file analysis for digital forensics',
        'supported_features': [
            'Hex dump generation with ASCII representation',
            'File signature detection and validation',
            'Byte pattern analysis and frequency statistics',
            'String extraction (ASCII and Unicode)',
            'Entropy calculation and randomness analysis',
            'File structure analysis (JPEG, PNG, PDF)',
            'Anomaly detection and security analysis',
            'Pattern searching (hex and ASCII)',
            'Binary file comparison',
            'Hash calculation (MD5, SHA1, SHA256)'
        ],
        'supported_formats': list(ALLOWED_EXTENSIONS),
        'max_file_size_mb': MAX_FILE_SIZE // (1024 * 1024),
        'endpoints': {
            '/analyze': 'Comprehensive hex analysis of uploaded file',
            '/search': 'Search for patterns in uploaded file',
            '/compare': 'Compare two files at byte level',
            '/file-info': 'Get basic file information and signatures'
        }
    }), 200

@hex_viewer_bp.route('/analyze', methods=['POST'])
def analyze_file():
    """Perform comprehensive hex analysis on uploaded file"""
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed for analysis'}), 400
        
        # Check file size
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        if file_size > MAX_FILE_SIZE:
            return jsonify({
                'error': f'File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB'
            }), 400
        
        if file_size == 0:
            return jsonify({'error': 'Empty file'}), 400
        
        # Get analysis parameters
        max_bytes = min(int(request.form.get('max_bytes', 1024*1024)), MAX_FILE_SIZE)
        include_strings = request.form.get('include_strings', 'true').lower() == 'true'
        include_structure = request.form.get('include_structure', 'true').lower() == 'true'
        hex_lines = min(int(request.form.get('hex_lines', 100)), 1000)
        
        # Save file temporarily
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            filename = secure_filename(file.filename)
            file.save(tmp_file.name)
            tmp_path = tmp_file.name
        
        try:
            # Perform analysis
            logger.info(f"Starting hex analysis of file: {filename} ({file_size} bytes)")
            
            analysis_result = hex_analyzer.analyze_file(tmp_path, max_bytes=max_bytes)
            
            # Customize result based on parameters
            if not include_strings:
                analysis_result.pop('string_analysis', None)
                
            if not include_structure:
                analysis_result.pop('structure_analysis', None)
            
            # Limit hex dump lines
            if 'hex_dump' in analysis_result:
                hex_dump = analysis_result['hex_dump']
                if len(hex_dump.get('lines', [])) > hex_lines:
                    hex_dump['lines'] = hex_dump['lines'][:hex_lines]
                    hex_dump['is_truncated'] = True
            
            # Add request metadata
            analysis_result['analysis_metadata'] = {
                'original_filename': filename,
                'analysis_timestamp': None,
                'max_bytes_analyzed': max_bytes,
                'full_file_analyzed': file_size <= max_bytes,
                'parameters': {
                    'include_strings': include_strings,
                    'include_structure': include_structure,
                    'hex_lines': hex_lines
                }
            }
            
            logger.info(f"Hex analysis completed for file: {filename}")
            return jsonify(analysis_result), 200
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(tmp_path)
            except OSError:
                logger.warning(f"Could not delete temporary file: {tmp_path}")
    
    except Exception as e:
        logger.error(f"Error in hex analysis: {str(e)}")
        return jsonify({
            'error': f'Analysis failed: {str(e)}',
            'details': 'An error occurred during hex analysis'
        }), 500

@hex_viewer_bp.route('/search', methods=['POST'])
def search_pattern():
    """Search for specific patterns in uploaded file"""
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Get search parameters
        pattern = request.form.get('pattern', '').strip()
        search_type = request.form.get('search_type', 'hex').lower()
        
        if not pattern:
            return jsonify({'error': 'No search pattern provided'}), 400
        
        if search_type not in ['hex', 'ascii']:
            return jsonify({'error': 'Invalid search type. Use "hex" or "ascii"'}), 400
        
        # Validate file
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed for analysis'}), 400
        
        # Check file size
        file.seek(0, 2)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > MAX_FILE_SIZE:
            return jsonify({
                'error': f'File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB'
            }), 400
        
        # Save file temporarily
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            filename = secure_filename(file.filename)
            file.save(tmp_file.name)
            tmp_path = tmp_file.name
        
        try:
            # Perform pattern search
            logger.info(f"Searching for pattern '{pattern}' ({search_type}) in file: {filename}")
            
            search_result = hex_analyzer.search_pattern(tmp_path, pattern, search_type)
            
            # Add metadata
            search_result['search_metadata'] = {
                'original_filename': filename,
                'file_size': file_size,
                'search_timestamp': None
            }
            
            logger.info(f"Pattern search completed: {search_result.get('matches_found', 0)} matches found")
            return jsonify(search_result), 200
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(tmp_path)
            except OSError:
                logger.warning(f"Could not delete temporary file: {tmp_path}")
    
    except Exception as e:
        logger.error(f"Error in pattern search: {str(e)}")
        return jsonify({
            'error': f'Pattern search failed: {str(e)}',
            'details': 'An error occurred during pattern search'
        }), 500

@hex_viewer_bp.route('/compare', methods=['POST'])
def compare_files():
    """Compare two files at byte level"""
    try:
        # Check if both files are present
        if 'file1' not in request.files or 'file2' not in request.files:
            return jsonify({'error': 'Two files required for comparison'}), 400
        
        file1 = request.files['file1']
        file2 = request.files['file2']
        
        if file1.filename == '' or file2.filename == '':
            return jsonify({'error': 'Both files must be selected'}), 400
        
        # Validate files
        if not allowed_file(file1.filename) or not allowed_file(file2.filename):
            return jsonify({'error': 'File type not allowed for analysis'}), 400
        
        # Check file sizes
        file1.seek(0, 2)
        file1_size = file1.tell()
        file1.seek(0)
        
        file2.seek(0, 2)
        file2_size = file2.tell()
        file2.seek(0)
        
        if file1_size > MAX_FILE_SIZE or file2_size > MAX_FILE_SIZE:
            return jsonify({
                'error': f'File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB'
            }), 400
        
        # Save files temporarily
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file1, \
             tempfile.NamedTemporaryFile(delete=False) as tmp_file2:
            
            filename1 = secure_filename(file1.filename)
            filename2 = secure_filename(file2.filename)
            
            file1.save(tmp_file1.name)
            file2.save(tmp_file2.name)
            
            tmp_path1 = tmp_file1.name
            tmp_path2 = tmp_file2.name
        
        try:
            # Perform comparison
            logger.info(f"Comparing files: {filename1} vs {filename2}")
            
            comparison_result = hex_analyzer.compare_files(tmp_path1, tmp_path2)
            
            # Add metadata
            comparison_result['comparison_metadata'] = {
                'file1_name': filename1,
                'file2_name': filename2,
                'comparison_timestamp': None
            }
            
            logger.info(f"File comparison completed: {comparison_result.get('similarity_percentage', 0):.1f}% similarity")
            return jsonify(comparison_result), 200
            
        finally:
            # Clean up temporary files
            for tmp_path in [tmp_path1, tmp_path2]:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    logger.warning(f"Could not delete temporary file: {tmp_path}")
    
    except Exception as e:
        logger.error(f"Error in file comparison: {str(e)}")
        return jsonify({
            'error': f'File comparison failed: {str(e)}',
            'details': 'An error occurred during file comparison'
        }), 500

@hex_viewer_bp.route('/file-info', methods=['POST'])
def get_file_info():
    """Get basic file information and signatures"""
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed for analysis'}), 400
        
        # Check file size
        file.seek(0, 2)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > MAX_FILE_SIZE:
            return jsonify({
                'error': f'File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB'
            }), 400
        
        # Read first 1KB for signature analysis
        header_data = file.read(min(1024, file_size))
        file.seek(0)
        
        # Save file temporarily for hash calculation
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            filename = secure_filename(file.filename)
            file.save(tmp_file.name)
            tmp_path = tmp_file.name
        
        try:
            # Analyze file signature
            signature_info = hex_analyzer._analyze_file_signature(header_data)
            
            # Calculate hashes
            with open(tmp_path, 'rb') as f:
                full_data = f.read()
            hash_info = hex_analyzer._calculate_hashes(full_data)
            
            # Basic file info
            file_info = {
                'filename': filename,
                'file_size': file_size,
                'file_extension': os.path.splitext(filename)[1].lower(),
                'signature_analysis': signature_info,
                'hashes': hash_info,
                'header_preview': {
                    'hex': header_data[:32].hex().upper(),
                    'ascii': hex_analyzer._bytes_to_ascii(header_data[:32])
                }
            }
            
            logger.info(f"File info retrieved for: {filename}")
            return jsonify(file_info), 200
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(tmp_path)
            except OSError:
                logger.warning(f"Could not delete temporary file: {tmp_path}")
    
    except Exception as e:
        logger.error(f"Error getting file info: {str(e)}")
        return jsonify({
            'error': f'File info retrieval failed: {str(e)}',
            'details': 'An error occurred while getting file information'
        }), 500

@hex_viewer_bp.route('/supported-formats', methods=['GET'])
def get_supported_formats():
    """Get list of supported file formats"""
    return jsonify({
        'supported_extensions': sorted(list(ALLOWED_EXTENSIONS)),
        'categories': {
            'images': ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp', 'ico'],
            'documents': ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'],
            'executables': ['exe', 'dll', 'sys', 'bin'],
            'archives': ['zip', 'rar', '7z', 'tar', 'gz'],
            'media': ['mp3', 'mp4', 'avi', 'mov', 'wav'],
            'text': ['txt', 'log', 'xml', 'json', 'csv'],
            'generic': ['dat', 'tmp', 'bak']
        },
        'max_file_size_mb': MAX_FILE_SIZE // (1024 * 1024),
        'note': 'Files without extensions are also accepted for forensic analysis'
    }), 200

# Error handlers
@hex_viewer_bp.errorhandler(413)
def file_too_large(error):
    return jsonify({
        'error': 'File too large',
        'max_size_mb': MAX_FILE_SIZE // (1024 * 1024)
    }), 413

@hex_viewer_bp.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request'}), 400

@hex_viewer_bp.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500