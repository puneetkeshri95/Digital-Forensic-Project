"""
File management API endpoints
"""
from flask import Blueprint, request, jsonify, current_app, send_from_directory
import os
import shutil
import logging
from datetime import datetime

file_bp = Blueprint('files', __name__)
logger = logging.getLogger(__name__)

@file_bp.route('/upload', methods=['POST'])
def upload_file():
    """Upload evidence file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file type
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        # Save file
        filename = secure_filename(file.filename)
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        logger.info(f'File uploaded: {filename}')
        
        return jsonify({
            'success': True,
            'filename': filename,
            'size': os.path.getsize(file_path),
            'upload_time': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f'Error uploading file: {str(e)}')
        return jsonify({'error': 'Upload failed'}), 500

@file_bp.route('/list', methods=['GET'])
def list_files():
    """List all uploaded files"""
    try:
        upload_folder = current_app.config['UPLOAD_FOLDER']
        files = []
        
        for filename in os.listdir(upload_folder):
            file_path = os.path.join(upload_folder, filename)
            if os.path.isfile(file_path):
                files.append({
                    'filename': filename,
                    'size': os.path.getsize(file_path),
                    'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                })
        
        return jsonify({'files': files})
        
    except Exception as e:
        logger.error(f'Error listing files: {str(e)}')
        return jsonify({'error': 'Failed to list files'}), 500

@file_bp.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    """Download file"""
    try:
        return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except Exception as e:
        logger.error(f'Error downloading file {filename}: {str(e)}')
        return jsonify({'error': 'Download failed'}), 500

@file_bp.route('/delete/<filename>', methods=['DELETE'])
def delete_file(filename):
    """Delete file"""
    try:
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f'File deleted: {filename}')
            return jsonify({'success': True, 'message': f'File {filename} deleted'})
        else:
            return jsonify({'error': 'File not found'}), 404
            
    except Exception as e:
        logger.error(f'Error deleting file {filename}: {str(e)}')
        return jsonify({'error': 'Delete failed'}), 500

def allowed_file(filename):
    """Check if file extension is allowed"""
    if '.' not in filename:
        return False
    
    ext = filename.rsplit('.', 1)[1].lower()
    allowed_extensions = set()
    
    # Flatten all allowed extensions
    config_extensions = current_app.config.get('ALLOWED_EXTENSIONS', {})
    for category in config_extensions.values():
        allowed_extensions.update(category)
    
    return ext in allowed_extensions

def secure_filename(filename):
    """Secure filename for saving"""
    import re
    filename = re.sub(r'[^\w\-_\.]', '_', filename)
    return filename