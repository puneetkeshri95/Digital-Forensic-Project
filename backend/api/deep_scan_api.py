"""
Deep Scan API endpoints for low-level sector scanning
"""
from flask import Blueprint, request, jsonify, current_app, send_file
import os
import logging
import threading
import uuid
import base64
import mimetypes
from datetime import datetime
# Try to import full forensic scanner, fallback to demo version
try:
    # Test if pytsk3 is available
    import pytsk3
    from utils.deep_scanner import DeepScanner
    FORENSIC_LIBS_AVAILABLE = True
    print("INFO: Full forensic scanner available with pytsk3 and pyewf support")
except ImportError as e:
    # Fallback to demo version if forensic libraries are not installed
    try:
        from utils.deep_scanner_demo import DeepScanner
        FORENSIC_LIBS_AVAILABLE = False
        print("WARNING: pytsk3 not available - using demo deep scanner. Install Microsoft Visual C++ Build Tools and pytsk3 for full functionality")
        print(f"   Installation guide: pip install pytsk3 (requires Visual C++ 14.0+)")
    except ImportError:
        # Create a minimal scanner if even demo is not available
        from utils.deep_scanner import DeepScanner
        FORENSIC_LIBS_AVAILABLE = False
        print("WARNING: Using deep scanner with limited functionality - pytsk3 import failed")
import json

deep_scan_bp = Blueprint('deep_scan', __name__)
logger = logging.getLogger(__name__)

# Global storage for scan sessions
active_scans = {}
scan_results = {}
scan_sessions = {}

class ScanSession:
    """Manages a deep scan session"""
    
    def __init__(self, session_id: str, image_path: str, scan_options: dict):
        self.session_id = session_id
        self.image_path = image_path
        self.scan_options = scan_options
        self.scanner = DeepScanner()
        self.status = "initializing"
        self.progress = 0
        self.files_found = 0
        self.current_activity = "Preparing scan..."
        self.start_time = datetime.now()
        self.results = []
        self.statistics = {}
        self.error = None
        self.thread = None
    
    def start_scan(self):
        """Start the scanning process in a separate thread"""
        self.thread = threading.Thread(target=self._run_scan)
        self.thread.daemon = True
        self.thread.start()
    
    def _run_scan(self):
        """Execute the deep scan"""
        try:
            self.status = "scanning"
            self.current_activity = "Analyzing disk image structure..."
            
            # Extract file types from scan options
            file_types = []
            if self.scan_options.get('scan_images', True):
                file_types.extend(['jpg', 'png', 'gif', 'bmp'])
            if self.scan_options.get('scan_documents', True):
                file_types.extend(['pdf', 'docx', 'xlsx', 'pptx'])
            if self.scan_options.get('scan_archives', True):
                file_types.extend(['zip', 'rar'])
            if self.scan_options.get('scan_media', True):
                file_types.extend(['mp3', 'mp4', 'avi'])
            
            # Perform deep scan
            for update in self.scanner.scan_disk_image(self.image_path, file_types):
                if "error" in update:
                    self.status = "error"
                    self.error = update["error"]
                    break
                
                if update.get("status") == "started":
                    self.current_activity = f"Scanning {update.get('total_sectors', 0)} sectors..."
                
                elif update.get("status") == "scanning_volume":
                    volume_num = update.get("volume", 1)
                    total_volumes = update.get("total_volumes", 1)
                    self.current_activity = f"Scanning volume {volume_num} of {total_volumes}..."
                
                elif update.get("status") == "progress":
                    self.progress = update.get("progress", 0)
                    current_sector = update.get("current_sector", 0)
                    total_sectors = update.get("total_sectors", 1)
                    self.current_activity = f"Scanning sector {current_sector:,} of {total_sectors:,}..."
                
                elif update.get("status") == "file_found":
                    file_info = update.get("file", {})
                    self.results.append(file_info)
                    self.files_found += 1
                    self.progress = update.get("progress", self.progress)
                    self.current_activity = f"Found {file_info.get('file_type', 'file')}: {file_info.get('filename', 'unknown')}"
                
                elif update.get("status") == "completed":
                    self.status = "completed"
                    self.progress = 100
                    self.current_activity = f"Scan completed. Found {len(self.results)} files."
                    self.statistics = self.scanner.get_scan_statistics()
                    break
            
            if self.status == "scanning":  # No completion update received
                self.status = "completed"
                self.progress = 100
                self.current_activity = f"Scan completed. Found {len(self.results)} files."
                self.statistics = self.scanner.get_scan_statistics()
                
        except Exception as e:
            logger.error(f"Deep scan error in session {self.session_id}: {e}")
            self.status = "error"
            self.error = str(e)
            self.current_activity = f"Scan failed: {str(e)}"
    
    def get_status(self):
        """Get current scan status"""
        return {
            "session_id": self.session_id,
            "status": self.status,
            "progress": round(self.progress, 2),
            "files_found": self.files_found,
            "current_activity": self.current_activity,
            "start_time": self.start_time.isoformat(),
            "elapsed_time": (datetime.now() - self.start_time).total_seconds(),
            "error": self.error,
            "statistics": self.statistics
        }
    
    def get_results(self, page: int = 1, per_page: int = 50, file_type_filter: str = None, search_query: str = None):
        """Get scan results with pagination and filtering"""
        filtered_results = self.results.copy()
        
        # Apply file type filter
        if file_type_filter and file_type_filter != "all":
            filtered_results = [r for r in filtered_results if r.get("file_type", "").lower() == file_type_filter.lower()]
        
        # Apply search filter
        if search_query:
            search_query = search_query.lower()
            filtered_results = [r for r in filtered_results if search_query in r.get("filename", "").lower()]
        
        # Calculate pagination
        total_results = len(filtered_results)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        page_results = filtered_results[start_idx:end_idx]
        
        return {
            "results": page_results,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total_results,
                "pages": (total_results + per_page - 1) // per_page
            },
            "filters": {
                "file_type": file_type_filter,
                "search_query": search_query
            }
        }

@deep_scan_bp.route('/start-scan', methods=['POST'])
def start_deep_scan():
    """Start a new deep scan session"""
    try:
        data = request.get_json()
        
        # Validate required parameters
        if not data or 'image_path' not in data:
            return jsonify({"error": "Missing required parameter: image_path"}), 400
        
        image_path = data['image_path']
        
        # Validate image file exists
        if not os.path.exists(image_path):
            return jsonify({"error": f"Image file not found: {image_path}"}), 404
        
        # Validate file extension
        valid_extensions = ['.img', '.dd', '.raw', '.e01', '.ex01', '.ad1']
        if not any(image_path.lower().endswith(ext) for ext in valid_extensions):
            return jsonify({"error": "Unsupported image format. Supported: .img, .dd, .raw, .e01, .ex01, .ad1"}), 400
        
        # Extract scan options
        scan_options = data.get('scan_options', {})
        default_options = {
            'scan_type': 'deep',
            'scan_images': True,
            'scan_documents': True,
            'scan_archives': True,
            'scan_media': True,
            'deleted_files_only': True
        }
        scan_options = {**default_options, **scan_options}
        
        # Create new scan session
        session_id = str(uuid.uuid4())
        session = ScanSession(session_id, image_path, scan_options)
        
        # Store session
        active_scans[session_id] = session
        
        # Start scanning
        session.start_scan()
        
        logger.info(f"Started deep scan session {session_id} for image: {image_path}")
        
        return jsonify({
            "status": "success",
            "session_id": session_id,
            "message": "Deep scan started successfully",
            "scan_options": scan_options
        })
        
    except Exception as e:
        logger.error(f"Error starting deep scan: {e}")
        return jsonify({"error": f"Failed to start scan: {str(e)}"}), 500

@deep_scan_bp.route('/scan-status/<session_id>', methods=['GET'])
def get_scan_status(session_id):
    """Get status of a running scan"""
    try:
        if session_id not in active_scans:
            return jsonify({"error": "Scan session not found"}), 404
        
        session = active_scans[session_id]
        return jsonify(session.get_status())
        
    except Exception as e:
        logger.error(f"Error getting scan status: {e}")
        return jsonify({"error": str(e)}), 500

@deep_scan_bp.route('/scan-results/<session_id>', methods=['GET'])
def get_scan_results(session_id):
    """Get results from completed scan"""
    try:
        if session_id not in active_scans:
            return jsonify({"error": "Scan session not found"}), 404
        
        session = active_scans[session_id]
        
        # Get query parameters
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        file_type_filter = request.args.get('file_type', 'all')
        search_query = request.args.get('search', '')
        
        results = session.get_results(page, per_page, file_type_filter, search_query)
        
        return jsonify({
            "status": "success",
            "session_id": session_id,
            "scan_status": session.status,
            **results
        })
        
    except Exception as e:
        logger.error(f"Error getting scan results: {e}")
        return jsonify({"error": str(e)}), 500

@deep_scan_bp.route('/recover-file/<session_id>/<file_id>', methods=['POST'])
def recover_file(session_id, file_id):
    """Recover a specific file from scan results"""
    try:
        if session_id not in active_scans:
            return jsonify({"error": "Scan session not found"}), 404
        
        session = active_scans[session_id]
        
        # Find the file
        target_file = next((f for f in session.results if f.get("id") == file_id), None)
        if not target_file:
            return jsonify({"error": "File not found in scan results"}), 404
        
        # Create recovery directory
        recovery_dir = os.path.join(current_app.config.get('RECOVERED_FILES_FOLDER', '../recovered_files'), session_id)
        os.makedirs(recovery_dir, exist_ok=True)
        
        # Generate output path
        output_filename = target_file.get("filename", f"recovered_{file_id}")
        output_path = os.path.join(recovery_dir, output_filename)
        
        # Save the file
        success = session.scanner.save_recovered_file(file_id, output_path)
        
        if success:
            return jsonify({
                "status": "success",
                "message": "File recovered successfully",
                "output_path": output_path,
                "filename": output_filename
            })
        else:
            return jsonify({"error": "Failed to recover file"}), 500
            
    except Exception as e:
        logger.error(f"Error recovering file: {e}")
        return jsonify({"error": str(e)}), 500

@deep_scan_bp.route('/recover-selected/<session_id>', methods=['POST'])
def recover_selected_files(session_id):
    """Recover multiple selected files"""
    try:
        if session_id not in active_scans:
            return jsonify({"error": "Scan session not found"}), 404
        
        data = request.get_json()
        file_ids = data.get('file_ids', [])
        
        if not file_ids:
            return jsonify({"error": "No files selected for recovery"}), 400
        
        session = active_scans[session_id]
        recovery_dir = os.path.join(current_app.config.get('RECOVERED_FILES_FOLDER', '../recovered_files'), session_id)
        os.makedirs(recovery_dir, exist_ok=True)
        
        recovered_files = []
        failed_files = []
        
        for file_id in file_ids:
            target_file = next((f for f in session.results if f.get("id") == file_id), None)
            if target_file:
                output_filename = target_file.get("filename", f"recovered_{file_id}")
                output_path = os.path.join(recovery_dir, output_filename)
                
                if session.scanner.save_recovered_file(file_id, output_path):
                    recovered_files.append({
                        "file_id": file_id,
                        "filename": output_filename,
                        "path": output_path
                    })
                else:
                    failed_files.append(file_id)
            else:
                failed_files.append(file_id)
        
        return jsonify({
            "status": "success",
            "recovered_count": len(recovered_files),
            "failed_count": len(failed_files),
            "recovered_files": recovered_files,
            "failed_files": failed_files,
            "recovery_directory": recovery_dir
        })
        
    except Exception as e:
        logger.error(f"Error recovering selected files: {e}")
        return jsonify({"error": str(e)}), 500

@deep_scan_bp.route('/scan-sessions', methods=['GET'])
def list_scan_sessions():
    """List all active scan sessions"""
    try:
        sessions = []
        for session_id, session in active_scans.items():
            sessions.append({
                "session_id": session_id,
                "image_path": session.image_path,
                "status": session.status,
                "files_found": session.files_found,
                "start_time": session.start_time.isoformat(),
                "elapsed_time": (datetime.now() - session.start_time).total_seconds()
            })
        
        return jsonify({
            "status": "success",
            "active_sessions": len(sessions),
            "sessions": sessions
        })
        
    except Exception as e:
        logger.error(f"Error listing scan sessions: {e}")
        return jsonify({"error": str(e)}), 500

@deep_scan_bp.route('/cancel-scan/<session_id>', methods=['POST'])
def cancel_scan(session_id):
    """Cancel a running scan"""
    try:
        if session_id not in active_scans:
            return jsonify({"error": "Scan session not found"}), 404
        
        session = active_scans[session_id]
        session.status = "cancelled"
        session.current_activity = "Scan cancelled by user"
        
        # Note: Thread cancellation is complex in Python, so we just mark as cancelled
        # The scanning thread will continue but results won't be processed
        
        return jsonify({
            "status": "success",
            "message": "Scan cancelled successfully"
        })
        
    except Exception as e:
        logger.error(f"Error cancelling scan: {e}")
        return jsonify({"error": str(e)}), 500

@deep_scan_bp.route('/supported-formats', methods=['GET'])
def get_supported_formats():
    """Get list of supported disk image formats and file types"""
    return jsonify({
        "status": "success",
        "disk_image_formats": [
            {"extension": ".img", "description": "Raw disk image"},
            {"extension": ".dd", "description": "Raw disk dump"},
            {"extension": ".raw", "description": "Raw disk image"},
            {"extension": ".e01", "description": "Expert Witness Format (EnCase)"},
            {"extension": ".ex01", "description": "Expert Witness Format (Extended)"},
            {"extension": ".ad1", "description": "AccessData Forensic Image"}
        ],
        "recoverable_file_types": [
            {"type": "Images", "extensions": ["jpg", "jpeg", "png", "gif", "bmp"]},
            {"type": "Documents", "extensions": ["pdf", "docx", "xlsx", "pptx"]},
            {"type": "Archives", "extensions": ["zip", "rar"]},
            {"type": "Media", "extensions": ["mp3", "mp4", "avi"]}
        ]
    })

@deep_scan_bp.route('/carve/<session_id>', methods=['POST'])
def start_file_carving(session_id):
    """Start file carving process for a session"""
    try:
        if session_id not in scan_sessions:
            return jsonify({'error': 'Session not found'}), 404
            
        session = scan_sessions[session_id]
        data = request.get_json()
        
        if not data or 'device_path' not in data:
            return jsonify({'error': 'Device path required'}), 400
            
        device_path = data['device_path']
        
        # Check if scanner supports carving
        scanner = session.scanner
        if not hasattr(scanner, 'carve_files'):
            return jsonify({'error': 'File carving not supported by this scanner'}), 400
        
        # Start carving in background thread
        def carving_worker():
            try:
                session.status = 'carving'
                carved_files = scanner.carve_files(device_path)
                session.carved_files = carved_files
                session.carving_results = scanner.get_carved_files_info()
                session.status = 'carving_completed'
                logger.info(f"File carving completed for session {session_id}: {len(carved_files)} files carved")
            except Exception as e:
                logger.error(f"File carving error: {e}")
                session.status = 'carving_error'
                session.error = str(e)
        
        thread = threading.Thread(target=carving_worker, daemon=True)
        thread.start()
        session.carving_thread = thread
        
        return jsonify({
            'message': 'File carving started',
            'session_id': session_id,
            'status': 'carving'
        })
        
    except Exception as e:
        logger.error(f"Error starting file carving: {e}")
        return jsonify({'error': str(e)}), 500

@deep_scan_bp.route('/carve-results/<session_id>', methods=['GET'])
def get_carving_results(session_id):
    """Get file carving results for a session"""
    try:
        if session_id not in scan_sessions:
            return jsonify({'error': 'Session not found'}), 404
            
        session = scan_sessions[session_id]
        
        results = {
            'session_id': session_id,
            'status': session.status,
            'carved_files': getattr(session, 'carved_files', []),
            'carving_results': getattr(session, 'carving_results', {}),
            'error': getattr(session, 'error', None)
        }
        
        # Format carved files for API response
        if results['carved_files']:
            formatted_files = []
            for cf in results['carved_files']:
                if hasattr(cf, '__dict__'):
                    # Convert CarvedFile object to dict
                    file_dict = {
                        'filename': getattr(cf, 'filename', 'unknown'),
                        'filepath': getattr(cf, 'recovery_path', ''),
                        'size': getattr(cf, 'file_size', 0),
                        'file_type': getattr(cf, 'file_type', 'Unknown'),
                        'signature': getattr(cf, 'signature', ''),
                        'md5_hash': getattr(cf, 'md5_hash', ''),
                        'sha256_hash': getattr(cf, 'sha256_hash', ''),
                        'offset': getattr(cf, 'offset', 0),
                        'confidence': getattr(cf, 'confidence', 0.0),
                        'recovery_time': getattr(cf, 'recovery_time', None)
                    }
                    if file_dict['recovery_time']:
                        file_dict['recovery_time'] = file_dict['recovery_time'].isoformat()
                    formatted_files.append(file_dict)
                else:
                    # Already a dict
                    formatted_files.append(cf)
            results['carved_files'] = formatted_files
        
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Error getting carving results: {e}")
        return jsonify({'error': str(e)}), 500

@deep_scan_bp.route('/scan-with-carving', methods=['POST'])
def start_comprehensive_scan():
    """Start a comprehensive scan with both deep scan and file carving"""
    try:
        data = request.get_json()
        
        if not data or 'image_path' not in data:
            return jsonify({'error': 'Image path required'}), 400
            
        image_path = data['image_path']
        scan_mode = data.get('scan_mode', 'quick')
        enable_carving = data.get('enable_carving', True)
        
        # Create new session
        session_id = str(uuid.uuid4())
        
        # Extract scan options
        scan_options = data.get('scan_options', {})
        default_options = {
            'scan_type': 'deep',
            'scan_images': True,
            'scan_documents': True,
            'scan_archives': True,
            'scan_media': True,
            'deleted_files_only': True,
            'enable_carving': enable_carving
        }
        scan_options = {**default_options, **scan_options}
        
        # Create session with carving enabled
        session = ScanSession(session_id, image_path, scan_options)
        session.enable_carving = enable_carving
        session.carved_files = []
        session.carving_results = {}
        
        # Store session
        scan_sessions[session_id] = session
        
        # Start comprehensive scan in background
        def comprehensive_scan_worker():
            try:
                session.status = 'scanning'
                session.start_time = datetime.now()
                
                # Initialize scanner with carving
                scanner = DeepScanner(enable_carving=enable_carving)
                session.scanner = scanner
                
                # Perform scan with carving
                if hasattr(scanner, 'scan_with_carving'):
                    results = scanner.scan_with_carving(image_path, scan_mode)
                    session.results = results
                    session.carved_files = results.get('carved_files', [])
                    session.carving_results = results.get('carving_results', {})
                else:
                    # Fallback to regular scan
                    results = {'scan_results': None, 'carved_files': [], 'carving_results': {}}
                    for update in scanner.scan_disk_image(image_path):
                        if 'status' in update and update['status'] == 'completed':
                            results['scan_results'] = update
                            break
                    session.results = results
                
                session.status = 'completed'
                session.end_time = datetime.now()
                
                logger.info(f"Comprehensive scan completed for session {session_id}")
                
            except Exception as e:
                logger.error(f"Comprehensive scan error: {e}")
                session.status = 'error'
                session.error_message = str(e)
                session.end_time = datetime.now()
        
        thread = threading.Thread(target=comprehensive_scan_worker, daemon=True)
        thread.start()
        session.thread = thread
        
        return jsonify({
            'message': 'Comprehensive scan started',
            'session_id': session_id,
            'image_path': image_path,
            'scan_mode': scan_mode,
            'carving_enabled': enable_carving
        })
        
    except Exception as e:
        logger.error(f"Error starting comprehensive scan: {e}")
        return jsonify({'error': str(e)}), 500

@deep_scan_bp.route('/recovered-files/<session_id>', methods=['GET'])
def get_recovered_files_list(session_id):
    """Get detailed list of recovered files for DataTables display"""
    try:
        if session_id not in scan_sessions:
            return jsonify({'error': 'Session not found'}), 404
            
        session = scan_sessions[session_id]
        
        # Get query parameters for DataTables
        draw = request.args.get('draw', type=int, default=1)
        start = request.args.get('start', type=int, default=0)
        length = request.args.get('length', type=int, default=25)
        search_value = request.args.get('search[value]', default='')
        
        # Get files from session results
        files = []
        if hasattr(session, 'results') and session.results:
            scan_results = session.results.get('scan_results', {})
            files.extend(scan_results.get('files', []))
            
            carved_files = session.results.get('carved_files', [])
            for carved_file in carved_files:
                files.append({
                    'id': carved_file.get('filename', 'unknown'),
                    'filename': carved_file.get('filename', 'unknown'),
                    'filepath': carved_file.get('filepath', ''),
                    'size': carved_file.get('size', 0),
                    'file_type': carved_file.get('file_type', 'Unknown'),
                    'confidence': carved_file.get('confidence', 0.5),
                    'recovery_confidence': carved_file.get('confidence', 0.5),
                    'md5_hash': carved_file.get('md5_hash', ''),
                    'signature': carved_file.get('signature', ''),
                    'sector_offset': carved_file.get('offset', 0),
                    'recovery_status': 'carved',
                    'modified_date': carved_file.get('recovery_time')
                })
        
        # Apply search filter
        if search_value:
            files = [f for f in files if search_value.lower() in f.get('filename', '').lower()]
        
        # Calculate pagination
        total_records = len(files)
        filtered_records = total_records
        
        # Apply pagination
        paginated_files = files[start:start + length]
        
        # Format response for DataTables
        response = {
            'draw': draw,
            'recordsTotal': total_records,
            'recordsFiltered': filtered_records,
            'data': paginated_files
        }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error getting recovered files list: {e}")
        return jsonify({'error': str(e)}), 500

@deep_scan_bp.route('/preview-file/<session_id>/<file_id>', methods=['GET'])
def preview_file(session_id, file_id):
    """Generate file preview for recovered files"""
    try:
        if session_id not in scan_sessions:
            return jsonify({'success': False, 'error': 'Session not found'}), 404
        
        session = scan_sessions[session_id]
        mode = request.args.get('mode', 'content')  # 'content' or 'hex'
        
        # Find file in session results
        file_info = None
        file_path = None
        
        # Check carved files
        if hasattr(session, 'results') and 'carved_files' in session.results:
            for carved_file in session.results['carved_files']:
                if carved_file.get('filename') == file_id or carved_file.get('id') == file_id:
                    file_info = carved_file
                    file_path = carved_file.get('filepath')
                    break
        
        # Check regular scan files
        if not file_info and hasattr(session, 'results') and 'scan_results' in session.results:
            scan_files = session.results['scan_results'].get('files', [])
            for scan_file in scan_files:
                if scan_file.get('filename') == file_id or scan_file.get('id') == file_id:
                    file_info = scan_file
                    file_path = scan_file.get('filepath')
                    break
        
        if not file_info:
            return jsonify({'success': False, 'error': 'File not found'}), 404
        
        if not file_path or not os.path.exists(file_path):
            return jsonify({'success': False, 'error': 'File path not accessible'}), 404
        
        # Get file information
        file_size = os.path.getsize(file_path)
        file_type = file_info.get('file_type', '').lower()
        filename = file_info.get('filename', file_id)
        
        # Read file data
        try:
            with open(file_path, 'rb') as f:
                if mode == 'hex':
                    # Read first 16KB for hex view
                    data = f.read(16384)
                    hex_data = generate_hex_dump(data)
                    
                    return jsonify({
                        'success': True,
                        'filename': filename,
                        'file_type': file_type,
                        'size': file_size,
                        'mode': 'hex',
                        'hex_data': hex_data
                    })
                else:
                    # Content mode
                    if is_image_type(file_type):
                        # Read entire image file
                        data = f.read()
                        base64_data = base64.b64encode(data).decode('utf-8')
                        
                        return jsonify({
                            'success': True,
                            'filename': filename,
                            'file_type': file_type,
                            'size': file_size,
                            'mode': 'image',
                            'base64_data': base64_data
                        })
                    
                    elif is_text_type(file_type):
                        # Read as text (first 64KB)
                        data = f.read(65536)
                        try:
                            # Try UTF-8 first
                            text_content = data.decode('utf-8')
                            encoding = 'utf-8'
                        except UnicodeDecodeError:
                            try:
                                # Try latin-1 as fallback
                                text_content = data.decode('latin-1')
                                encoding = 'latin-1'
                            except UnicodeDecodeError:
                                # If all fails, show hex
                                hex_data = generate_hex_dump(data)
                                return jsonify({
                                    'success': True,
                                    'filename': filename,
                                    'file_type': file_type,
                                    'size': file_size,
                                    'mode': 'hex',
                                    'hex_data': hex_data,
                                    'encoding': 'binary'
                                })
                        
                        return jsonify({
                            'success': True,
                            'filename': filename,
                            'file_type': file_type,
                            'size': file_size,
                            'mode': 'text',
                            'text_content': text_content,
                            'encoding': encoding
                        })
                    
                    elif file_type == 'pdf':
                        # Read PDF file
                        data = f.read()
                        base64_data = base64.b64encode(data).decode('utf-8')
                        
                        return jsonify({
                            'success': True,
                            'filename': filename,
                            'file_type': file_type,
                            'size': file_size,
                            'mode': 'pdf',
                            'base64_data': base64_data
                        })
                    
                    else:
                        # Unknown type - show hex
                        data = f.read(16384)
                        hex_data = generate_hex_dump(data)
                        
                        return jsonify({
                            'success': True,
                            'filename': filename,
                            'file_type': file_type,
                            'size': file_size,
                            'mode': 'hex',
                            'hex_data': hex_data,
                            'encoding': 'binary'
                        })
        
        except IOError as e:
            return jsonify({'success': False, 'error': f'Failed to read file: {str(e)}'}), 500
    
    except Exception as e:
        current_app.logger.error(f"File preview error: {str(e)}")
        return jsonify({'success': False, 'error': f'Preview failed: {str(e)}'}), 500

def generate_hex_dump(data, bytes_per_line=16):
    """Generate hex dump format string"""
    if not data:
        return "No data available"
    
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        
        # Offset
        offset = f"{i:08X}"
        
        # Hex values
        hex_values = ' '.join(f"{b:02X}" for b in chunk)
        hex_values = hex_values.ljust(bytes_per_line * 3 - 1)  # Pad to fixed width
        
        # ASCII representation
        ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        
        lines.append(f"{offset}  {hex_values}  |{ascii_repr}|")
    
    return '\n'.join(lines)

def is_image_type(file_type):
    """Check if file type is an image"""
    image_types = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg', 'tiff', 'ico']
    return file_type in image_types

def is_text_type(file_type):
    """Check if file type is text-based"""
    text_types = ['txt', 'csv', 'json', 'xml', 'html', 'css', 'js', 'py', 'java', 
                  'cpp', 'c', 'h', 'md', 'log', 'cfg', 'ini', 'yml', 'yaml']
    return file_type in text_types