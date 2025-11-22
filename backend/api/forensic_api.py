"""
Forensic Analysis API endpoints
"""
from flask import Blueprint, request, jsonify, current_app
import os
import hashlib
import logging
import re
from datetime import datetime
from utils.file_analyzer import FileAnalyzer
from utils.hash_calculator import HashCalculator
from models.database import Database

forensic_bp = Blueprint('forensic', __name__)
logger = logging.getLogger(__name__)

@forensic_bp.route('/analyze', methods=['POST'])
def analyze_evidence():
    """Analyze uploaded evidence file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Perform analysis
        analyzer = FileAnalyzer()
        analysis_result = analyzer.analyze_file(file_path)
        
        # Calculate file hash
        hash_calc = HashCalculator()
        file_hash = hash_calc.calculate_hash(file_path)
        
        # Store results in database
        db = Database()
        case_id = db.create_case({
            'filename': filename,
            'file_path': file_path,
            'file_hash': file_hash,
            'analysis_result': analysis_result,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        logger.info(f'Evidence analysis completed for file: {filename}')
        
        return jsonify({
            'success': True,
            'case_id': case_id,
            'filename': filename,
            'file_hash': file_hash,
            'analysis': analysis_result
        })
        
    except Exception as e:
        logger.error(f'Error analyzing evidence: {str(e)}')
        return jsonify({'error': 'Analysis failed'}), 500

@forensic_bp.route('/cases', methods=['GET', 'POST'])
def handle_cases():
    """Handle cases - GET to retrieve all cases, POST to create new case"""
    if request.method == 'GET':
        try:
            db = Database()
            # Try enhanced cases first, fallback to regular cases
            try:
                cases = db.get_enhanced_cases()
            except:
                cases = db.get_all_cases()
            return jsonify({'cases': cases})
        except Exception as e:
            logger.error(f'Error retrieving cases: {str(e)}')
            return jsonify({'error': 'Failed to retrieve cases'}), 500
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            # Validate required fields
            required_fields = ['case_name', 'investigator']
            for field in required_fields:
                if not data.get(field):
                    return jsonify({'error': f'{field} is required'}), 400
            
            # Prepare case data
            case_data = {
                'case_id': data.get('case_id'),
                'case_name': data.get('case_name'),
                'investigator': data.get('investigator'),
                'department': data.get('department'),
                'priority': data.get('priority', 'medium'),
                'case_type': data.get('case_type', 'criminal'),
                'incident_date': data.get('incident_date'),
                'description': data.get('description'),
                'location': data.get('location'),
                'status': data.get('status', 'open'),
                'seized_by': data.get('seized_by'),
                'seizure_date': data.get('seizure_date'),
                'custody_notes': data.get('custody_notes'),
                'team_members': data.get('team_members'),
                'created_date': datetime.utcnow().isoformat()
            }
            
            # Create case in database
            db = Database()
            case_id = db.create_enhanced_case(case_data)
            
            logger.info(f'New case created: {case_data["case_name"]} (ID: {case_id})')
            
            return jsonify({
                'success': True,
                'case_id': case_id,
                'message': 'Case created successfully'
            }), 201
            
        except Exception as e:
            logger.error(f'Error creating case: {str(e)}')
            return jsonify({'error': 'Failed to create case'}), 500

@forensic_bp.route('/cases/<int:case_id>', methods=['GET'])
def get_case(case_id):
    """Get specific case details"""
    try:
        db = Database()
        case = db.get_case(case_id)
        if case:
            return jsonify({'case': case})
        else:
            return jsonify({'error': 'Case not found'}), 404
    except Exception as e:
        logger.error(f'Error retrieving case {case_id}: {str(e)}')
        return jsonify({'error': 'Failed to retrieve case'}), 500

@forensic_bp.route('/cases/<case_id>/evidence', methods=['POST'])
def upload_evidence(case_id):
    """Upload evidence files to a specific case"""
    try:
        if 'files' not in request.files:
            return jsonify({'error': 'No files provided'}), 400
        
        files = request.files.getlist('files')
        if not files or all(f.filename == '' for f in files):
            return jsonify({'error': 'No files selected'}), 400
        
        # Get metadata from form
        evidence_type = request.form.get('evidence_type', 'unknown')
        source = request.form.get('source', '')
        description = request.form.get('description', '')
        collected_by = request.form.get('collected_by', '')
        collection_date = request.form.get('collection_date', '')
        
        db = Database()
        uploaded_files = []
        
        for file in files:
            if file.filename != '':
                # Secure filename
                filename = secure_filename(file.filename)
                
                # Create evidence directory if it doesn't exist
                evidence_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], case_id, 'evidence')
                os.makedirs(evidence_dir, exist_ok=True)
                
                # Save file
                file_path = os.path.join(evidence_dir, filename)
                file.save(file_path)
                
                # Calculate hash
                hash_calc = HashCalculator()
                file_hash = hash_calc.calculate_hash(file_path)
                
                # Store evidence metadata in database
                evidence_data = {
                    'case_id': case_id,
                    'filename': filename,
                    'file_path': file_path,
                    'file_size': os.path.getsize(file_path),
                    'evidence_type': evidence_type,
                    'source': source,
                    'description': description,
                    'collected_by': collected_by,
                    'collection_date': collection_date,
                    'file_hash': file_hash['sha256'],
                    'upload_date': datetime.utcnow().isoformat()
                }
                
                evidence_id = db.add_evidence(evidence_data)
                uploaded_files.append({
                    'evidence_id': evidence_id,
                    'filename': filename,
                    'file_hash': file_hash['sha256']
                })
        
        logger.info(f'Uploaded {len(uploaded_files)} evidence files to case {case_id}')
        
        return jsonify({
            'success': True,
            'message': f'{len(uploaded_files)} files uploaded successfully',
            'files': uploaded_files
        }), 201
        
    except Exception as e:
        logger.error(f'Error uploading evidence to case {case_id}: {str(e)}')
        return jsonify({'error': 'Failed to upload evidence'}), 500

@forensic_bp.route('/cases/<case_id>/evidence', methods=['GET'])
def get_case_evidence(case_id):
    """Get all evidence files for a specific case"""
    try:
        db = Database()
        evidence = db.get_case_evidence(case_id)
        return jsonify({'evidence': evidence})
    except Exception as e:
        logger.error(f'Error retrieving evidence for case {case_id}: {str(e)}')
        return jsonify({'error': 'Failed to retrieve evidence'}), 500

@forensic_bp.route('/hash', methods=['POST'])
def calculate_hash():
    """Calculate hash of uploaded file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        hash_calc = HashCalculator()
        
        # Calculate hash without saving file
        file_hash = hash_calc.calculate_hash_from_stream(file.stream)
        
        return jsonify({
            'filename': file.filename,
            'md5': file_hash['md5'],
            'sha1': file_hash['sha1'],
            'sha256': file_hash['sha256']
        })
        
    except Exception as e:
        logger.error(f'Error calculating hash: {str(e)}')
        return jsonify({'error': 'Hash calculation failed'}), 500

def secure_filename(filename):
    """Secure filename for saving"""
    import re
    filename = re.sub(r'[^\w\-_\.]', '_', filename)
    return filename