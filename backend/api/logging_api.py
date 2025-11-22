"""
Flask API for Forensics Logging and Investigator Notes
=====================================================

Provides REST API endpoints for:
- Activity log management and retrieval
- Investigator notes CRUD operations
- Investigation session management
- Evidence tracking and chain of custody
- Search and filtering capabilities
"""

from flask import Blueprint, request, jsonify, g
from datetime import datetime
import os
import json
from typing import Dict, Any, List

from database.forensics_db import ForensicsDatabase
from utils.activity_logger import ActivityLogger, log_user_action, ActivityTypes

# Create Blueprint
logging_bp = Blueprint('logging', __name__, url_prefix='/api/logging')

# Initialize database and logger
db = ForensicsDatabase()
activity_logger = ActivityLogger()

# Helper functions
def get_request_context() -> Dict[str, Any]:
    """Extract context from current request"""
    return {
        'ip_address': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', ''),
        'session_id': request.headers.get('X-Session-ID') or request.form.get('session_id'),
        'investigator_id': request.headers.get('X-Investigator-ID') or request.form.get('investigator_id')
    }

def validate_required_fields(data: Dict, required_fields: List[str]) -> Dict[str, Any]:
    """Validate required fields in request data"""
    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields:
        return {
            'error': f"Missing required fields: {', '.join(missing_fields)}",
            'missing_fields': missing_fields
        }
    return {}

# Session Management Endpoints
@logging_bp.route('/sessions', methods=['POST'])
def create_session():
    """Create a new investigation session"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate required fields
        validation_error = validate_required_fields(data, ['investigator_id'])
        if validation_error:
            return jsonify(validation_error), 400
        
        # Add request context
        context = get_request_context()
        data.update(context)
        
        # Create session
        session_id = db.create_session(data)
        
        # Log the activity
        log_user_action(
            'session_created',
            {'session_id': session_id, 'case_number': data.get('case_number')},
            **context
        )
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'message': 'Investigation session created successfully'
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to create session: {str(e)}'}), 500

@logging_bp.route('/sessions/<session_id>', methods=['PUT'])
def end_session(session_id):
    """End an investigation session"""
    try:
        data = request.get_json() or {}
        context = get_request_context()
        
        success = db.end_session(session_id, data.get('session_notes'))
        
        if success:
            log_user_action(
                'session_ended',
                {'session_id': session_id},
                **context
            )
            return jsonify({
                'success': True,
                'message': 'Session ended successfully'
            })
        else:
            return jsonify({'error': 'Session not found'}), 404
            
    except Exception as e:
        return jsonify({'error': f'Failed to end session: {str(e)}'}), 500

@logging_bp.route('/sessions', methods=['GET'])
def get_sessions():
    """Get investigation sessions"""
    try:
        investigator_id = request.args.get('investigator_id')
        status = request.args.get('status')
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        
        sessions = db.get_sessions(investigator_id, status, limit, offset)
        
        return jsonify({
            'success': True,
            'sessions': sessions,
            'count': len(sessions)
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to get sessions: {str(e)}'}), 500

@logging_bp.route('/sessions/<session_id>/summary', methods=['GET'])
def get_session_summary(session_id):
    """Get comprehensive session summary"""
    try:
        summary = db.get_session_summary(session_id)
        
        if not summary:
            return jsonify({'error': 'Session not found'}), 404
        
        return jsonify({
            'success': True,
            'summary': summary
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to get session summary: {str(e)}'}), 500

# Activity Logging Endpoints
@logging_bp.route('/activities', methods=['POST'])
def log_activity():
    """Log an activity"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate required fields
        validation_error = validate_required_fields(data, ['activity_type', 'description'])
        if validation_error:
            return jsonify(validation_error), 400
        
        # Add request context
        context = get_request_context()
        data.update(context)
        
        # Log activity
        activity_id = db.log_activity(data)
        
        return jsonify({
            'success': True,
            'activity_id': activity_id,
            'message': 'Activity logged successfully'
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to log activity: {str(e)}'}), 500

@logging_bp.route('/activities', methods=['GET'])
def get_activities():
    """Get activity logs with filtering"""
    try:
        session_id = request.args.get('session_id')
        investigator_id = request.args.get('investigator_id')
        activity_type = request.args.get('activity_type')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        activities = db.get_activity_logs(session_id, investigator_id, activity_type, limit, offset)
        
        return jsonify({
            'success': True,
            'activities': activities,
            'count': len(activities),
            'limit': limit,
            'offset': offset
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to get activities: {str(e)}'}), 500

@logging_bp.route('/activities/search', methods=['GET'])
def search_activities():
    """Search activity logs"""
    try:
        search_term = request.args.get('q', '')
        session_id = request.args.get('session_id')
        limit = int(request.args.get('limit', 100))
        
        if not search_term:
            return jsonify({'error': 'Search term required'}), 400
        
        results = db.search_logs(search_term, session_id, limit)
        
        return jsonify({
            'success': True,
            'results': results,
            'count': len(results),
            'search_term': search_term
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to search activities: {str(e)}'}), 500

# Investigator Notes Endpoints
@logging_bp.route('/notes', methods=['POST'])
def add_note():
    """Add an investigator note"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate required fields
        validation_error = validate_required_fields(data, ['investigator_id', 'title', 'content'])
        if validation_error:
            return jsonify(validation_error), 400
        
        # Add request context
        context = get_request_context()
        data.update(context)
        
        # Add note
        note_id = db.add_investigator_note(data)
        
        # Log the activity
        log_user_action(
            'note_added',
            {
                'note_id': note_id,
                'title': data.get('title'),
                'note_type': data.get('note_type', 'general')
            },
            **context
        )
        
        return jsonify({
            'success': True,
            'note_id': note_id,
            'message': 'Note added successfully'
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to add note: {str(e)}'}), 500

@logging_bp.route('/notes', methods=['GET'])
def get_notes():
    """Get investigator notes with filtering"""
    try:
        session_id = request.args.get('session_id')
        investigator_id = request.args.get('investigator_id')
        note_type = request.args.get('note_type')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        notes = db.get_investigator_notes(session_id, investigator_id, note_type, limit, offset)
        
        return jsonify({
            'success': True,
            'notes': notes,
            'count': len(notes),
            'limit': limit,
            'offset': offset
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to get notes: {str(e)}'}), 500

@logging_bp.route('/notes/<int:note_id>', methods=['PUT'])
def update_note(note_id):
    """Update an investigator note"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        context = get_request_context()
        
        success = db.update_note(note_id, data)
        
        if success:
            log_user_action(
                'note_updated',
                {'note_id': note_id, 'updated_fields': list(data.keys())},
                **context
            )
            return jsonify({
                'success': True,
                'message': 'Note updated successfully'
            })
        else:
            return jsonify({'error': 'Note not found or no changes made'}), 404
            
    except Exception as e:
        return jsonify({'error': f'Failed to update note: {str(e)}'}), 500

@logging_bp.route('/notes/<int:note_id>', methods=['DELETE'])
def delete_note(note_id):
    """Delete (archive) an investigator note"""
    try:
        context = get_request_context()
        
        success = db.delete_note(note_id)
        
        if success:
            log_user_action(
                'note_deleted',
                {'note_id': note_id},
                **context
            )
            return jsonify({
                'success': True,
                'message': 'Note deleted successfully'
            })
        else:
            return jsonify({'error': 'Note not found'}), 404
            
    except Exception as e:
        return jsonify({'error': f'Failed to delete note: {str(e)}'}), 500

@logging_bp.route('/notes/search', methods=['GET'])
def search_notes():
    """Search investigator notes"""
    try:
        search_term = request.args.get('q', '')
        session_id = request.args.get('session_id')
        limit = int(request.args.get('limit', 100))
        
        if not search_term:
            return jsonify({'error': 'Search term required'}), 400
        
        results = db.search_notes(search_term, session_id, limit)
        
        return jsonify({
            'success': True,
            'results': results,
            'count': len(results),
            'search_term': search_term
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to search notes: {str(e)}'}), 500

# Evidence Management Endpoints
@logging_bp.route('/evidence', methods=['POST'])
def add_evidence():
    """Add an evidence item"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate required fields
        validation_error = validate_required_fields(data, ['item_type'])
        if validation_error:
            return jsonify(validation_error), 400
        
        # Add request context
        context = get_request_context()
        data.update(context)
        
        # Add evidence
        evidence_id = db.add_evidence_item(data)
        
        # Log the activity
        log_user_action(
            'evidence_added',
            {
                'evidence_id': evidence_id,
                'item_type': data.get('item_type'),
                'file_name': data.get('file_name')
            },
            **context
        )
        
        return jsonify({
            'success': True,
            'evidence_id': evidence_id,
            'message': 'Evidence item added successfully'
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to add evidence: {str(e)}'}), 500

@logging_bp.route('/evidence', methods=['GET'])
def get_evidence():
    """Get evidence items with filtering"""
    try:
        session_id = request.args.get('session_id')
        case_number = request.args.get('case_number')
        item_type = request.args.get('item_type')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        evidence = db.get_evidence_items(session_id, case_number, item_type, limit, offset)
        
        return jsonify({
            'success': True,
            'evidence': evidence,
            'count': len(evidence),
            'limit': limit,
            'offset': offset
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to get evidence: {str(e)}'}), 500

# Export and Reporting Endpoints
@logging_bp.route('/sessions/<session_id>/export', methods=['GET'])
def export_session_data(session_id):
    """Export session data for reporting"""
    try:
        include_logs = request.args.get('include_logs', 'true').lower() == 'true'
        include_notes = request.args.get('include_notes', 'true').lower() == 'true'
        include_evidence = request.args.get('include_evidence', 'true').lower() == 'true'
        
        export_data = db.export_session_data(session_id, include_logs, include_notes, include_evidence)
        
        if not export_data.get('summary'):
            return jsonify({'error': 'Session not found'}), 404
        
        # Log the export activity
        context = get_request_context()
        log_user_action(
            'data_exported',
            {
                'session_id': session_id,
                'export_type': 'session_data',
                'include_logs': include_logs,
                'include_notes': include_notes,
                'include_evidence': include_evidence
            },
            **context
        )
        
        return jsonify({
            'success': True,
            'export_data': export_data
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to export session data: {str(e)}'}), 500

# Statistics and Analytics Endpoints
@logging_bp.route('/statistics/activity-types', methods=['GET'])
def get_activity_statistics():
    """Get activity type statistics"""
    try:
        session_id = request.args.get('session_id')
        investigator_id = request.args.get('investigator_id')
        
        # This would require additional database methods
        # For now, return a simple response
        return jsonify({
            'success': True,
            'message': 'Activity statistics endpoint - implementation pending',
            'available_types': [
                ActivityTypes.ELA_ANALYSIS,
                ActivityTypes.EXIF_ANALYSIS,
                ActivityTypes.HEX_ANALYSIS,
                ActivityTypes.CLONE_DETECTION,
                ActivityTypes.NOISE_ANALYSIS,
                ActivityTypes.FILE_CARVING
            ]
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to get statistics: {str(e)}'}), 500

# Health Check Endpoint
@logging_bp.route('/health', methods=['GET'])
def health_check():
    """Check API health and database connectivity"""
    try:
        # Test database connection
        test_logs = db.get_activity_logs(limit=1)
        
        return jsonify({
            'success': True,
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.now().isoformat(),
            'endpoints': {
                'sessions': '/api/logging/sessions',
                'activities': '/api/logging/activities',
                'notes': '/api/logging/notes',
                'evidence': '/api/logging/evidence',
                'search': '/api/logging/activities/search, /api/logging/notes/search',
                'export': '/api/logging/sessions/<session_id>/export'
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

# Error Handlers
@logging_bp.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request', 'message': str(error)}), 400

@logging_bp.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found', 'message': str(error)}), 404

@logging_bp.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error', 'message': str(error)}), 500