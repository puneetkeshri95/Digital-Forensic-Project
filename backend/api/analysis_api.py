"""
Analysis results API endpoints
"""
from flask import Blueprint, request, jsonify, current_app
import os
import json
import logging
from datetime import datetime

analysis_bp = Blueprint('analysis', __name__)
logger = logging.getLogger(__name__)

@analysis_bp.route('/results', methods=['GET'])
def get_analysis_results():
    """Get all analysis results"""
    try:
        results_folder = current_app.config['FORENSIC_RESULTS_FOLDER']
        results = []
        
        for filename in os.listdir(results_folder):
            if filename.endswith('.json'):
                file_path = os.path.join(results_folder, filename)
                with open(file_path, 'r') as f:
                    result = json.load(f)
                    results.append(result)
        
        return jsonify({'results': results})
        
    except Exception as e:
        logger.error(f'Error retrieving analysis results: {str(e)}')
        return jsonify({'error': 'Failed to retrieve results'}), 500

@analysis_bp.route('/results/<result_id>', methods=['GET'])
def get_analysis_result(result_id):
    """Get specific analysis result"""
    try:
        results_folder = current_app.config['FORENSIC_RESULTS_FOLDER']
        file_path = os.path.join(results_folder, f'{result_id}.json')
        
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                result = json.load(f)
            return jsonify({'result': result})
        else:
            return jsonify({'error': 'Result not found'}), 404
            
    except Exception as e:
        logger.error(f'Error retrieving result {result_id}: {str(e)}')
        return jsonify({'error': 'Failed to retrieve result'}), 500

@analysis_bp.route('/export/<result_id>', methods=['GET'])
def export_result(result_id):
    """Export analysis result"""
    try:
        results_folder = current_app.config['FORENSIC_RESULTS_FOLDER']
        file_path = os.path.join(results_folder, f'{result_id}.json')
        
        if os.path.exists(file_path):
            return send_from_directory(results_folder, f'{result_id}.json', as_attachment=True)
        else:
            return jsonify({'error': 'Result not found'}), 404
            
    except Exception as e:
        logger.error(f'Error exporting result {result_id}: {str(e)}')
        return jsonify({'error': 'Export failed'}), 500

@analysis_bp.route('/summary', methods=['GET'])
def get_analysis_summary():
    """Get analysis summary statistics"""
    try:
        results_folder = current_app.config['FORENSIC_RESULTS_FOLDER']
        
        total_analyses = len([f for f in os.listdir(results_folder) if f.endswith('.json')])
        
        # Count by file types analyzed
        file_types = {}
        for filename in os.listdir(results_folder):
            if filename.endswith('.json'):
                file_path = os.path.join(results_folder, filename)
                with open(file_path, 'r') as f:
                    result = json.load(f)
                    file_type = result.get('file_type', 'unknown')
                    file_types[file_type] = file_types.get(file_type, 0) + 1
        
        return jsonify({
            'total_analyses': total_analyses,
            'file_types': file_types,
            'last_updated': datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f'Error getting analysis summary: {str(e)}')
        return jsonify({'error': 'Failed to get summary'}), 500