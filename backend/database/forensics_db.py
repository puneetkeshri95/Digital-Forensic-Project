"""
Database Models for Forensics Logging and Investigator Notes
==========================================================

Provides comprehensive database models for:
- Activity logging with timestamps
- Investigator notes and case documentation
- File analysis tracking
- Session management
- Evidence chain of custody
"""

import os
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional, Any
import json
import logging

class ForensicsDatabase:
    """Database manager for forensics logging and notes"""
    
    def __init__(self, db_path: str = None):
        if db_path is None:
            # Create database in logs directory
            logs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
            os.makedirs(logs_dir, exist_ok=True)
            db_path = os.path.join(logs_dir, 'forensics.db')
        
        self.db_path = db_path
        self.init_database()
        
    def init_database(self):
        """Initialize database with required tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Activity logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    session_id TEXT,
                    investigator_id TEXT,
                    activity_type TEXT NOT NULL,
                    activity_category TEXT,
                    description TEXT NOT NULL,
                    file_path TEXT,
                    file_name TEXT,
                    file_hash TEXT,
                    file_size INTEGER,
                    operation_details TEXT,
                    result_status TEXT,
                    error_message TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    duration_ms INTEGER,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Investigator notes table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS investigator_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    session_id TEXT,
                    investigator_id TEXT NOT NULL,
                    investigator_name TEXT,
                    case_number TEXT,
                    note_type TEXT DEFAULT 'general',
                    priority TEXT DEFAULT 'normal',
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    tags TEXT,
                    related_file_path TEXT,
                    related_file_hash TEXT,
                    related_activity_id INTEGER,
                    evidence_reference TEXT,
                    is_confidential BOOLEAN DEFAULT 0,
                    is_archived BOOLEAN DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (related_activity_id) REFERENCES activity_logs (id)
                )
            ''')
            
            # Investigation sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS investigation_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    investigator_id TEXT NOT NULL,
                    investigator_name TEXT,
                    case_number TEXT,
                    case_title TEXT,
                    session_title TEXT,
                    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                    end_time DATETIME,
                    status TEXT DEFAULT 'active',
                    total_files_analyzed INTEGER DEFAULT 0,
                    total_evidence_items INTEGER DEFAULT 0,
                    session_notes TEXT,
                    client_info TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Evidence tracking table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS evidence_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    evidence_id TEXT UNIQUE NOT NULL,
                    session_id TEXT,
                    case_number TEXT,
                    item_type TEXT NOT NULL,
                    file_path TEXT,
                    file_name TEXT,
                    file_hash TEXT,
                    file_size INTEGER,
                    acquisition_method TEXT,
                    chain_of_custody TEXT,
                    integrity_verified BOOLEAN DEFAULT 0,
                    analysis_status TEXT DEFAULT 'pending',
                    findings_summary TEXT,
                    significance_level TEXT DEFAULT 'unknown',
                    tags TEXT,
                    metadata TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES investigation_sessions (session_id)
                )
            ''')
            
            # Create indexes for better performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_logs_timestamp ON activity_logs (timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_logs_session ON activity_logs (session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_logs_type ON activity_logs (activity_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_notes_timestamp ON investigator_notes (timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_notes_session ON investigator_notes (session_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_notes_investigator ON investigator_notes (investigator_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_investigator ON investigation_sessions (investigator_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_evidence_session ON evidence_items (session_id)')
            
            conn.commit()
    
    def log_activity(self, activity_data: Dict[str, Any]) -> int:
        """Log an activity with timestamp"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Prepare data with defaults
            data = {
                'session_id': activity_data.get('session_id'),
                'investigator_id': activity_data.get('investigator_id'),
                'activity_type': activity_data.get('activity_type', 'unknown'),
                'activity_category': activity_data.get('activity_category'),
                'description': activity_data.get('description', ''),
                'file_path': activity_data.get('file_path'),
                'file_name': activity_data.get('file_name'),
                'file_hash': activity_data.get('file_hash'),
                'file_size': activity_data.get('file_size'),
                'operation_details': json.dumps(activity_data.get('operation_details', {})) if activity_data.get('operation_details') else None,
                'result_status': activity_data.get('result_status', 'success'),
                'error_message': activity_data.get('error_message'),
                'ip_address': activity_data.get('ip_address'),
                'user_agent': activity_data.get('user_agent'),
                'duration_ms': activity_data.get('duration_ms')
            }
            
            cursor.execute('''
                INSERT INTO activity_logs 
                (session_id, investigator_id, activity_type, activity_category, description,
                 file_path, file_name, file_hash, file_size, operation_details,
                 result_status, error_message, ip_address, user_agent, duration_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', tuple(data.values()))
            
            activity_id = cursor.lastrowid
            conn.commit()
            return activity_id
    
    def add_investigator_note(self, note_data: Dict[str, Any]) -> int:
        """Add an investigator note"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            data = {
                'session_id': note_data.get('session_id'),
                'investigator_id': note_data.get('investigator_id', 'unknown'),
                'investigator_name': note_data.get('investigator_name'),
                'case_number': note_data.get('case_number'),
                'note_type': note_data.get('note_type', 'general'),
                'priority': note_data.get('priority', 'normal'),
                'title': note_data.get('title', 'Untitled Note'),
                'content': note_data.get('content', ''),
                'tags': ','.join(note_data.get('tags', [])) if isinstance(note_data.get('tags'), list) else note_data.get('tags'),
                'related_file_path': note_data.get('related_file_path'),
                'related_file_hash': note_data.get('related_file_hash'),
                'related_activity_id': note_data.get('related_activity_id'),
                'evidence_reference': note_data.get('evidence_reference'),
                'is_confidential': note_data.get('is_confidential', False),
                'is_archived': note_data.get('is_archived', False)
            }
            
            cursor.execute('''
                INSERT INTO investigator_notes 
                (session_id, investigator_id, investigator_name, case_number, note_type, priority,
                 title, content, tags, related_file_path, related_file_hash, related_activity_id,
                 evidence_reference, is_confidential, is_archived)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', tuple(data.values()))
            
            note_id = cursor.lastrowid
            conn.commit()
            return note_id
    
    def create_session(self, session_data: Dict[str, Any]) -> str:
        """Create a new investigation session"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            session_id = session_data.get('session_id') or f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            data = {
                'session_id': session_id,
                'investigator_id': session_data.get('investigator_id', 'unknown'),
                'investigator_name': session_data.get('investigator_name'),
                'case_number': session_data.get('case_number'),
                'case_title': session_data.get('case_title'),
                'session_title': session_data.get('session_title', f'Investigation Session {datetime.now().strftime("%Y-%m-%d %H:%M")}'),
                'session_notes': session_data.get('session_notes'),
                'client_info': json.dumps(session_data.get('client_info', {})) if session_data.get('client_info') else None
            }
            
            cursor.execute('''
                INSERT INTO investigation_sessions 
                (session_id, investigator_id, investigator_name, case_number, case_title,
                 session_title, session_notes, client_info)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', tuple(data.values()))
            
            conn.commit()
            return session_id
    
    def end_session(self, session_id: str, session_notes: str = None) -> bool:
        """End an investigation session"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            update_data = [datetime.now().isoformat(), 'completed']
            query = 'UPDATE investigation_sessions SET end_time = ?, status = ?, updated_at = CURRENT_TIMESTAMP'
            
            if session_notes:
                query += ', session_notes = ?'
                update_data.append(session_notes)
            
            query += ' WHERE session_id = ?'
            update_data.append(session_id)
            
            cursor.execute(query, update_data)
            success = cursor.rowcount > 0
            conn.commit()
            return success
    
    def add_evidence_item(self, evidence_data: Dict[str, Any]) -> str:
        """Add an evidence item"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            evidence_id = evidence_data.get('evidence_id') or f"evidence_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:17]}"
            
            data = {
                'evidence_id': evidence_id,
                'session_id': evidence_data.get('session_id'),
                'case_number': evidence_data.get('case_number'),
                'item_type': evidence_data.get('item_type', 'file'),
                'file_path': evidence_data.get('file_path'),
                'file_name': evidence_data.get('file_name'),
                'file_hash': evidence_data.get('file_hash'),
                'file_size': evidence_data.get('file_size'),
                'acquisition_method': evidence_data.get('acquisition_method'),
                'chain_of_custody': evidence_data.get('chain_of_custody'),
                'integrity_verified': evidence_data.get('integrity_verified', False),
                'analysis_status': evidence_data.get('analysis_status', 'pending'),
                'findings_summary': evidence_data.get('findings_summary'),
                'significance_level': evidence_data.get('significance_level', 'unknown'),
                'tags': ','.join(evidence_data.get('tags', [])) if isinstance(evidence_data.get('tags'), list) else evidence_data.get('tags'),
                'metadata': json.dumps(evidence_data.get('metadata', {})) if evidence_data.get('metadata') else None
            }
            
            cursor.execute('''
                INSERT INTO evidence_items 
                (evidence_id, session_id, case_number, item_type, file_path, file_name,
                 file_hash, file_size, acquisition_method, chain_of_custody, integrity_verified,
                 analysis_status, findings_summary, significance_level, tags, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', tuple(data.values()))
            
            conn.commit()
            return evidence_id
    
    def get_activity_logs(self, session_id: str = None, investigator_id: str = None, 
                         activity_type: str = None, limit: int = 100, offset: int = 0) -> List[Dict]:
        """Retrieve activity logs with filtering"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            query = 'SELECT * FROM activity_logs WHERE 1=1'
            params = []
            
            if session_id:
                query += ' AND session_id = ?'
                params.append(session_id)
            
            if investigator_id:
                query += ' AND investigator_id = ?'
                params.append(investigator_id)
            
            if activity_type:
                query += ' AND activity_type = ?'
                params.append(activity_type)
            
            query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            columns = [desc[0] for desc in cursor.description]
            
            logs = []
            for row in cursor.fetchall():
                log_dict = dict(zip(columns, row))
                # Parse JSON fields
                if log_dict.get('operation_details'):
                    try:
                        log_dict['operation_details'] = json.loads(log_dict['operation_details'])
                    except json.JSONDecodeError:
                        pass
                logs.append(log_dict)
            
            return logs
    
    def get_investigator_notes(self, session_id: str = None, investigator_id: str = None, 
                              note_type: str = None, limit: int = 100, offset: int = 0) -> List[Dict]:
        """Retrieve investigator notes with filtering"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            query = 'SELECT * FROM investigator_notes WHERE is_archived = 0'
            params = []
            
            if session_id:
                query += ' AND session_id = ?'
                params.append(session_id)
            
            if investigator_id:
                query += ' AND investigator_id = ?'
                params.append(investigator_id)
            
            if note_type:
                query += ' AND note_type = ?'
                params.append(note_type)
            
            query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            columns = [desc[0] for desc in cursor.description]
            
            notes = []
            for row in cursor.fetchall():
                note_dict = dict(zip(columns, row))
                # Parse tags
                if note_dict.get('tags'):
                    note_dict['tags'] = [tag.strip() for tag in note_dict['tags'].split(',') if tag.strip()]
                else:
                    note_dict['tags'] = []
                notes.append(note_dict)
            
            return notes
    
    def get_sessions(self, investigator_id: str = None, status: str = None, 
                    limit: int = 50, offset: int = 0) -> List[Dict]:
        """Retrieve investigation sessions"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            query = 'SELECT * FROM investigation_sessions WHERE 1=1'
            params = []
            
            if investigator_id:
                query += ' AND investigator_id = ?'
                params.append(investigator_id)
            
            if status:
                query += ' AND status = ?'
                params.append(status)
            
            query += ' ORDER BY start_time DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            columns = [desc[0] for desc in cursor.description]
            
            sessions = []
            for row in cursor.fetchall():
                session_dict = dict(zip(columns, row))
                # Parse JSON fields
                if session_dict.get('client_info'):
                    try:
                        session_dict['client_info'] = json.loads(session_dict['client_info'])
                    except json.JSONDecodeError:
                        session_dict['client_info'] = {}
                sessions.append(session_dict)
            
            return sessions
    
    def get_evidence_items(self, session_id: str = None, case_number: str = None, 
                          item_type: str = None, limit: int = 100, offset: int = 0) -> List[Dict]:
        """Retrieve evidence items"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            query = 'SELECT * FROM evidence_items WHERE 1=1'
            params = []
            
            if session_id:
                query += ' AND session_id = ?'
                params.append(session_id)
            
            if case_number:
                query += ' AND case_number = ?'
                params.append(case_number)
            
            if item_type:
                query += ' AND item_type = ?'
                params.append(item_type)
            
            query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            columns = [desc[0] for desc in cursor.description]
            
            evidence = []
            for row in cursor.fetchall():
                evidence_dict = dict(zip(columns, row))
                # Parse JSON and tags
                if evidence_dict.get('metadata'):
                    try:
                        evidence_dict['metadata'] = json.loads(evidence_dict['metadata'])
                    except json.JSONDecodeError:
                        evidence_dict['metadata'] = {}
                
                if evidence_dict.get('tags'):
                    evidence_dict['tags'] = [tag.strip() for tag in evidence_dict['tags'].split(',') if tag.strip()]
                else:
                    evidence_dict['tags'] = []
                
                evidence.append(evidence_dict)
            
            return evidence
    
    def update_note(self, note_id: int, updates: Dict[str, Any]) -> bool:
        """Update an investigator note"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Build dynamic update query
            set_clauses = []
            params = []
            
            for field, value in updates.items():
                if field in ['title', 'content', 'note_type', 'priority', 'tags', 
                           'evidence_reference', 'is_confidential', 'is_archived']:
                    set_clauses.append(f'{field} = ?')
                    if field == 'tags' and isinstance(value, list):
                        params.append(','.join(value))
                    else:
                        params.append(value)
            
            if not set_clauses:
                return False
            
            set_clauses.append('updated_at = CURRENT_TIMESTAMP')
            params.append(note_id)
            
            query = f'UPDATE investigator_notes SET {", ".join(set_clauses)} WHERE id = ?'
            cursor.execute(query, params)
            
            success = cursor.rowcount > 0
            conn.commit()
            return success
    
    def delete_note(self, note_id: int) -> bool:
        """Soft delete a note (archive it)"""
        return self.update_note(note_id, {'is_archived': True})
    
    def search_logs(self, search_term: str, session_id: str = None, limit: int = 100) -> List[Dict]:
        """Search activity logs by description or file name"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            query = '''
                SELECT * FROM activity_logs 
                WHERE (description LIKE ? OR file_name LIKE ? OR operation_details LIKE ?)
            '''
            params = [f'%{search_term}%', f'%{search_term}%', f'%{search_term}%']
            
            if session_id:
                query += ' AND session_id = ?'
                params.append(session_id)
            
            query += ' ORDER BY timestamp DESC LIMIT ?'
            params.append(limit)
            
            cursor.execute(query, params)
            columns = [desc[0] for desc in cursor.description]
            
            results = []
            for row in cursor.fetchall():
                log_dict = dict(zip(columns, row))
                if log_dict.get('operation_details'):
                    try:
                        log_dict['operation_details'] = json.loads(log_dict['operation_details'])
                    except json.JSONDecodeError:
                        pass
                results.append(log_dict)
            
            return results
    
    def search_notes(self, search_term: str, session_id: str = None, limit: int = 100) -> List[Dict]:
        """Search investigator notes by title or content"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            query = '''
                SELECT * FROM investigator_notes 
                WHERE is_archived = 0 AND (title LIKE ? OR content LIKE ? OR tags LIKE ?)
            '''
            params = [f'%{search_term}%', f'%{search_term}%', f'%{search_term}%']
            
            if session_id:
                query += ' AND session_id = ?'
                params.append(session_id)
            
            query += ' ORDER BY timestamp DESC LIMIT ?'
            params.append(limit)
            
            cursor.execute(query, params)
            columns = [desc[0] for desc in cursor.description]
            
            results = []
            for row in cursor.fetchall():
                note_dict = dict(zip(columns, row))
                if note_dict.get('tags'):
                    note_dict['tags'] = [tag.strip() for tag in note_dict['tags'].split(',') if tag.strip()]
                else:
                    note_dict['tags'] = []
                results.append(note_dict)
            
            return results
    
    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """Get comprehensive session summary"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Get session info
            cursor.execute('SELECT * FROM investigation_sessions WHERE session_id = ?', (session_id,))
            session_row = cursor.fetchone()
            if not session_row:
                return {}
            
            session_columns = [desc[0] for desc in cursor.description]
            session_info = dict(zip(session_columns, session_row))
            
            # Get activity count by type
            cursor.execute('''
                SELECT activity_type, COUNT(*) as count
                FROM activity_logs 
                WHERE session_id = ?
                GROUP BY activity_type
            ''', (session_id,))
            activity_counts = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Get notes count by type
            cursor.execute('''
                SELECT note_type, COUNT(*) as count
                FROM investigator_notes 
                WHERE session_id = ? AND is_archived = 0
                GROUP BY note_type
            ''', (session_id,))
            note_counts = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Get evidence count
            cursor.execute('SELECT COUNT(*) FROM evidence_items WHERE session_id = ?', (session_id,))
            evidence_count = cursor.fetchone()[0]
            
            # Get recent activities
            cursor.execute('''
                SELECT activity_type, description, timestamp
                FROM activity_logs 
                WHERE session_id = ?
                ORDER BY timestamp DESC
                LIMIT 10
            ''', (session_id,))
            recent_activities = [{'type': row[0], 'description': row[1], 'timestamp': row[2]} 
                               for row in cursor.fetchall()]
            
            return {
                'session_info': session_info,
                'activity_counts': activity_counts,
                'note_counts': note_counts,
                'evidence_count': evidence_count,
                'recent_activities': recent_activities,
                'total_activities': sum(activity_counts.values()),
                'total_notes': sum(note_counts.values())
            }
    
    def export_session_data(self, session_id: str, include_logs: bool = True, 
                           include_notes: bool = True, include_evidence: bool = True) -> Dict[str, Any]:
        """Export all session data for reporting"""
        export_data = {
            'session_id': session_id,
            'export_timestamp': datetime.now().isoformat(),
            'summary': self.get_session_summary(session_id)
        }
        
        if include_logs:
            export_data['activity_logs'] = self.get_activity_logs(session_id=session_id, limit=10000)
        
        if include_notes:
            export_data['investigator_notes'] = self.get_investigator_notes(session_id=session_id, limit=10000)
        
        if include_evidence:
            export_data['evidence_items'] = self.get_evidence_items(session_id=session_id, limit=10000)
        
        return export_data