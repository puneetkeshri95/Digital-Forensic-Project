"""
Database models and operations for digital forensics application
"""
import sqlite3
import json
import logging
from datetime import datetime
import os

logger = logging.getLogger(__name__)

class Database:
    """Database operations for forensic cases and evidence"""
    
    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'database', 'forensics.db')
        
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        try:
            # Create database directory if it doesn't exist
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Cases table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS cases (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        case_name TEXT NOT NULL,
                        description TEXT,
                        created_date TEXT NOT NULL,
                        status TEXT DEFAULT 'open',
                        investigator TEXT,
                        metadata TEXT
                    )
                ''')
                
                # Evidence table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS evidence (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        case_id INTEGER,
                        filename TEXT NOT NULL,
                        file_path TEXT NOT NULL,
                        file_hash TEXT,
                        file_size INTEGER,
                        file_type TEXT,
                        upload_date TEXT NOT NULL,
                        analysis_result TEXT,
                        FOREIGN KEY (case_id) REFERENCES cases (id)
                    )
                ''')
                
                # Analysis results table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS analysis_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        evidence_id INTEGER,
                        analysis_type TEXT NOT NULL,
                        result_data TEXT NOT NULL,
                        created_date TEXT NOT NULL,
                        FOREIGN KEY (evidence_id) REFERENCES evidence (id)
                    )
                ''')
                
                # Audit log table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        action TEXT NOT NULL,
                        table_name TEXT NOT NULL,
                        record_id INTEGER,
                        user_id TEXT,
                        timestamp TEXT NOT NULL,
                        details TEXT
                    )
                ''')
                
                # Enhanced cases table with additional fields
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS enhanced_cases (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        case_id TEXT UNIQUE NOT NULL,
                        case_name TEXT NOT NULL,
                        investigator TEXT NOT NULL,
                        department TEXT,
                        priority TEXT DEFAULT 'medium',
                        case_type TEXT DEFAULT 'criminal',
                        incident_date TEXT,
                        description TEXT,
                        location TEXT,
                        status TEXT DEFAULT 'open',
                        seized_by TEXT,
                        seizure_date TEXT,
                        custody_notes TEXT,
                        team_members TEXT,
                        created_date TEXT NOT NULL,
                        updated_date TEXT
                    )
                ''')
                
                # Enhanced evidence table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS enhanced_evidence (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        case_id TEXT NOT NULL,
                        filename TEXT NOT NULL,
                        file_path TEXT NOT NULL,
                        file_size INTEGER,
                        evidence_type TEXT,
                        source TEXT,
                        description TEXT,
                        collected_by TEXT,
                        collection_date TEXT,
                        file_hash TEXT,
                        upload_date TEXT NOT NULL,
                        analysis_status TEXT DEFAULT 'pending',
                        metadata TEXT,
                        FOREIGN KEY (case_id) REFERENCES enhanced_cases (case_id)
                    )
                ''')

                conn.commit()
                logger.info('Database initialized successfully')
                
        except Exception as e:
            logger.error(f'Error initializing database: {str(e)}')
            raise
    
    def create_case(self, case_data):
        """Create a new forensic case"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO cases (case_name, description, created_date, investigator, metadata)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    case_data.get('case_name', 'Untitled Case'),
                    case_data.get('description', ''),
                    datetime.utcnow().isoformat(),
                    case_data.get('investigator', 'Unknown'),
                    json.dumps(case_data.get('metadata', {}))
                ))
                
                case_id = cursor.lastrowid
                
                # Add to audit log
                self._audit_log('INSERT', 'cases', case_id, case_data.get('investigator'))
                
                conn.commit()
                logger.info(f'Case created with ID: {case_id}')
                return case_id
                
        except Exception as e:
            logger.error(f'Error creating case: {str(e)}')
            raise
    
    def add_evidence(self, evidence_data):
        """Add evidence to a case"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO evidence (case_id, filename, file_path, file_hash, file_size, 
                                        file_type, upload_date, analysis_result)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    evidence_data.get('case_id'),
                    evidence_data.get('filename'),
                    evidence_data.get('file_path'),
                    evidence_data.get('file_hash'),
                    evidence_data.get('file_size'),
                    evidence_data.get('file_type'),
                    datetime.utcnow().isoformat(),
                    json.dumps(evidence_data.get('analysis_result', {}))
                ))
                
                evidence_id = cursor.lastrowid
                
                # Add to audit log
                self._audit_log('INSERT', 'evidence', evidence_id, 'system')
                
                conn.commit()
                logger.info(f'Evidence added with ID: {evidence_id}')
                return evidence_id
                
        except Exception as e:
            logger.error(f'Error adding evidence: {str(e)}')
            raise
    
    def get_all_cases(self):
        """Get all forensic cases"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('SELECT * FROM cases ORDER BY created_date DESC')
                cases = [dict(row) for row in cursor.fetchall()]
                
                # Parse metadata JSON
                for case in cases:
                    try:
                        case['metadata'] = json.loads(case['metadata'] or '{}')
                    except:
                        case['metadata'] = {}
                
                return cases
                
        except Exception as e:
            logger.error(f'Error retrieving cases: {str(e)}')
            raise
    
    def get_case(self, case_id):
        """Get specific case by ID"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('SELECT * FROM cases WHERE id = ?', (case_id,))
                case = cursor.fetchone()
                
                if case:
                    case = dict(case)
                    try:
                        case['metadata'] = json.loads(case['metadata'] or '{}')
                    except:
                        case['metadata'] = {}
                    
                    # Get associated evidence
                    cursor.execute('SELECT * FROM evidence WHERE case_id = ?', (case_id,))
                    evidence = [dict(row) for row in cursor.fetchall()]
                    
                    # Parse evidence analysis results
                    for item in evidence:
                        try:
                            item['analysis_result'] = json.loads(item['analysis_result'] or '{}')
                        except:
                            item['analysis_result'] = {}
                    
                    case['evidence'] = evidence
                
                return case
                
        except Exception as e:
            logger.error(f'Error retrieving case {case_id}: {str(e)}')
            raise
    
    def _audit_log(self, action, table_name, record_id, user_id='system'):
        """Add entry to audit log"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO audit_log (action, table_name, record_id, user_id, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                ''', (action, table_name, record_id, user_id, datetime.utcnow().isoformat()))
                
                conn.commit()
                
        except Exception as e:
            logger.warning(f'Error writing to audit log: {str(e)}')
    
    def get_audit_log(self, limit=100):
        """Get audit log entries"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM audit_log 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f'Error retrieving audit log: {str(e)}')
            raise
    
    def create_enhanced_case(self, case_data):
        """Create a new enhanced forensic case with full metadata"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO enhanced_cases (
                        case_id, case_name, investigator, department, priority, 
                        case_type, incident_date, description, location, status,
                        seized_by, seizure_date, custody_notes, team_members, 
                        created_date, updated_date
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    case_data.get('case_id'),
                    case_data.get('case_name'),
                    case_data.get('investigator'),
                    case_data.get('department'),
                    case_data.get('priority', 'medium'),
                    case_data.get('case_type', 'criminal'),
                    case_data.get('incident_date'),
                    case_data.get('description'),
                    case_data.get('location'),
                    case_data.get('status', 'open'),
                    case_data.get('seized_by'),
                    case_data.get('seizure_date'),
                    case_data.get('custody_notes'),
                    case_data.get('team_members'),
                    case_data.get('created_date'),
                    datetime.utcnow().isoformat()
                ))
                
                case_id = cursor.lastrowid
                conn.commit()
                
                # Add to audit log
                self._audit_log('CREATE', 'enhanced_cases', case_id)
                
                logger.info(f'Enhanced case created with ID: {case_id}')
                return case_id
                
        except Exception as e:
            logger.error(f'Error creating enhanced case: {str(e)}')
            raise
    
    def add_evidence(self, evidence_data):
        """Add evidence file to a case"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO enhanced_evidence (
                        case_id, filename, file_path, file_size, evidence_type,
                        source, description, collected_by, collection_date,
                        file_hash, upload_date, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    evidence_data.get('case_id'),
                    evidence_data.get('filename'),
                    evidence_data.get('file_path'),
                    evidence_data.get('file_size'),
                    evidence_data.get('evidence_type'),
                    evidence_data.get('source'),
                    evidence_data.get('description'),
                    evidence_data.get('collected_by'),
                    evidence_data.get('collection_date'),
                    evidence_data.get('file_hash'),
                    evidence_data.get('upload_date'),
                    json.dumps(evidence_data.get('metadata', {}))
                ))
                
                evidence_id = cursor.lastrowid
                conn.commit()
                
                # Add to audit log
                self._audit_log('CREATE', 'enhanced_evidence', evidence_id)
                
                logger.info(f'Evidence added with ID: {evidence_id}')
                return evidence_id
                
        except Exception as e:
            logger.error(f'Error adding evidence: {str(e)}')
            raise
    
    def get_enhanced_cases(self):
        """Get all enhanced forensic cases"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM enhanced_cases 
                    ORDER BY created_date DESC
                ''')
                
                cases = [dict(row) for row in cursor.fetchall()]
                
                # Get evidence count for each case
                for case in cases:
                    cursor.execute('''
                        SELECT COUNT(*) as evidence_count
                        FROM enhanced_evidence
                        WHERE case_id = ?
                    ''', (case['case_id'],))
                    
                    result = cursor.fetchone()
                    case['evidence_count'] = result['evidence_count'] if result else 0
                
                return cases
                
        except Exception as e:
            logger.error(f'Error retrieving enhanced cases: {str(e)}')
            raise
    
    def get_enhanced_case(self, case_id):
        """Get specific enhanced case with evidence"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Get case details
                cursor.execute('SELECT * FROM enhanced_cases WHERE case_id = ?', (case_id,))
                case = cursor.fetchone()
                
                if not case:
                    return None
                
                case = dict(case)
                
                # Get associated evidence
                cursor.execute('''
                    SELECT * FROM enhanced_evidence 
                    WHERE case_id = ? 
                    ORDER BY upload_date DESC
                ''', (case_id,))
                
                evidence = [dict(row) for row in cursor.fetchall()]
                
                # Parse metadata for evidence
                for item in evidence:
                    try:
                        item['metadata'] = json.loads(item['metadata'] or '{}')
                    except:
                        item['metadata'] = {}
                
                case['evidence'] = evidence
                
                return case
                
        except Exception as e:
            logger.error(f'Error retrieving enhanced case {case_id}: {str(e)}')
            raise
    
    def get_case_evidence(self, case_id):
        """Get all evidence for a specific case"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM enhanced_evidence 
                    WHERE case_id = ? 
                    ORDER BY upload_date DESC
                ''', (case_id,))
                
                evidence = [dict(row) for row in cursor.fetchall()]
                
                # Parse metadata
                for item in evidence:
                    try:
                        item['metadata'] = json.loads(item['metadata'] or '{}')
                    except:
                        item['metadata'] = {}
                
                return evidence
                
        except Exception as e:
            logger.error(f'Error retrieving evidence for case {case_id}: {str(e)}')
            raise