"""
File analysis utilities for digital forensics
"""
import os
import hashlib
import json
from datetime import datetime
import logging

# Optional import for magic - fall back to basic analysis if not available
try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

logger = logging.getLogger(__name__)

class FileAnalyzer:
    """Analyze files for forensic purposes"""
    
    def __init__(self):
        self.supported_types = {
            'image': ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff'],
            'document': ['pdf', 'doc', 'docx', 'txt', 'rtf'],
            'archive': ['zip', 'rar', '7z', 'tar', 'gz'],
            'executable': ['exe', 'dll', 'bat', 'cmd'],
            'script': ['py', 'js', 'php', 'sh', 'ps1']
        }
    
    def analyze_file(self, file_path):
        """Perform comprehensive file analysis"""
        try:
            analysis = {
                'timestamp': datetime.utcnow().isoformat(),
                'file_path': file_path,
                'basic_info': self._get_basic_info(file_path),
                'file_type': self._detect_file_type(file_path),
                'metadata': self._extract_metadata(file_path),
                'security_scan': self._security_scan(file_path),
                'hash_analysis': self._hash_analysis(file_path)
            }
            
            # Save analysis result
            self._save_analysis(analysis)
            
            return analysis
            
        except Exception as e:
            logger.error(f'Error analyzing file {file_path}: {str(e)}')
            raise
    
    def _get_basic_info(self, file_path):
        """Get basic file information"""
        stat = os.stat(file_path)
        return {
            'filename': os.path.basename(file_path),
            'size': stat.st_size,
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'accessed': datetime.fromtimestamp(stat.st_atime).isoformat()
        }
    
    def _detect_file_type(self, file_path):
        """Detect file type using magic numbers or fallback to extension"""
        try:
            if HAS_MAGIC:
                # Try to use python-magic if available
                file_type = magic.from_file(file_path)
                mime_type = magic.from_file(file_path, mime=True)
                
                return {
                    'description': file_type,
                    'mime_type': mime_type,
                    'extension': os.path.splitext(file_path)[1].lower()
                }
        except:
            pass
        
        # Fallback to extension-based detection
        ext = os.path.splitext(file_path)[1].lower().replace('.', '')
        category = 'unknown'
        
        for cat, extensions in self.supported_types.items():
            if ext in extensions:
                category = cat
                break
        
        return {
            'description': f'{ext.upper()} file',
            'mime_type': 'application/octet-stream',
            'extension': f'.{ext}',
            'category': category
        }
    
    def _extract_metadata(self, file_path):
        """Extract file metadata"""
        metadata = {}
        
        try:
            # Basic file attributes
            stat = os.stat(file_path)
            metadata['permissions'] = oct(stat.st_mode)[-3:]
            metadata['owner_uid'] = stat.st_uid
            metadata['group_gid'] = stat.st_gid
            
            # File signature analysis
            with open(file_path, 'rb') as f:
                header = f.read(16)
                metadata['file_signature'] = header.hex()
            
        except Exception as e:
            logger.warning(f'Error extracting metadata from {file_path}: {str(e)}')
            metadata['error'] = str(e)
        
        return metadata
    
    def _security_scan(self, file_path):
        """Perform basic security scanning"""
        security_info = {
            'suspicious_indicators': [],
            'risk_level': 'low'
        }
        
        try:
            filename = os.path.basename(file_path).lower()
            
            # Check for suspicious file names
            suspicious_names = [
                'password', 'secret', 'confidential', 'private',
                'keylog', 'trojan', 'virus', 'malware'
            ]
            
            for name in suspicious_names:
                if name in filename:
                    security_info['suspicious_indicators'].append(f'Suspicious filename: {name}')
                    security_info['risk_level'] = 'medium'
            
            # Check file size anomalies
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                security_info['suspicious_indicators'].append('Zero-byte file')
            elif file_size > 100 * 1024 * 1024:  # > 100MB
                security_info['suspicious_indicators'].append('Unusually large file')
            
            # Update risk level based on indicators
            if len(security_info['suspicious_indicators']) > 2:
                security_info['risk_level'] = 'high'
            elif len(security_info['suspicious_indicators']) > 0:
                security_info['risk_level'] = 'medium'
                
        except Exception as e:
            logger.warning(f'Error in security scan for {file_path}: {str(e)}')
            security_info['error'] = str(e)
        
        return security_info
    
    def _hash_analysis(self, file_path):
        """Calculate file hashes"""
        hashes = {}
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                
                hashes['md5'] = hashlib.md5(content).hexdigest()
                hashes['sha1'] = hashlib.sha1(content).hexdigest()
                hashes['sha256'] = hashlib.sha256(content).hexdigest()
                
        except Exception as e:
            logger.error(f'Error calculating hashes for {file_path}: {str(e)}')
            hashes['error'] = str(e)
        
        return hashes
    
    def _save_analysis(self, analysis):
        """Save analysis results to file"""
        try:
            results_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'forensic_results')
            if not os.path.exists(results_dir):
                os.makedirs(results_dir)
            
            # Generate unique filename
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f'analysis_{timestamp}.json'
            file_path = os.path.join(results_dir, filename)
            
            with open(file_path, 'w') as f:
                json.dump(analysis, f, indent=2)
            
            logger.info(f'Analysis results saved to {file_path}')
            
        except Exception as e:
            logger.error(f'Error saving analysis results: {str(e)}')
            raise