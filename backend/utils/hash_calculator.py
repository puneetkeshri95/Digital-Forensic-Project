"""
Hash calculation utilities for digital forensics
"""
import hashlib
import logging

logger = logging.getLogger(__name__)

class HashCalculator:
    """Calculate various hash types for files"""
    
    def __init__(self):
        self.hash_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }
    
    def calculate_hash(self, file_path, algorithms=None):
        """Calculate hash for a file"""
        if algorithms is None:
            algorithms = ['md5', 'sha1', 'sha256']
        
        hashes = {}
        
        try:
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files
                chunk_size = 8192
                hash_objects = {}
                
                # Initialize hash objects
                for algo in algorithms:
                    if algo in self.hash_algorithms:
                        hash_objects[algo] = self.hash_algorithms[algo]()
                
                # Process file chunks
                while chunk := f.read(chunk_size):
                    for algo, hash_obj in hash_objects.items():
                        hash_obj.update(chunk)
                
                # Get final hash values
                for algo, hash_obj in hash_objects.items():
                    hashes[algo] = hash_obj.hexdigest()
            
            logger.info(f'Hash calculation completed for {file_path}')
            return hashes
            
        except Exception as e:
            logger.error(f'Error calculating hash for {file_path}: {str(e)}')
            raise
    
    def calculate_hash_from_stream(self, stream, algorithms=None):
        """Calculate hash from a file stream"""
        if algorithms is None:
            algorithms = ['md5', 'sha1', 'sha256']
        
        hashes = {}
        
        try:
            # Reset stream position
            stream.seek(0)
            
            # Read content
            content = stream.read()
            stream.seek(0)  # Reset for further use
            
            # Calculate hashes
            for algo in algorithms:
                if algo in self.hash_algorithms:
                    hash_obj = self.hash_algorithms[algo]()
                    hash_obj.update(content)
                    hashes[algo] = hash_obj.hexdigest()
            
            return hashes
            
        except Exception as e:
            logger.error(f'Error calculating hash from stream: {str(e)}')
            raise
    
    def verify_hash(self, file_path, expected_hash, algorithm='sha256'):
        """Verify file hash against expected value"""
        try:
            calculated_hash = self.calculate_hash(file_path, [algorithm])
            return calculated_hash[algorithm].lower() == expected_hash.lower()
            
        except Exception as e:
            logger.error(f'Error verifying hash for {file_path}: {str(e)}')
            return False
    
    def compare_files(self, file1_path, file2_path, algorithm='sha256'):
        """Compare two files by hash"""
        try:
            hash1 = self.calculate_hash(file1_path, [algorithm])
            hash2 = self.calculate_hash(file2_path, [algorithm])
            
            return hash1[algorithm] == hash2[algorithm]
            
        except Exception as e:
            logger.error(f'Error comparing files: {str(e)}')
            return False