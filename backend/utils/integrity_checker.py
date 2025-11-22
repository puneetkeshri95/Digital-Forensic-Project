"""
File Integrity Verification System
=================================

Provides comprehensive file integrity checking using multiple hash algorithms.
Generates hash values before and after analysis operations to ensure file integrity.
Supports SHA256, MD5, SHA1, and CRC32 for different use cases.
"""

import hashlib
import os
import time
import json
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

class FileIntegrityChecker:
    """Comprehensive file integrity checking system"""
    
    def __init__(self):
        self.supported_algorithms = {
            'sha256': hashlib.sha256,
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha3_256': hashlib.sha3_256,
            'blake2b': hashlib.blake2b
        }
        self.chunk_size = 8192  # 8KB chunks for memory efficiency
        self.logger = logging.getLogger(__name__)
        
    def calculate_file_hash(self, file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """
        Calculate hash for a single file using specified algorithm
        
        Args:
            file_path (str): Path to the file
            algorithm (str): Hash algorithm to use
            
        Returns:
            str: Hexadecimal hash string or None if error
        """
        if algorithm not in self.supported_algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        if not os.path.exists(file_path):
            self.logger.error(f"File not found: {file_path}")
            return None
        
        try:
            hash_obj = self.supported_algorithms[algorithm]()
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(self.chunk_size):
                    hash_obj.update(chunk)
            
            return hash_obj.hexdigest()
            
        except Exception as e:
            self.logger.error(f"Error calculating {algorithm} hash for {file_path}: {str(e)}")
            return None
    
    def calculate_multiple_hashes(self, file_path: str, algorithms: List[str] = None) -> Dict[str, str]:
        """
        Calculate multiple hash values for a file efficiently in a single pass
        
        Args:
            file_path (str): Path to the file
            algorithms (List[str]): List of algorithms to use
            
        Returns:
            Dict[str, str]: Dictionary mapping algorithm names to hash values
        """
        if algorithms is None:
            algorithms = ['sha256', 'md5']
        
        if not os.path.exists(file_path):
            self.logger.error(f"File not found: {file_path}")
            return {}
        
        # Validate algorithms
        invalid_algorithms = [alg for alg in algorithms if alg not in self.supported_algorithms]
        if invalid_algorithms:
            raise ValueError(f"Unsupported algorithms: {invalid_algorithms}")
        
        try:
            # Initialize hash objects
            hash_objects = {alg: self.supported_algorithms[alg]() for alg in algorithms}
            
            # Read file once and update all hash objects
            with open(file_path, 'rb') as f:
                while chunk := f.read(self.chunk_size):
                    for hash_obj in hash_objects.values():
                        hash_obj.update(chunk)
            
            # Get final hash values
            return {alg: hash_obj.hexdigest() for alg, hash_obj in hash_objects.items()}
            
        except Exception as e:
            self.logger.error(f"Error calculating hashes for {file_path}: {str(e)}")
            return {}
    
    def calculate_crc32(self, file_path: str) -> Optional[str]:
        """Calculate CRC32 checksum for a file"""
        import zlib
        
        if not os.path.exists(file_path):
            return None
        
        try:
            crc = 0
            with open(file_path, 'rb') as f:
                while chunk := f.read(self.chunk_size):
                    crc = zlib.crc32(chunk, crc)
            
            return f"{crc & 0xffffffff:08x}"
            
        except Exception as e:
            self.logger.error(f"Error calculating CRC32 for {file_path}: {str(e)}")
            return None
    
    def create_integrity_record(self, file_path: str, context: str = "analysis", 
                              algorithms: List[str] = None) -> Dict[str, Any]:
        """
        Create a comprehensive integrity record for a file
        
        Args:
            file_path (str): Path to the file
            context (str): Context of the integrity check (e.g., "pre_analysis", "post_analysis")
            algorithms (List[str]): Hash algorithms to use
            
        Returns:
            Dict: Comprehensive integrity record
        """
        if algorithms is None:
            algorithms = ['sha256', 'md5', 'sha1']
        
        start_time = time.time()
        
        try:
            # Get file info
            file_stat = os.stat(file_path)
            file_size = file_stat.st_size
            modification_time = datetime.fromtimestamp(file_stat.st_mtime)
            
            # Calculate hashes
            hashes = self.calculate_multiple_hashes(file_path, algorithms)
            
            # Add CRC32
            crc32 = self.calculate_crc32(file_path)
            if crc32:
                hashes['crc32'] = crc32
            
            calculation_time = time.time() - start_time
            
            integrity_record = {
                'file_path': file_path,
                'file_name': os.path.basename(file_path),
                'file_size': file_size,
                'modification_time': modification_time.isoformat(),
                'context': context,
                'timestamp': datetime.now().isoformat(),
                'hashes': hashes,
                'calculation_time_ms': int(calculation_time * 1000),
                'integrity_status': 'calculated',
                'algorithms_used': list(hashes.keys())
            }
            
            return integrity_record
            
        except Exception as e:
            self.logger.error(f"Error creating integrity record for {file_path}: {str(e)}")
            return {
                'file_path': file_path,
                'error': str(e),
                'integrity_status': 'error',
                'timestamp': datetime.now().isoformat()
            }
    
    def verify_integrity(self, original_record: Dict[str, Any], 
                        verification_file_path: str = None) -> Dict[str, Any]:
        """
        Verify file integrity by comparing hash values
        
        Args:
            original_record (Dict): Original integrity record
            verification_file_path (str): Path to file for verification (uses original path if None)
            
        Returns:
            Dict: Verification results
        """
        file_path = verification_file_path or original_record.get('file_path')
        
        if not file_path or not os.path.exists(file_path):
            return {
                'verification_status': 'failed',
                'error': 'File not found for verification',
                'timestamp': datetime.now().isoformat()
            }
        
        try:
            # Get original hashes
            original_hashes = original_record.get('hashes', {})
            if not original_hashes:
                return {
                    'verification_status': 'failed',
                    'error': 'No original hashes to compare',
                    'timestamp': datetime.now().isoformat()
                }
            
            # Calculate current hashes
            algorithms = list(original_hashes.keys())
            # Remove crc32 from algorithms list as it's calculated separately
            hash_algorithms = [alg for alg in algorithms if alg != 'crc32']
            
            current_hashes = self.calculate_multiple_hashes(file_path, hash_algorithms)
            
            # Add CRC32 if it was in original
            if 'crc32' in original_hashes:
                crc32 = self.calculate_crc32(file_path)
                if crc32:
                    current_hashes['crc32'] = crc32
            
            # Compare hashes
            verification_results = {}
            all_match = True
            
            for algorithm, original_hash in original_hashes.items():
                current_hash = current_hashes.get(algorithm)
                matches = current_hash == original_hash if current_hash else False
                
                verification_results[algorithm] = {
                    'original': original_hash,
                    'current': current_hash,
                    'matches': matches,
                    'status': 'verified' if matches else 'mismatch'
                }
                
                if not matches:
                    all_match = False
            
            # Get current file info
            file_stat = os.stat(file_path)
            current_size = file_stat.st_size
            current_modification_time = datetime.fromtimestamp(file_stat.st_mtime)
            
            # Check if file size changed
            original_size = original_record.get('file_size')
            size_changed = original_size != current_size if original_size is not None else False
            
            verification_record = {
                'verification_status': 'verified' if all_match else 'failed',
                'overall_integrity': 'intact' if all_match and not size_changed else 'compromised',
                'file_path': file_path,
                'original_context': original_record.get('context'),
                'verification_context': 'post_analysis',
                'timestamp': datetime.now().isoformat(),
                'file_size_changed': size_changed,
                'original_size': original_size,
                'current_size': current_size,
                'original_modification_time': original_record.get('modification_time'),
                'current_modification_time': current_modification_time.isoformat(),
                'hash_verification': verification_results,
                'algorithms_verified': list(verification_results.keys()),
                'matched_hashes': sum(1 for result in verification_results.values() if result['matches']),
                'total_hashes': len(verification_results)
            }
            
            return verification_record
            
        except Exception as e:
            self.logger.error(f"Error verifying integrity for {file_path}: {str(e)}")
            return {
                'verification_status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def batch_calculate_hashes(self, file_paths: List[str], algorithms: List[str] = None,
                              max_workers: int = 4) -> Dict[str, Dict[str, Any]]:
        """
        Calculate hashes for multiple files concurrently
        
        Args:
            file_paths (List[str]): List of file paths
            algorithms (List[str]): Hash algorithms to use
            max_workers (int): Maximum number of worker threads
            
        Returns:
            Dict: Mapping of file paths to integrity records
        """
        if algorithms is None:
            algorithms = ['sha256', 'md5']
        
        results = {}
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_path = {
                executor.submit(self.create_integrity_record, path, "batch_analysis", algorithms): path
                for path in file_paths
            }
            
            # Collect results
            for future in as_completed(future_to_path):
                file_path = future_to_path[future]
                try:
                    result = future.result()
                    results[file_path] = result
                except Exception as e:
                    self.logger.error(f"Error processing {file_path}: {str(e)}")
                    results[file_path] = {
                        'file_path': file_path,
                        'error': str(e),
                        'integrity_status': 'error'
                    }
        
        return results
    
    def export_integrity_report(self, integrity_records: Dict[str, Dict[str, Any]], 
                               output_path: str) -> bool:
        """
        Export integrity records to JSON file
        
        Args:
            integrity_records (Dict): Integrity records to export
            output_path (str): Output file path
            
        Returns:
            bool: Success status
        """
        try:
            report_data = {
                'report_type': 'file_integrity_report',
                'generated_at': datetime.now().isoformat(),
                'total_files': len(integrity_records),
                'records': integrity_records,
                'summary': self._generate_integrity_summary(integrity_records)
            }
            
            with open(output_path, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            self.logger.info(f"Integrity report exported to: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting integrity report: {str(e)}")
            return False
    
    def _generate_integrity_summary(self, records: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics for integrity records"""
        total_files = len(records)
        successful_calculations = sum(1 for r in records.values() 
                                    if r.get('integrity_status') == 'calculated')
        errors = total_files - successful_calculations
        
        total_size = sum(r.get('file_size', 0) for r in records.values() 
                        if r.get('file_size'))
        
        algorithms_used = set()
        for record in records.values():
            if 'algorithms_used' in record:
                algorithms_used.update(record['algorithms_used'])
        
        return {
            'total_files': total_files,
            'successful_calculations': successful_calculations,
            'errors': errors,
            'success_rate': (successful_calculations / total_files * 100) if total_files > 0 else 0,
            'total_size_bytes': total_size,
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'algorithms_used': list(algorithms_used)
        }
    
    def create_verification_chain(self, file_path: str, operation_contexts: List[str]) -> List[Dict[str, Any]]:
        """
        Create a chain of integrity records for different operation contexts
        
        Args:
            file_path (str): Path to the file
            operation_contexts (List[str]): List of operation contexts
            
        Returns:
            List[Dict]: Chain of integrity records
        """
        chain = []
        
        for context in operation_contexts:
            if os.path.exists(file_path):
                record = self.create_integrity_record(file_path, context)
                chain.append(record)
            else:
                chain.append({
                    'file_path': file_path,
                    'context': context,
                    'error': 'File not found',
                    'integrity_status': 'missing',
                    'timestamp': datetime.now().isoformat()
                })
        
        return chain
    
    def validate_hash_format(self, hash_value: str, algorithm: str) -> bool:
        """
        Validate if a hash value has the correct format for the algorithm
        
        Args:
            hash_value (str): Hash value to validate
            algorithm (str): Hash algorithm
            
        Returns:
            bool: True if format is valid
        """
        expected_lengths = {
            'md5': 32,
            'sha1': 40,
            'sha256': 64,
            'sha3_256': 64,
            'blake2b': 128,
            'crc32': 8
        }
        
        if algorithm not in expected_lengths:
            return False
        
        expected_length = expected_lengths[algorithm]
        
        # Check length and hex format
        if len(hash_value) != expected_length:
            return False
        
        try:
            int(hash_value, 16)
            return True
        except ValueError:
            return False

# Convenience functions for common operations
def quick_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
    """Quick hash calculation for a single file"""
    checker = FileIntegrityChecker()
    return checker.calculate_file_hash(file_path, algorithm)

def quick_integrity_check(file_path: str, algorithms: List[str] = None) -> Dict[str, str]:
    """Quick integrity check with multiple algorithms"""
    checker = FileIntegrityChecker()
    return checker.calculate_multiple_hashes(file_path, algorithms)

def verify_file_integrity(original_record: Dict[str, Any], current_file_path: str = None) -> Dict[str, Any]:
    """Quick integrity verification"""
    checker = FileIntegrityChecker()
    return checker.verify_integrity(original_record, current_file_path)