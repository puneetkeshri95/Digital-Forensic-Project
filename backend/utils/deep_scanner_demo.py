"""
Deep Scan (Low-Level Sector Scan) Utility - Demo Version
This version works without pytsk3/pyewf for demonstration purposes
"""
import os
import struct
import logging
import hashlib
import random
from typing import Dict, List, Tuple, Optional, Generator
from datetime import datetime
from dataclasses import dataclass
try:
    from .file_carver import FileCarver, CarvedFile
    CARVER_AVAILABLE = True
    logging.info("File carver module loaded successfully")
except ImportError as e:
    CARVER_AVAILABLE = False
    CarvedFile = None
    FileCarver = None
    logging.warning(f"File carver module not available: {e}")

logger = logging.getLogger(__name__)

@dataclass
class FileSignature:
    """File signature definition"""
    name: str
    extension: str
    header: bytes
    footer: bytes = b''
    max_size: int = 100 * 1024 * 1024  # 100MB default
    description: str = ''

@dataclass
class RecoveredFile:
    """Recovered file metadata"""
    id: str
    filename: str
    file_type: str
    size: int
    sector_start: int
    sector_end: int
    md5_hash: str
    recovery_status: str  # 'excellent', 'good', 'poor'
    data: bytes
    timestamp: datetime

class FileSignatureDatabase:
    """Database of known file signatures for recovery"""
    
    SIGNATURES = [
        # Image files
        FileSignature(
            name="JPEG",
            extension="jpg",
            header=b'\xFF\xD8\xFF',
            footer=b'\xFF\xD9',
            max_size=50 * 1024 * 1024,
            description="JPEG Image"
        ),
        FileSignature(
            name="PNG",
            extension="png",
            header=b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A',
            footer=b'\x49\x45\x4E\x44\xAE\x42\x60\x82',
            max_size=50 * 1024 * 1024,
            description="PNG Image"
        ),
        FileSignature(
            name="GIF",
            extension="gif",
            header=b'GIF8',
            footer=b'\x00\x3B',
            max_size=20 * 1024 * 1024,
            description="GIF Image"
        ),
        FileSignature(
            name="BMP",
            extension="bmp",
            header=b'BM',
            max_size=100 * 1024 * 1024,
            description="Bitmap Image"
        ),
        
        # Document files
        FileSignature(
            name="PDF",
            extension="pdf",
            header=b'%PDF-',
            footer=b'%%EOF',
            max_size=200 * 1024 * 1024,
            description="PDF Document"
        ),
        FileSignature(
            name="DOCX",
            extension="docx",
            header=b'\x50\x4B\x03\x04',  # ZIP header (DOCX is ZIP-based)
            max_size=100 * 1024 * 1024,
            description="Word Document"
        ),
        FileSignature(
            name="XLSX",
            extension="xlsx",
            header=b'\x50\x4B\x03\x04',  # ZIP header
            max_size=100 * 1024 * 1024,
            description="Excel Spreadsheet"
        ),
        FileSignature(
            name="PPTX",
            extension="pptx",
            header=b'\x50\x4B\x03\x04',  # ZIP header
            max_size=100 * 1024 * 1024,
            description="PowerPoint Presentation"
        ),
        
        # Archive files
        FileSignature(
            name="ZIP",
            extension="zip",
            header=b'\x50\x4B\x03\x04',
            max_size=1024 * 1024 * 1024,  # 1GB
            description="ZIP Archive"
        ),
        FileSignature(
            name="RAR",
            extension="rar",
            header=b'\x52\x61\x72\x21\x1A\x07\x00',
            max_size=1024 * 1024 * 1024,  # 1GB
            description="RAR Archive"
        ),
        
        # Media files
        FileSignature(
            name="MP3",
            extension="mp3",
            header=b'\xFF\xFB',
            max_size=50 * 1024 * 1024,
            description="MP3 Audio"
        ),
        FileSignature(
            name="MP4",
            extension="mp4",
            header=b'\x00\x00\x00\x18\x66\x74\x79\x70',
            max_size=2 * 1024 * 1024 * 1024,  # 2GB
            description="MP4 Video"
        ),
        FileSignature(
            name="AVI",
            extension="avi",
            header=b'RIFF',
            footer=b'AVI ',
            max_size=2 * 1024 * 1024 * 1024,  # 2GB
            description="AVI Video"
        ),
    ]
    
    @classmethod
    def get_signatures(cls) -> List[FileSignature]:
        """Get all file signatures"""
        return cls.SIGNATURES
    
    @classmethod
    def get_signature_by_header(cls, data: bytes) -> Optional[FileSignature]:
        """Find signature matching the header"""
        for sig in cls.SIGNATURES:
            if data.startswith(sig.header):
                return sig
        return None

class DeepScannerDemo:
    """Demo Deep sector-level scanner for deleted file recovery (without pytsk3)"""
    
    def __init__(self, sector_size: int = 512, enable_carving: bool = True):
        self.sector_size = sector_size
        self.signatures = FileSignatureDatabase.get_signatures()
        self.recovered_files: List[RecoveredFile] = []
        self.scan_progress = 0
        self.total_sectors = 0
        self.current_sector = 0
        self.enable_carving = enable_carving and CARVER_AVAILABLE
        
        # Initialize file carver if available
        if self.enable_carving:
            self.file_carver = FileCarver(recovery_base_path="Recovered", sector_size=sector_size)
        else:
            self.file_carver = None
        
    def scan_disk_image(self, image_path: str, file_types: List[str] = None) -> Generator[Dict, None, None]:
        """
        Demo scan disk image for deleted files (simulated for demo)
        
        Args:
            image_path: Path to disk image file (.img, .dd, etc.)
            file_types: List of file types to scan for (None = all)
        
        Yields:
            Progress updates and found files
        """
        try:
            # Check if image file exists
            if not os.path.exists(image_path):
                yield {"error": f"Image file not found: {image_path}"}
                return
            
            # Get file size for simulation
            file_size = os.path.getsize(image_path)
            total_sectors = file_size // self.sector_size
            self.total_sectors = total_sectors
            self.current_sector = 0
            
            yield {
                "status": "started",
                "total_sectors": total_sectors,
                "image_size": file_size
            }
            
            # Simulate sector-by-sector scanning
            yield from self._simulate_sector_scan(image_path, file_types)
            
            yield {
                "status": "completed",
                "total_found": len(self.recovered_files),
                "files": [self._file_to_dict(f) for f in self.recovered_files]
            }
            
        except Exception as e:
            logger.error(f"Deep scan error: {e}")
            yield {"error": f"Scan failed: {str(e)}"}
    
    def _simulate_sector_scan(self, image_path: str, file_types: List[str]) -> Generator[Dict, None, None]:
        """Simulate scanning process for demo purposes"""
        import time
        import random
        
        # Filter signatures by requested file types
        signatures_to_check = self.signatures
        if file_types:
            signatures_to_check = [sig for sig in self.signatures if sig.extension in file_types]
        
        # Simulate scanning with periodic file discoveries
        sectors_processed = 0
        files_found = 0
        
        while sectors_processed < self.total_sectors:
            sectors_to_process = min(1000, self.total_sectors - sectors_processed)
            sectors_processed += sectors_to_process
            self.current_sector = sectors_processed
            
            # Simulate processing time
            time.sleep(0.1)
            
            # Randomly "find" files during scanning
            if random.random() < 0.3 and len(signatures_to_check) > 0:  # 30% chance to find a file
                signature = random.choice(signatures_to_check)
                recovered_file = self._generate_demo_file(sectors_processed, signature)
                
                if recovered_file:
                    self.recovered_files.append(recovered_file)
                    files_found += 1
                    
                    yield {
                        "status": "file_found",
                        "file": self._file_to_dict(recovered_file),
                        "progress": (sectors_processed / self.total_sectors) * 100
                    }
            
            # Send progress update
            if sectors_processed % 5000 == 0 or sectors_processed >= self.total_sectors:
                yield {
                    "status": "progress",
                    "progress": (sectors_processed / self.total_sectors) * 100,
                    "current_sector": sectors_processed,
                    "total_sectors": self.total_sectors
                }
    
    def _generate_demo_file(self, sector_pos: int, signature: FileSignature) -> Optional[RecoveredFile]:
        """Generate a demo recovered file"""
        import random
        
        try:
            # Generate demo file data
            file_size = random.randint(1024, min(signature.max_size, 10 * 1024 * 1024))  # Up to 10MB for demo
            file_data = os.urandom(file_size)  # Random data for demo
            
            # Generate file metadata
            file_id = hashlib.md5(file_data).hexdigest()[:8]
            filename = f"recovered_{file_id}.{signature.extension}"
            md5_hash = hashlib.md5(file_data).hexdigest()
            
            # Determine recovery status randomly for demo
            recovery_statuses = ['excellent', 'good', 'poor']
            recovery_status = random.choice(recovery_statuses)
            
            return RecoveredFile(
                id=file_id,
                filename=filename,
                file_type=signature.name,
                size=file_size,
                sector_start=sector_pos,
                sector_end=sector_pos + (file_size // self.sector_size),
                md5_hash=md5_hash,
                recovery_status=recovery_status,
                data=file_data,
                timestamp=datetime.now()
            )
            
        except Exception as e:
            logger.warning(f"Error generating demo file: {e}")
            return None
    
    def _file_to_dict(self, file: RecoveredFile) -> Dict:
        """Convert RecoveredFile to dictionary for JSON serialization"""
        return {
            "id": file.id,
            "filename": file.filename,
            "file_type": file.file_type,
            "size": file.size,
            "sector_start": file.sector_start,
            "sector_end": file.sector_end,
            "md5_hash": file.md5_hash,
            "recovery_status": file.recovery_status,
            "timestamp": file.timestamp.isoformat()
        }
    
    def save_recovered_file(self, file_id: str, output_path: str) -> bool:
        """Save recovered file to disk"""
        try:
            recovered_file = next((f for f in self.recovered_files if f.id == file_id), None)
            if not recovered_file:
                return False
            
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'wb') as f:
                f.write(recovered_file.data)
            
            logger.info(f"Saved recovered file: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving file {file_id}: {e}")
            return False
    
    def get_scan_statistics(self) -> Dict:
        """Get current scan statistics"""
        stats = {
            "total_files_found": len(self.recovered_files),
            "files_by_type": {},
            "files_by_status": {"excellent": 0, "good": 0, "poor": 0},
            "total_data_recovered": sum(f.size for f in self.recovered_files),
            "scan_progress": self.scan_progress
        }
        
        # Count by file type
        for file in self.recovered_files:
            file_type = file.file_type
            if file_type not in stats["files_by_type"]:
                stats["files_by_type"][file_type] = 0
            stats["files_by_type"][file_type] += 1
            
            # Count by recovery status
            stats["files_by_status"][file.recovery_status] += 1
        
        return stats
    
    def carve_files(self, device_path: str, progress_callback=None) -> List:
        """Perform file carving using signature-based recovery"""        
        if not self.enable_carving or not self.file_carver:
            logging.warning("File carving not available")
            return []
        
        try:
            return self.file_carver.carve_from_device(device_path, progress_callback)
        except Exception as e:
            logging.error(f"Error during file carving: {e}")
            return []
    
    def get_carved_files_info(self) -> Dict:
        """Get information about carved files"""
        if not self.enable_carving or not self.file_carver:
            return {'available': False, 'message': 'File carving not available'}
        
        try:
            return self.file_carver.get_recovery_statistics()
        except Exception as e:
            logging.error(f"Error getting carved files info: {e}")
            return {'available': False, 'error': str(e)}
    
    def scan_with_carving(self, device_path: str, scan_mode: str = 'quick', progress_callback=None) -> Dict:
        """Perform deep scan with optional file carving"""
        results = {'scan_results': None, 'carved_files': [], 'carving_results': None}
        
        # First perform regular deep scan (simulate for demo)
        logging.info(f"Starting deep scan of {device_path}")
        
        # For demo, we'll simulate a scan
        scan_results = {
            'files_found': random.randint(10, 50),
            'scan_time': random.uniform(30, 120),
            'sectors_scanned': random.randint(1000, 10000),
            'total_sectors': random.randint(10000, 100000),
            'carving_enabled': self.enable_carving,
            'files': []
        }
        
        # Generate some demo recovered files
        for i in range(scan_results['files_found']):
            sig = random.choice(list(self.signatures.values()))
            file_id = hashlib.md5(f"demo_file_{i}_{device_path}".encode()).hexdigest()[:8]
            scan_results['files'].append({
                'filename': f"recovered_{file_id}.{sig.extension}",
                'filepath': f"recovered/{sig.name}/recovered_{file_id}.{sig.extension}",
                'size': random.randint(1024, 1024*1024),
                'file_type': sig.name,
                'signature': sig.signature,
                'md5_hash': hashlib.md5(f"demo_{i}".encode()).hexdigest(),
                'sector_offset': random.randint(100, 10000),
                'confidence': random.uniform(0.7, 1.0)
            })
        
        results['scan_results'] = scan_results
        
        # Then perform file carving if enabled
        if self.enable_carving:
            logging.info("Starting file carving process")
            carved_files = self.carve_files(device_path, progress_callback)
            results['carved_files'] = [
                {
                    'filename': cf.filename if hasattr(cf, 'filename') else f"carved_{i}.bin",
                    'filepath': cf.recovery_path if hasattr(cf, 'recovery_path') else f"Recovered/carved_{i}.bin",
                    'size': cf.file_size if hasattr(cf, 'file_size') else 0,
                    'file_type': cf.file_type if hasattr(cf, 'file_type') else 'Unknown',
                    'signature': cf.signature if hasattr(cf, 'signature') else '',
                    'md5_hash': cf.md5_hash if hasattr(cf, 'md5_hash') else '',
                    'sha256_hash': cf.sha256_hash if hasattr(cf, 'sha256_hash') else '',
                    'offset': cf.offset if hasattr(cf, 'offset') else 0,
                    'confidence': cf.confidence if hasattr(cf, 'confidence') else 0.5,
                    'recovery_time': cf.recovery_time.isoformat() if hasattr(cf, 'recovery_time') and cf.recovery_time else None
                } for i, cf in enumerate(carved_files)
            ]
            results['carving_results'] = self.get_carved_files_info()
        
        return results

# Alias for compatibility
DeepScanner = DeepScannerDemo