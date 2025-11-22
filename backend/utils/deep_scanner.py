"""
Deep Scan (Low-Level Sector Scan) Utility
Implements sector-by-sector scanning for deleted file recovery
"""
import os
import struct
import logging
import hashlib
from typing import Dict, List, Tuple, Optional, Generator
from datetime import datetime
from dataclasses import dataclass

# Try to import forensic libraries
try:
    import pytsk3
    TSK_AVAILABLE = True
except ImportError:
    pytsk3 = None
    TSK_AVAILABLE = False

try:
    import pyewf
    EWF_AVAILABLE = True
except ImportError:
    pyewf = None
    EWF_AVAILABLE = False

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

class DeepScanner:
    """Deep sector-level scanner for deleted file recovery"""
    
    def __init__(self, sector_size: int = 512):
        self.sector_size = sector_size
        self.signatures = FileSignatureDatabase.get_signatures()
        self.recovered_files: List[RecoveredFile] = []
        self.scan_progress = 0
        self.total_sectors = 0
        self.current_sector = 0
        self.tsk_available = TSK_AVAILABLE
        self.ewf_available = EWF_AVAILABLE
        
        if not self.tsk_available:
            logger.warning("pytsk3 not available - using limited functionality")
        
    def scan_disk_image(self, image_path: str, file_types: List[str] = None) -> Generator[Dict, None, None]:
        """
        Scan disk image for deleted files
        
        Args:
            image_path: Path to disk image file (.img, .dd, .E01, etc.)
            file_types: List of file types to scan for (None = all)
        
        Yields:
            Progress updates and found files
        """
        try:
            # Detect image format and open
            img_info = self._open_image(image_path)
            if not img_info:
                yield {"error": "Failed to open disk image"}
                return
            
            # Get volume system
            try:
                if self.tsk_available and hasattr(img_info, 'get_size'):
                    vs = pytsk3.Volume_Info(img_info)
                    volumes = []
                    for volume in vs:
                        if volume.len > 2048:  # Skip small partitions
                            volumes.append(volume)
                else:
                    raise Exception("No pytsk3 available")
            except:
                # No partition table or pytsk3 unavailable, treat as single volume
                volumes = [type('Volume', (), {'start': 0, 'len': img_info.get_size() // self.sector_size})()]
            
            total_sectors = sum(vol.len for vol in volumes)
            self.total_sectors = total_sectors
            self.current_sector = 0
            
            yield {
                "status": "started",
                "total_sectors": total_sectors,
                "image_size": img_info.get_size()
            }
            
            # Scan each volume
            for vol_idx, volume in enumerate(volumes):
                yield {
                    "status": "scanning_volume",
                    "volume": vol_idx + 1,
                    "total_volumes": len(volumes)
                }
                
                # Perform sector-by-sector scan
                yield from self._scan_volume_sectors(img_info, volume, file_types)
            
            yield {
                "status": "completed",
                "total_found": len(self.recovered_files),
                "files": [self._file_to_dict(f) for f in self.recovered_files]
            }
            
        except Exception as e:
            logger.error(f"Deep scan error: {e}")
            yield {"error": f"Scan failed: {str(e)}"}
    
    def _open_image(self, image_path: str):
        """Open disk image file"""
        if not self.tsk_available:
            logger.warning("pytsk3 not available - cannot open forensic disk images")
            # Fall back to simple file reading for basic file types
            if os.path.exists(image_path):
                return type('MockImg', (), {
                    'get_size': lambda: os.path.getsize(image_path),
                    'read': lambda offset, size: self._read_file_chunk(image_path, offset, size),
                    'path': image_path
                })()
            return None
            
        try:
            # Try different image formats with pytsk3
            if image_path.lower().endswith(('.e01', '.ex01')):
                # Expert Witness Format (EnCase)
                return pytsk3.Img_Info([image_path])
            elif image_path.lower().endswith(('.img', '.dd', '.raw')):
                # Raw disk image
                return pytsk3.Img_Info([image_path])
            else:
                # Try as raw image
                return pytsk3.Img_Info([image_path])
        except Exception as e:
            logger.error(f"Failed to open image {image_path}: {e}")
            return None
    
    def _read_file_chunk(self, file_path: str, offset: int, size: int) -> bytes:
        """Read a chunk from a regular file (fallback when pytsk3 unavailable)"""
        try:
            with open(file_path, 'rb') as f:
                f.seek(offset)
                return f.read(size)
        except Exception as e:
            logger.error(f"Failed to read file chunk: {e}")
            return b''
    
    def _scan_volume_sectors(self, img_info, volume, file_types: List[str]) -> Generator[Dict, None, None]:
        """Scan sectors in a volume for file signatures"""
        start_sector = volume.start if hasattr(volume, 'start') else 0
        sector_count = volume.len if hasattr(volume, 'len') else (img_info.get_size() // self.sector_size)
        
        # Buffer for reading sectors
        buffer_size = 1024 * 1024  # 1MB buffer
        sectors_per_buffer = buffer_size // self.sector_size
        
        for sector_offset in range(0, sector_count, sectors_per_buffer):
            current_sectors = min(sectors_per_buffer, sector_count - sector_offset)
            read_size = current_sectors * self.sector_size
            
            try:
                # Read sector data
                data = img_info.read((start_sector + sector_offset) * self.sector_size, read_size)
                
                # Search for file signatures in this buffer
                found_files = self._search_signatures_in_buffer(
                    data, start_sector + sector_offset, file_types
                )
                
                for recovered_file in found_files:
                    self.recovered_files.append(recovered_file)
                    yield {
                        "status": "file_found",
                        "file": self._file_to_dict(recovered_file),
                        "progress": (self.current_sector / self.total_sectors) * 100
                    }
                
                self.current_sector += current_sectors
                
                # Update progress every 1000 sectors
                if sector_offset % 1000 == 0:
                    yield {
                        "status": "progress",
                        "progress": (self.current_sector / self.total_sectors) * 100,
                        "current_sector": self.current_sector,
                        "total_sectors": self.total_sectors
                    }
                    
            except Exception as e:
                logger.warning(f"Error reading sector {sector_offset}: {e}")
                continue
    
    def _search_signatures_in_buffer(self, data: bytes, start_sector: int, file_types: List[str]) -> List[RecoveredFile]:
        """Search for file signatures in data buffer"""
        found_files = []
        data_len = len(data)
        
        # Filter signatures by requested file types
        signatures_to_check = self.signatures
        if file_types:
            signatures_to_check = [sig for sig in self.signatures if sig.extension in file_types]
        
        for i in range(0, data_len - 16):  # Minimum header size check
            for signature in signatures_to_check:
                if data[i:i+len(signature.header)] == signature.header:
                    # Found potential file header
                    recovered_file = self._extract_file_from_position(
                        data, i, start_sector, signature
                    )
                    if recovered_file:
                        found_files.append(recovered_file)
        
        return found_files
    
    def _extract_file_from_position(self, data: bytes, position: int, start_sector: int, signature: FileSignature) -> Optional[RecoveredFile]:
        """Extract file data from found signature position"""
        try:
            # Calculate actual sector position
            sector_pos = start_sector + (position // self.sector_size)
            
            # Find file end
            file_data = data[position:]
            file_end = len(file_data)
            
            # Look for footer if signature has one
            if signature.footer:
                footer_pos = file_data.find(signature.footer)
                if footer_pos != -1:
                    file_end = footer_pos + len(signature.footer)
            else:
                # Estimate file end based on common patterns or max size
                file_end = min(signature.max_size, len(file_data))
            
            # Extract file data
            extracted_data = file_data[:file_end]
            
            # Skip very small files (likely false positives)
            if len(extracted_data) < 100:
                return None
            
            # Generate file metadata
            file_id = hashlib.md5(extracted_data).hexdigest()[:8]
            filename = f"recovered_{file_id}.{signature.extension}"
            md5_hash = hashlib.md5(extracted_data).hexdigest()
            
            # Determine recovery status based on file completeness
            recovery_status = self._assess_recovery_quality(extracted_data, signature)
            
            return RecoveredFile(
                id=file_id,
                filename=filename,
                file_type=signature.name,
                size=len(extracted_data),
                sector_start=sector_pos,
                sector_end=sector_pos + (len(extracted_data) // self.sector_size),
                md5_hash=md5_hash,
                recovery_status=recovery_status,
                data=extracted_data,
                timestamp=datetime.now()
            )
            
        except Exception as e:
            logger.warning(f"Error extracting file at position {position}: {e}")
            return None
    
    def _assess_recovery_quality(self, data: bytes, signature: FileSignature) -> str:
        """Assess the quality of file recovery"""
        try:
            # Check if file has proper footer
            if signature.footer and data.endswith(signature.footer):
                return "excellent"
            
            # Check file structure integrity
            if signature.name == "JPEG":
                # JPEG should have proper markers
                if b'\xFF\xC0' in data or b'\xFF\xC2' in data:  # SOF markers
                    return "good"
            elif signature.name == "PNG":
                # PNG should have IHDR chunk
                if b'IHDR' in data[:50]:
                    return "good"
            elif signature.name == "PDF":
                # PDF should have trailer
                if b'trailer' in data and b'xref' in data:
                    return "good"
            
            # Default to poor if no quality indicators found
            return "poor"
            
        except:
            return "poor"
    
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