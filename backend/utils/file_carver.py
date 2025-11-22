"""
File Carving Logic - Signature-Based Recovery System
Advanced file recovery using magic numbers and signature patterns
"""
import os
import struct
import hashlib
import logging
from typing import Dict, List, Tuple, Optional, BinaryIO
from datetime import datetime
from dataclasses import dataclass, field
from pathlib import Path
import json

logger = logging.getLogger(__name__)

class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder for datetime objects"""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super(DateTimeEncoder, self).default(obj)

@dataclass
class FileSignature:
    """Enhanced file signature with carving-specific attributes"""
    name: str
    extension: str
    magic_header: bytes
    magic_footer: bytes = b''
    max_size: int = 100 * 1024 * 1024  # 100MB default
    min_size: int = 64  # Minimum file size to consider valid
    description: str = ''
    recovery_confidence: float = 0.8  # Confidence threshold for recovery
    additional_signatures: List[bytes] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.additional_signatures:
            self.additional_signatures = []

@dataclass 
class CarvedFile:
    """Represents a carved/recovered file"""
    file_id: str
    original_filename: str
    carved_filename: str
    file_type: str
    signature: str
    start_offset: int
    end_offset: int
    file_size: int
    md5_hash: str
    sha256_hash: str
    recovery_confidence: float
    carved_timestamp: datetime
    source_image: str
    sector_start: int
    sector_end: int
    recovery_path: str
    data_preview: bytes = field(default=b'')
    recovery_status: str = field(default='recovered')
    metadata: Dict = field(default_factory=dict)
    
    @property
    def filename(self) -> str:
        """Compatibility property for filename"""
        return self.carved_filename
    
    @property
    def offset(self) -> int:
        """Compatibility property for offset"""
        return self.start_offset
    
    @property
    def confidence(self) -> float:
        """Compatibility property for confidence"""
        return self.recovery_confidence
    
    @property
    def recovery_time(self) -> datetime:
        """Compatibility property for recovery time"""
        return self.carved_timestamp
    recovery_status: str = 'recovered'  # recovered, partial, corrupted
    metadata: Dict = field(default_factory=dict)

class FileSignatureDatabase:
    """Comprehensive database of file signatures for carving"""
    
    @staticmethod
    def get_carving_signatures() -> List[FileSignature]:
        """Get comprehensive list of file signatures for carving"""
        return [
            # Image formats with enhanced signatures
            FileSignature(
                name="JPEG",
                extension="jpg",
                magic_header=b'\xFF\xD8\xFF',
                magic_footer=b'\xFF\xD9',
                max_size=50 * 1024 * 1024,
                min_size=512,
                description="JPEG Image File",
                recovery_confidence=0.95,
                additional_signatures=[
                    b'\xFF\xD8\xFF\xE0',  # JFIF
                    b'\xFF\xD8\xFF\xE1',  # EXIF
                    b'\xFF\xD8\xFF\xDB'   # JPEG with quantization table
                ]
            ),
            
            FileSignature(
                name="PNG",
                extension="png",
                magic_header=b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A',
                magic_footer=b'\x49\x45\x4E\x44\xAE\x42\x60\x82',
                max_size=50 * 1024 * 1024,
                min_size=100,
                description="Portable Network Graphics",
                recovery_confidence=0.98,
                additional_signatures=[b'\x89PNG\r\n\x1a\n']
            ),
            
            FileSignature(
                name="GIF",
                extension="gif",
                magic_header=b'GIF8',
                magic_footer=b'\x00\x3B',
                max_size=20 * 1024 * 1024,
                min_size=64,
                description="Graphics Interchange Format",
                recovery_confidence=0.90,
                additional_signatures=[b'GIF87a', b'GIF89a']
            ),
            
            FileSignature(
                name="BMP",
                extension="bmp",
                magic_header=b'BM',
                max_size=100 * 1024 * 1024,
                min_size=54,  # BMP header size
                description="Windows Bitmap",
                recovery_confidence=0.85
            ),
            
            FileSignature(
                name="TIFF",
                extension="tiff",
                magic_header=b'\x49\x49\x2A\x00',  # Little endian
                max_size=100 * 1024 * 1024,
                min_size=128,
                description="Tagged Image File Format",
                recovery_confidence=0.88,
                additional_signatures=[b'\x4D\x4D\x00\x2A']  # Big endian
            ),
            
            # Document formats
            FileSignature(
                name="PDF",
                extension="pdf",
                magic_header=b'%PDF-',
                magic_footer=b'%%EOF',
                max_size=200 * 1024 * 1024,
                min_size=256,
                description="Portable Document Format",
                recovery_confidence=0.92,
                additional_signatures=[
                    b'%PDF-1.0', b'%PDF-1.1', b'%PDF-1.2', 
                    b'%PDF-1.3', b'%PDF-1.4', b'%PDF-1.5',
                    b'%PDF-1.6', b'%PDF-1.7', b'%PDF-2.0'
                ]
            ),
            
            FileSignature(
                name="DOCX",
                extension="docx",
                magic_header=b'\x50\x4B\x03\x04',  # ZIP header
                max_size=100 * 1024 * 1024,
                min_size=1024,
                description="Microsoft Word Document",
                recovery_confidence=0.75,  # Lower confidence due to ZIP format
                additional_signatures=[b'PK\x03\x04']
            ),
            
            FileSignature(
                name="RTF",
                extension="rtf",
                magic_header=b'{\\rtf1',
                max_size=50 * 1024 * 1024,
                min_size=128,
                description="Rich Text Format",
                recovery_confidence=0.88
            ),
            
            # Archive formats
            FileSignature(
                name="ZIP",
                extension="zip",
                magic_header=b'\x50\x4B\x03\x04',
                magic_footer=b'\x50\x4B\x05\x06',  # End of central directory
                max_size=1024 * 1024 * 1024,  # 1GB
                min_size=64,
                description="ZIP Archive",
                recovery_confidence=0.82,
                additional_signatures=[
                    b'PK\x03\x04',  # Local file header
                    b'PK\x01\x02',  # Central directory
                    b'PK\x05\x06'   # End of central directory
                ]
            ),
            
            FileSignature(
                name="RAR",
                extension="rar",
                magic_header=b'\x52\x61\x72\x21\x1A\x07\x00',
                max_size=1024 * 1024 * 1024,  # 1GB
                min_size=128,
                description="WinRAR Archive",
                recovery_confidence=0.90,
                additional_signatures=[b'Rar!\x1a\x07\x00']
            ),
            
            FileSignature(
                name="7Z",
                extension="7z",
                magic_header=b'\x37\x7A\xBC\xAF\x27\x1C',
                max_size=2 * 1024 * 1024 * 1024,  # 2GB
                min_size=128,
                description="7-Zip Archive",
                recovery_confidence=0.92
            ),
            
            # Media formats
            FileSignature(
                name="MP3",
                extension="mp3",
                magic_header=b'\xFF\xFB',
                max_size=100 * 1024 * 1024,
                min_size=512,
                description="MPEG Audio Layer 3",
                recovery_confidence=0.80,
                additional_signatures=[
                    b'\xFF\xFA',  # MPEG Audio Layer 3
                    b'\x49\x44\x33'  # ID3 tag
                ]
            ),
            
            FileSignature(
                name="MP4",
                extension="mp4",
                magic_header=b'\x00\x00\x00\x18\x66\x74\x79\x70',
                max_size=2 * 1024 * 1024 * 1024,  # 2GB
                min_size=1024,
                description="MPEG-4 Video",
                recovery_confidence=0.88,
                additional_signatures=[
                    b'\x00\x00\x00\x20\x66\x74\x79\x70',  # Alternative header
                    b'ftyp'  # File type box
                ]
            ),
            
            FileSignature(
                name="AVI",
                extension="avi",
                magic_header=b'RIFF',
                magic_footer=b'AVI ',
                max_size=4 * 1024 * 1024 * 1024,  # 4GB
                min_size=2048,
                description="Audio Video Interleave",
                recovery_confidence=0.85,
                additional_signatures=[b'RIFF....AVI ']
            ),
            
            FileSignature(
                name="WAV",
                extension="wav",
                magic_header=b'RIFF',
                magic_footer=b'WAVE',
                max_size=1024 * 1024 * 1024,  # 1GB
                min_size=44,  # WAV header size
                description="Waveform Audio File",
                recovery_confidence=0.90,
                additional_signatures=[b'RIFF....WAVE']
            ),
            
            # Additional formats
            FileSignature(
                name="EXE",
                extension="exe",
                magic_header=b'MZ',
                max_size=500 * 1024 * 1024,
                min_size=1024,
                description="Windows Executable",
                recovery_confidence=0.70
            ),
            
            FileSignature(
                name="DLL",
                extension="dll",
                magic_header=b'MZ',
                max_size=100 * 1024 * 1024,
                min_size=512,
                description="Dynamic Link Library",
                recovery_confidence=0.65
            ),
        ]
    
    @staticmethod
    def get_signatures() -> Dict[str, FileSignature]:
        """Get signatures as a dictionary for compatibility"""
        signatures = FileSignatureDatabase.get_carving_signatures()
        return {sig.name: sig for sig in signatures}
    
    @staticmethod
    def detect_file_type(data: bytes) -> Optional[FileSignature]:
        """Detect file type from binary data using signatures"""
        if not data or len(data) < 4:
            return None
        
        signatures = FileSignatureDatabase.get_carving_signatures()
        
        # Check each signature against the data
        for signature in signatures:
            # Check main magic header
            if data.startswith(signature.magic_header):
                return signature
            
            # Check additional signatures if available
            if hasattr(signature, 'additional_signatures') and signature.additional_signatures:
                for alt_sig in signature.additional_signatures:
                    if data.startswith(alt_sig):
                        return signature
        
        return None

class FileCarver:
    """Advanced file carving engine with signature-based recovery"""
    
    def __init__(self, recovery_base_path: str = "Recovered", sector_size: int = 512):
        self.recovery_base_path = Path(recovery_base_path)
        self.sector_size = sector_size
        self.signatures = FileSignatureDatabase.get_carving_signatures()
        self.signature_db = FileSignatureDatabase()  # For compatibility with tests
        self.carved_files: List[CarvedFile] = []
        self.carving_index = {}
        self.carving_statistics = {
            'total_carved': 0,
            'files_by_type': {},
            'total_size_recovered': 0,
            'recovery_start_time': None,
            'recovery_end_time': None
        }
        
        # Create recovery directory structure
        self._initialize_recovery_structure()
    
    def _initialize_recovery_structure(self):
        """Initialize the recovery directory structure"""
        try:
            # Create main recovery directory
            self.recovery_base_path.mkdir(parents=True, exist_ok=True)
            
            # Create subdirectories for each file type
            type_dirs = [
                'Images', 'Documents', 'Archives', 'Media', 
                'Executables', 'Other', 'Metadata', 'Logs'
            ]
            
            for dir_name in type_dirs:
                (self.recovery_base_path / dir_name).mkdir(exist_ok=True)
            
            logger.info(f"Recovery structure initialized at: {self.recovery_base_path}")
            
        except Exception as e:
            logger.error(f"Failed to initialize recovery structure: {e}")
            raise
    
    def carve_from_data(self, data: bytes, source_image: str, start_offset: int = 0) -> List[CarvedFile]:
        """
        Carve files from raw data using signature-based detection
        
        Args:
            data: Raw data to carve from
            source_image: Source image filename
            start_offset: Starting offset in the original image
        
        Returns:
            List of carved files
        """
        carved_files = []
        data_length = len(data)
        
        logger.info(f"Starting file carving on {data_length:,} bytes from {source_image}")
        self.carving_statistics['recovery_start_time'] = datetime.now()
        
        # Search for file signatures
        for signature in self.signatures:
            carved_files.extend(
                self._carve_signature(data, signature, source_image, start_offset)
            )
        
        # Update statistics
        self.carved_files.extend(carved_files)
        self._update_carving_statistics(carved_files)
        
        # Save carving index
        self._save_carving_index()
        
        self.carving_statistics['recovery_end_time'] = datetime.now()
        logger.info(f"File carving completed. Found {len(carved_files)} files.")
        
        return carved_files
    
    def _carve_signature(self, data: bytes, signature: FileSignature, 
                        source_image: str, base_offset: int) -> List[CarvedFile]:
        """Carve files matching a specific signature"""
        carved_files = []
        data_length = len(data)
        search_position = 0
        
        while search_position < data_length - len(signature.magic_header):
            # Search for header signature
            header_pos = data.find(signature.magic_header, search_position)
            
            if header_pos == -1:
                break
            
            # Try additional signatures if available
            if signature.additional_signatures:
                found_match = False
                for alt_sig in signature.additional_signatures:
                    if header_pos + len(alt_sig) <= data_length:
                        if data[header_pos:header_pos + len(alt_sig)] == alt_sig:
                            found_match = True
                            break
                
                if not found_match and signature.additional_signatures:
                    search_position = header_pos + 1
                    continue
            
            # Determine file end position
            end_pos = self._find_file_end(
                data, header_pos, signature, data_length
            )
            
            if end_pos > header_pos + signature.min_size:
                # Extract and validate file
                carved_file = self._extract_and_validate_file(
                    data, header_pos, end_pos, signature, 
                    source_image, base_offset
                )
                
                if carved_file:
                    carved_files.append(carved_file)
                    logger.debug(f"Carved {signature.name}: {carved_file.carved_filename}")
            
            # Move search position forward
            search_position = header_pos + len(signature.magic_header)
        
        return carved_files
    
    def _find_file_end(self, data: bytes, start_pos: int, 
                      signature: FileSignature, data_length: int) -> int:
        """Find the end position of a file based on footer or heuristics"""
        
        # Method 1: Look for footer signature
        if signature.magic_footer:
            footer_pos = data.find(
                signature.magic_footer, 
                start_pos + signature.min_size,
                min(start_pos + signature.max_size, data_length)
            )
            
            if footer_pos != -1:
                return footer_pos + len(signature.magic_footer)
        
        # Method 2: Use file format specific heuristics
        end_pos = self._apply_format_heuristics(
            data, start_pos, signature, data_length
        )
        
        if end_pos > start_pos:
            return min(end_pos, start_pos + signature.max_size, data_length)
        
        # Method 3: Default to maximum size or data end
        return min(start_pos + signature.max_size, data_length)
    
    def _apply_format_heuristics(self, data: bytes, start_pos: int,
                                signature: FileSignature, data_length: int) -> int:
        """Apply format-specific heuristics to find file boundaries"""
        
        if signature.name == "JPEG":
            return self._find_jpeg_end(data, start_pos, data_length)
        elif signature.name == "PNG":
            return self._find_png_end(data, start_pos, data_length)
        elif signature.name == "PDF":
            return self._find_pdf_end(data, start_pos, data_length)
        elif signature.name == "ZIP" or signature.name == "DOCX":
            return self._find_zip_end(data, start_pos, data_length)
        elif signature.name == "MP3":
            return self._find_mp3_end(data, start_pos, data_length)
        
        return -1
    
    def _find_jpeg_end(self, data: bytes, start_pos: int, data_length: int) -> int:
        """Find JPEG file end using EOI marker"""
        search_pos = start_pos + 10  # Skip header
        
        while search_pos < data_length - 1:
            if data[search_pos] == 0xFF and data[search_pos + 1] == 0xD9:
                return search_pos + 2
            search_pos += 1
        
        return -1
    
    def _find_png_end(self, data: bytes, start_pos: int, data_length: int) -> int:
        """Find PNG file end using IEND chunk"""
        search_pos = start_pos + 8  # Skip PNG signature
        
        while search_pos < data_length - 8:
            # Look for IEND chunk
            if data[search_pos:search_pos + 4] == b'IEND':
                return search_pos + 8  # Include CRC
            search_pos += 1
        
        return -1
    
    def _find_pdf_end(self, data: bytes, start_pos: int, data_length: int) -> int:
        """Find PDF file end using %%EOF marker"""
        search_pos = max(start_pos + 100, data_length - 1024)  # Search near end
        
        while search_pos < data_length - 5:
            if data[search_pos:search_pos + 5] == b'%%EOF':
                # Find actual end after %%EOF
                end_search = search_pos + 5
                while end_search < data_length and data[end_search] in b'\r\n\x00':
                    end_search += 1
                return end_search
            search_pos += 1
        
        return -1
    
    def _find_zip_end(self, data: bytes, start_pos: int, data_length: int) -> int:
        """Find ZIP file end using central directory structure"""
        # This is complex - simplified version looks for end of central directory
        search_pos = max(start_pos + 100, data_length - 65536)  # Search last 64KB
        
        while search_pos < data_length - 4:
            if data[search_pos:search_pos + 4] == b'\x50\x4B\x05\x06':
                # Found end of central directory record
                return min(search_pos + 22, data_length)  # Minimum EOCD size
            search_pos += 1
        
        return -1
    
    def _find_mp3_end(self, data: bytes, start_pos: int, data_length: int) -> int:
        """Find MP3 file end using frame analysis"""
        # Simplified MP3 frame detection
        search_pos = start_pos
        frame_count = 0
        
        while search_pos < data_length - 4 and frame_count < 10:  # Check first 10 frames
            if data[search_pos] == 0xFF and (data[search_pos + 1] & 0xE0) == 0xE0:
                # Found sync word, calculate frame size
                frame_size = self._calculate_mp3_frame_size(data[search_pos:search_pos + 4])
                if frame_size > 0:
                    search_pos += frame_size
                    frame_count += 1
                else:
                    break
            else:
                break
        
        return search_pos if frame_count > 0 else -1
    
    def _calculate_mp3_frame_size(self, header: bytes) -> int:
        """Calculate MP3 frame size from header (simplified)"""
        if len(header) < 4:
            return 0
        
        # Simplified calculation - real implementation would be more complex
        bitrate_index = (header[2] >> 4) & 0x0F
        sampling_rate_index = (header[2] >> 2) & 0x03
        padding = (header[2] >> 1) & 0x01
        
        # Basic frame size calculation (simplified)
        if bitrate_index == 0 or sampling_rate_index == 3:
            return 0
        
        # Return approximate frame size
        return 144 + padding
    
    def _extract_and_validate_file(self, data: bytes, start_pos: int, end_pos: int,
                                  signature: FileSignature, source_image: str,
                                  base_offset: int) -> Optional[CarvedFile]:
        """Extract file data and validate it"""
        try:
            file_data = data[start_pos:end_pos]
            file_size = len(file_data)
            
            # Validate minimum size
            if file_size < signature.min_size:
                return None
            
            # Generate file hashes
            md5_hash = hashlib.md5(file_data).hexdigest()
            sha256_hash = hashlib.sha256(file_data).hexdigest()
            
            # Generate unique filename
            file_id = f"{signature.name.lower()}_{md5_hash[:8]}"
            carved_filename = f"{file_id}.{signature.extension}"
            
            # Determine recovery confidence
            confidence = self._calculate_recovery_confidence(
                file_data, signature
            )
            
            # Create carved file object
            carved_file = CarvedFile(
                file_id=file_id,
                original_filename=f"unknown_{file_id}",
                carved_filename=carved_filename,
                file_type=signature.name,
                signature=signature.magic_header.hex(),
                start_offset=base_offset + start_pos,
                end_offset=base_offset + end_pos,
                file_size=file_size,
                md5_hash=md5_hash,
                sha256_hash=sha256_hash,
                recovery_confidence=confidence,
                carved_timestamp=datetime.now(),
                source_image=source_image,
                sector_start=(base_offset + start_pos) // self.sector_size,
                sector_end=(base_offset + end_pos) // self.sector_size,
                data_preview=file_data[:512],
                recovery_status='recovered' if confidence > 0.7 else 'partial'
            )
            
            # Save carved file to disk
            saved_path = self._save_carved_file(carved_file, file_data)
            if saved_path:
                carved_file.metadata['saved_path'] = str(saved_path)
                return carved_file
            
        except Exception as e:
            logger.error(f"Error extracting file at {start_pos}: {e}")
        
        return None
    
    def _calculate_recovery_confidence(self, file_data: bytes, 
                                     signature: FileSignature) -> float:
        """Calculate confidence score for recovered file"""
        confidence = signature.recovery_confidence
        
        # Adjust based on file completeness
        if signature.magic_footer:
            if file_data.endswith(signature.magic_footer):
                confidence += 0.1
            else:
                confidence -= 0.2
        
        # Adjust based on file size reasonableness
        if len(file_data) < signature.min_size * 2:
            confidence -= 0.1
        elif len(file_data) > signature.max_size * 0.8:
            confidence -= 0.05
        
        # Format-specific validation
        if signature.name == "JPEG":
            if b'\xFF\xC0' in file_data or b'\xFF\xC2' in file_data:
                confidence += 0.05
        elif signature.name == "PNG":
            if b'IHDR' in file_data[:100]:
                confidence += 0.05
        
        return max(0.0, min(1.0, confidence))
    
    def _save_carved_file(self, carved_file: CarvedFile, file_data: bytes) -> Optional[Path]:
        """Save carved file to appropriate directory"""
        try:
            # Determine target directory
            target_dir = self._get_target_directory(carved_file.file_type)
            
            # Create unique filename if collision exists
            target_path = target_dir / carved_file.carved_filename
            counter = 1
            while target_path.exists():
                name_parts = carved_file.carved_filename.rsplit('.', 1)
                if len(name_parts) == 2:
                    new_name = f"{name_parts[0]}_{counter}.{name_parts[1]}"
                else:
                    new_name = f"{carved_file.carved_filename}_{counter}"
                target_path = target_dir / new_name
                counter += 1
            
            # Write file data
            with open(target_path, 'wb') as f:
                f.write(file_data)
            
            # Create metadata file
            metadata_path = target_path.with_suffix(target_path.suffix + '.metadata.json')
            self._save_file_metadata(carved_file, metadata_path)
            
            logger.info(f"Carved file saved: {target_path}")
            return target_path
            
        except Exception as e:
            logger.error(f"Failed to save carved file {carved_file.carved_filename}: {e}")
            return None
    
    def _get_target_directory(self, file_type: str) -> Path:
        """Get target directory for file type"""
        type_mapping = {
            'JPEG': 'Images', 'PNG': 'Images', 'GIF': 'Images', 'BMP': 'Images', 'TIFF': 'Images',
            'PDF': 'Documents', 'DOCX': 'Documents', 'RTF': 'Documents',
            'ZIP': 'Archives', 'RAR': 'Archives', '7Z': 'Archives',
            'MP3': 'Media', 'MP4': 'Media', 'AVI': 'Media', 'WAV': 'Media',
            'EXE': 'Executables', 'DLL': 'Executables'
        }
        
        dir_name = type_mapping.get(file_type, 'Other')
        return self.recovery_base_path / dir_name
    
    def _save_file_metadata(self, carved_file: CarvedFile, metadata_path: Path):
        """Save file metadata as JSON"""
        try:
            metadata = {
                'file_id': carved_file.file_id,
                'original_filename': carved_file.original_filename,
                'carved_filename': carved_file.carved_filename,
                'file_type': carved_file.file_type,
                'signature': carved_file.signature,
                'start_offset': carved_file.start_offset,
                'end_offset': carved_file.end_offset,
                'file_size': carved_file.file_size,
                'md5_hash': carved_file.md5_hash,
                'sha256_hash': carved_file.sha256_hash,
                'recovery_confidence': carved_file.recovery_confidence,
                'carved_timestamp': carved_file.carved_timestamp.isoformat(),
                'source_image': carved_file.source_image,
                'sector_start': carved_file.sector_start,
                'sector_end': carved_file.sector_end,
                'recovery_status': carved_file.recovery_status,
                'additional_metadata': carved_file.metadata
            }
            
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2, cls=DateTimeEncoder)
                
        except Exception as e:
            logger.error(f"Failed to save metadata: {e}")
    
    def _update_carving_statistics(self, carved_files: List[CarvedFile]):
        """Update carving statistics"""
        self.carving_statistics['total_carved'] += len(carved_files)
        
        for carved_file in carved_files:
            file_type = carved_file.file_type
            if file_type not in self.carving_statistics['files_by_type']:
                self.carving_statistics['files_by_type'][file_type] = 0
            self.carving_statistics['files_by_type'][file_type] += 1
            self.carving_statistics['total_size_recovered'] += carved_file.file_size
    
    def _save_carving_index(self):
        """Save carving index and statistics"""
        try:
            index_data = {
                'carving_statistics': self.carving_statistics,
                'carved_files': [
                    {
                        'file_id': cf.file_id,
                        'carved_filename': cf.carved_filename,
                        'file_type': cf.file_type,
                        'file_size': cf.file_size,
                        'md5_hash': cf.md5_hash,
                        'recovery_confidence': cf.recovery_confidence,
                        'carved_timestamp': cf.carved_timestamp.isoformat(),
                        'source_image': cf.source_image
                    }
                    for cf in self.carved_files
                ]
            }
            
            index_path = self.recovery_base_path / 'carving_index.json'
            with open(index_path, 'w') as f:
                json.dump(index_data, f, indent=2, cls=DateTimeEncoder)
                
        except Exception as e:
            logger.error(f"Failed to save carving index: {e}")
    
    def get_carving_statistics(self) -> Dict:
        """Get current carving statistics"""
        stats = self.carving_statistics.copy()
        
        if stats['recovery_start_time'] and stats['recovery_end_time']:
            duration = stats['recovery_end_time'] - stats['recovery_start_time']
            stats['recovery_duration_seconds'] = duration.total_seconds()
        
        return stats
    
    def search_carved_files(self, file_type: str = None, min_confidence: float = 0.0,
                           hash_value: str = None) -> List[CarvedFile]:
        """Search carved files by criteria"""
        results = []
        
        for carved_file in self.carved_files:
            # Filter by file type
            if file_type and carved_file.file_type != file_type:
                continue
            
            # Filter by confidence
            if carved_file.recovery_confidence < min_confidence:
                continue
            
            # Filter by hash
            if hash_value and hash_value not in [carved_file.md5_hash, carved_file.sha256_hash]:
                continue
            
            results.append(carved_file)
        
        return results
    
    def carve_from_device(self, device_path: str, progress_callback=None) -> List[CarvedFile]:
        """Carve files from a device or image file"""
        try:
            # Read the entire device/image file
            with open(device_path, 'rb') as f:
                # Get file size
                f.seek(0, 2)  # Seek to end
                file_size = f.tell()
                f.seek(0)     # Seek back to beginning
                
                # Read in chunks to avoid memory issues
                chunk_size = 1024 * 1024  # 1MB chunks
                total_chunks = (file_size + chunk_size - 1) // chunk_size
                
                all_carved_files = []
                current_offset = 0
                
                for chunk_num in range(total_chunks):
                    if progress_callback:
                        progress_callback(chunk_num, total_chunks, f"Processing chunk {chunk_num + 1}/{total_chunks}")
                    
                    # Read chunk
                    data = f.read(chunk_size)
                    if not data:
                        break
                    
                    # Carve files from this chunk
                    carved_files = self.carve_from_data(data, device_path, current_offset)
                    all_carved_files.extend(carved_files)
                    
                    current_offset += len(data)
                
                if progress_callback:
                    progress_callback(total_chunks, total_chunks, f"Carving completed - Found {len(all_carved_files)} files")
                
                return all_carved_files
                
        except Exception as e:
            logging.error(f"Error carving from device {device_path}: {e}")
            return []
    
    def get_recovery_statistics(self) -> Dict:
        """Alias for get_carving_statistics for compatibility"""
        return self.get_carving_statistics()