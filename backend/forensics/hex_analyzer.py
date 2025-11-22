"""
Hex Analyzer - Byte-level File Analysis for Digital Forensics
===========================================================

Provides comprehensive binary data analysis including:
- Hex dump generation with ASCII representation
- File signature detection and validation
- Byte pattern analysis and anomaly detection
- File structure analysis
- Entropy calculation for detecting encryption/compression
- String extraction from binary data
- Byte frequency analysis
- Magic number validation
"""

import os
import struct
import re
import math
import binascii
from collections import Counter
from typing import Dict, List, Tuple, Optional, Any
import hashlib

class HexAnalyzer:
    """Advanced hex analysis and byte-level inspection"""
    
    def __init__(self):
        self.file_signatures = {
            # Image formats
            b'\xFF\xD8\xFF': {'type': 'JPEG', 'extension': '.jpg', 'description': 'JPEG Image'},
            b'\x89PNG\r\n\x1a\n': {'type': 'PNG', 'extension': '.png', 'description': 'PNG Image'},
            b'GIF87a': {'type': 'GIF', 'extension': '.gif', 'description': 'GIF Image (87a)'},
            b'GIF89a': {'type': 'GIF', 'extension': '.gif', 'description': 'GIF Image (89a)'},
            b'BM': {'type': 'BMP', 'extension': '.bmp', 'description': 'Bitmap Image'},
            b'RIFF': {'type': 'WEBP', 'extension': '.webp', 'description': 'WebP Image (check for WEBP)'},
            b'\x00\x00\x01\x00': {'type': 'ICO', 'extension': '.ico', 'description': 'Icon File'},
            
            # Document formats
            b'%PDF': {'type': 'PDF', 'extension': '.pdf', 'description': 'PDF Document'},
            b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': {'type': 'DOC', 'extension': '.doc', 'description': 'Microsoft Office Document'},
            b'PK\x03\x04': {'type': 'ZIP', 'extension': '.zip', 'description': 'ZIP Archive or Office Document'},
            
            # Executable formats
            b'MZ': {'type': 'EXE', 'extension': '.exe', 'description': 'Windows Executable'},
            b'\x7fELF': {'type': 'ELF', 'extension': '', 'description': 'Linux Executable'},
            
            # Archive formats
            b'Rar!\x1a\x07\x00': {'type': 'RAR', 'extension': '.rar', 'description': 'RAR Archive'},
            b'\x1f\x8b': {'type': 'GZIP', 'extension': '.gz', 'description': 'GZIP Compressed'},
            
            # Media formats
            b'\x00\x00\x00\x18ftypmp4': {'type': 'MP4', 'extension': '.mp4', 'description': 'MP4 Video'},
            b'ID3': {'type': 'MP3', 'extension': '.mp3', 'description': 'MP3 Audio'},
            
            # Other formats
            b'\xca\xfe\xba\xbe': {'type': 'CLASS', 'extension': '.class', 'description': 'Java Class File'},
            b'\xfe\xed\xfa\xce': {'type': 'MACHO', 'extension': '', 'description': 'Mach-O Binary (32-bit)'},
            b'\xfe\xed\xfa\xcf': {'type': 'MACHO', 'extension': '', 'description': 'Mach-O Binary (64-bit)'},
        }
        
    def analyze_file(self, file_path: str, max_bytes: int = 1024*1024) -> Dict[str, Any]:
        """Perform comprehensive hex analysis of a file"""
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
                
            file_size = os.path.getsize(file_path)
            
            with open(file_path, 'rb') as f:
                # Read file data (limit to max_bytes for large files)
                data = f.read(min(file_size, max_bytes))
                
            analysis_result = {
                'file_info': {
                    'path': file_path,
                    'name': os.path.basename(file_path),
                    'size': file_size,
                    'analyzed_bytes': len(data),
                    'is_truncated': len(data) < file_size
                },
                'file_signature': self._analyze_file_signature(data),
                'hex_dump': self._generate_hex_dump(data, max_lines=100),
                'byte_analysis': self._analyze_bytes(data),
                'string_analysis': self._extract_strings(data),
                'entropy_analysis': self._calculate_entropy(data),
                'structure_analysis': self._analyze_structure(data),
                'hash_values': self._calculate_hashes(data),
                'anomalies': self._detect_anomalies(data, file_path)
            }
            
            return analysis_result
            
        except Exception as e:
            return {
                'error': str(e),
                'file_info': {
                    'path': file_path,
                    'name': os.path.basename(file_path),
                    'size': 0,
                    'analyzed_bytes': 0,
                    'is_truncated': False
                }
            }
    
    def _analyze_file_signature(self, data: bytes) -> Dict[str, Any]:
        """Analyze file signature and magic numbers"""
        if len(data) < 16:
            return {'detected': False, 'reason': 'Insufficient data'}
            
        # Check known signatures
        detected_signatures = []
        
        for signature, info in self.file_signatures.items():
            if data.startswith(signature):
                detected_signatures.append({
                    'signature': signature.hex().upper(),
                    'type': info['type'],
                    'extension': info['extension'],
                    'description': info['description'],
                    'offset': 0
                })
        
        # Check for signatures at other offsets (e.g., WEBP)
        if data.startswith(b'RIFF') and b'WEBP' in data[:16]:
            detected_signatures.append({
                'signature': 'RIFF...WEBP',
                'type': 'WEBP',
                'extension': '.webp',
                'description': 'WebP Image',
                'offset': 0
            })
        
        # Check for embedded signatures
        embedded_signatures = self._find_embedded_signatures(data)
        
        return {
            'detected': len(detected_signatures) > 0,
            'signatures': detected_signatures,
            'embedded_signatures': embedded_signatures,
            'header_hex': data[:32].hex().upper(),
            'header_ascii': self._bytes_to_ascii(data[:32])
        }
    
    def _find_embedded_signatures(self, data: bytes, max_search: int = 1024) -> List[Dict]:
        """Find embedded file signatures within the data"""
        embedded = []
        search_data = data[:max_search]
        
        for signature, info in self.file_signatures.items():
            if len(signature) <= len(search_data):
                offset = search_data.find(signature, 1)  # Skip offset 0
                if offset > 0:
                    embedded.append({
                        'signature': signature.hex().upper(),
                        'type': info['type'],
                        'description': info['description'],
                        'offset': offset
                    })
        
        return embedded
    
    def _generate_hex_dump(self, data: bytes, max_lines: int = 100, bytes_per_line: int = 16) -> Dict[str, Any]:
        """Generate hex dump with ASCII representation"""
        lines = []
        total_lines = min(len(data) // bytes_per_line + (1 if len(data) % bytes_per_line else 0), max_lines)
        
        for i in range(total_lines):
            offset = i * bytes_per_line
            chunk = data[offset:offset + bytes_per_line]
            
            # Format hex bytes
            hex_part = ' '.join(f'{b:02X}' for b in chunk)
            hex_part = hex_part.ljust(bytes_per_line * 3 - 1)  # Pad to consistent width
            
            # Format ASCII representation
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            
            lines.append({
                'offset': f'{offset:08X}',
                'hex': hex_part,
                'ascii': ascii_part,
                'bytes': len(chunk)
            })
        
        return {
            'lines': lines,
            'total_lines': total_lines,
            'bytes_per_line': bytes_per_line,
            'is_truncated': len(data) > max_lines * bytes_per_line
        }
    
    def _analyze_bytes(self, data: bytes) -> Dict[str, Any]:
        """Analyze byte patterns and frequency"""
        if not data:
            return {'error': 'No data to analyze'}
            
        byte_counts = Counter(data)
        total_bytes = len(data)
        
        # Calculate frequency statistics
        frequencies = {byte: count / total_bytes for byte, count in byte_counts.items()}
        
        # Find most and least common bytes
        most_common = byte_counts.most_common(10)
        least_common = [(byte, count) for byte, count in sorted(byte_counts.items(), key=lambda x: x[1])[:10]]
        
        # Analyze byte distribution
        unique_bytes = len(byte_counts)
        byte_coverage = unique_bytes / 256  # Percentage of possible byte values used
        
        # Check for patterns
        null_bytes = byte_counts.get(0, 0)
        null_percentage = (null_bytes / total_bytes) * 100
        
        # High entropy bytes (potential encrypted/compressed data)
        high_entropy_bytes = sum(1 for freq in frequencies.values() if 0.003 <= freq <= 0.005)
        
        return {
            'total_bytes': total_bytes,
            'unique_bytes': unique_bytes,
            'byte_coverage': byte_coverage,
            'null_bytes': null_bytes,
            'null_percentage': null_percentage,
            'most_common_bytes': [{'byte': f'0x{byte:02X}', 'count': count, 'percentage': (count/total_bytes)*100} 
                                 for byte, count in most_common],
            'least_common_bytes': [{'byte': f'0x{byte:02X}', 'count': count, 'percentage': (count/total_bytes)*100} 
                                  for byte, count in least_common],
            'high_entropy_indicator': high_entropy_bytes,
            'distribution_analysis': {
                'uniform_distribution': abs(byte_coverage - 0.5) < 0.2,  # Roughly uniform distribution
                'sparse_distribution': byte_coverage < 0.1,  # Very few unique bytes
                'dense_distribution': byte_coverage > 0.8   # Most byte values present
            }
        }
    
    def _extract_strings(self, data: bytes, min_length: int = 4, max_strings: int = 100) -> Dict[str, Any]:
        """Extract printable strings from binary data"""
        # ASCII strings
        ascii_pattern = rb'[ -~]{' + str(min_length).encode() + rb',}'
        ascii_strings = re.findall(ascii_pattern, data)
        ascii_strings = [s.decode('ascii', errors='ignore') for s in ascii_strings[:max_strings]]
        
        # Unicode strings (UTF-16)
        unicode_strings = []
        try:
            # Look for UTF-16 patterns
            for i in range(0, min(len(data) - 1, 2048), 2):
                chunk = data[i:i+20]  # Check small chunks
                if b'\x00' in chunk and len(chunk) >= 8:  # Likely UTF-16
                    try:
                        decoded = chunk.decode('utf-16le', errors='ignore')
                        if len(decoded) >= min_length and decoded.isprintable():
                            unicode_strings.append(decoded.strip('\x00'))
                            if len(unicode_strings) >= 20:  # Limit Unicode strings
                                break
                    except:
                        continue
        except:
            pass
        
        # Look for URLs, emails, file paths
        interesting_patterns = {
            'urls': re.findall(rb'https?://[^\s<>"{}|\\^`\[\]]+', data),
            'emails': re.findall(rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', data),
            'file_paths': re.findall(rb'[A-Za-z]:\\[^<>:"|?*\x00-\x1f]+', data),  # Windows paths
            'registry_keys': re.findall(rb'HKEY_[A-Z_]+\\[^<>:"|?*\x00-\x1f]+', data)
        }
        
        # Decode pattern matches
        for category, matches in interesting_patterns.items():
            interesting_patterns[category] = [match.decode('ascii', errors='ignore') 
                                            for match in matches[:20]]  # Limit results
        
        return {
            'ascii_strings': ascii_strings,
            'unicode_strings': list(set(unicode_strings)),  # Remove duplicates
            'interesting_patterns': interesting_patterns,
            'total_ascii_strings': len(ascii_strings),
            'total_unicode_strings': len(unicode_strings)
        }
    
    def _calculate_entropy(self, data: bytes) -> Dict[str, Any]:
        """Calculate Shannon entropy and analyze randomness"""
        if not data:
            return {'entropy': 0, 'analysis': 'No data'}
            
        # Calculate Shannon entropy
        byte_counts = Counter(data)
        total_bytes = len(data)
        
        entropy = 0
        for count in byte_counts.values():
            probability = count / total_bytes
            entropy -= probability * math.log2(probability)
        
        # Analyze entropy sections (divide file into chunks)
        chunk_size = max(256, len(data) // 10)  # Analyze in chunks
        chunk_entropies = []
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            if len(chunk) > 10:  # Skip very small chunks
                chunk_counts = Counter(chunk)
                chunk_entropy = 0
                for count in chunk_counts.values():
                    prob = count / len(chunk)
                    chunk_entropy -= prob * math.log2(prob)
                chunk_entropies.append({
                    'offset': i,
                    'size': len(chunk),
                    'entropy': chunk_entropy
                })
        
        # Entropy analysis
        max_entropy = 8.0  # Maximum possible entropy for 8-bit bytes
        entropy_percentage = (entropy / max_entropy) * 100
        
        entropy_analysis = 'Unknown'
        if entropy < 2.0:
            entropy_analysis = 'Very Low (Highly structured/repetitive data)'
        elif entropy < 4.0:
            entropy_analysis = 'Low (Structured data, text files)'
        elif entropy < 6.0:
            entropy_analysis = 'Medium (Mixed content)'
        elif entropy < 7.5:
            entropy_analysis = 'High (Compressed or encrypted data)'
        else:
            entropy_analysis = 'Very High (Random or heavily encrypted data)'
        
        return {
            'overall_entropy': entropy,
            'entropy_percentage': entropy_percentage,
            'max_possible_entropy': max_entropy,
            'analysis': entropy_analysis,
            'chunk_entropies': chunk_entropies,
            'entropy_variance': max(chunk_entropies, key=lambda x: x['entropy'])['entropy'] - 
                              min(chunk_entropies, key=lambda x: x['entropy'])['entropy'] if chunk_entropies else 0
        }
    
    def _analyze_structure(self, data: bytes) -> Dict[str, Any]:
        """Analyze file structure and format-specific patterns"""
        structure_info = {
            'file_sections': [],
            'padding_analysis': {},
            'alignment_analysis': {},
            'format_specific': {}
        }
        
        # Analyze padding (sequences of null bytes or repeated patterns)
        null_sequences = []
        current_seq_start = None
        current_seq_length = 0
        
        for i, byte in enumerate(data):
            if byte == 0:
                if current_seq_start is None:
                    current_seq_start = i
                current_seq_length += 1
            else:
                if current_seq_start is not None and current_seq_length >= 16:
                    null_sequences.append({
                        'start': current_seq_start,
                        'length': current_seq_length,
                        'end': current_seq_start + current_seq_length - 1
                    })
                current_seq_start = None
                current_seq_length = 0
        
        # Check final sequence
        if current_seq_start is not None and current_seq_length >= 16:
            null_sequences.append({
                'start': current_seq_start,
                'length': current_seq_length,
                'end': current_seq_start + current_seq_length - 1
            })
        
        structure_info['padding_analysis'] = {
            'null_sequences': null_sequences,
            'total_null_bytes': sum(seq['length'] for seq in null_sequences),
            'null_percentage': (sum(seq['length'] for seq in null_sequences) / len(data)) * 100 if data else 0
        }
        
        # Analyze alignment patterns (check for common alignment boundaries)
        alignment_patterns = {}
        for alignment in [4, 8, 16, 32, 64, 128, 256, 512, 1024]:
            aligned_positions = []
            for i in range(alignment, len(data), alignment):
                if i < len(data):
                    aligned_positions.append(i)
            
            if aligned_positions:
                # Check if significant data starts at aligned positions
                significant_at_alignment = 0
                for pos in aligned_positions[:50]:  # Check first 50 positions
                    if pos < len(data) - 4:
                        chunk = data[pos:pos+4]
                        if not all(b == 0 for b in chunk):  # Non-zero data
                            significant_at_alignment += 1
                
                alignment_patterns[alignment] = {
                    'positions_checked': min(50, len(aligned_positions)),
                    'significant_positions': significant_at_alignment,
                    'significance_ratio': significant_at_alignment / min(50, len(aligned_positions)) if aligned_positions else 0
                }
        
        structure_info['alignment_analysis'] = alignment_patterns
        
        # Format-specific analysis
        if data.startswith(b'\xFF\xD8\xFF'):  # JPEG
            structure_info['format_specific']['jpeg'] = self._analyze_jpeg_structure(data)
        elif data.startswith(b'\x89PNG\r\n\x1a\n'):  # PNG
            structure_info['format_specific']['png'] = self._analyze_png_structure(data)
        elif data.startswith(b'%PDF'):  # PDF
            structure_info['format_specific']['pdf'] = self._analyze_pdf_structure(data)
        
        return structure_info
    
    def _analyze_jpeg_structure(self, data: bytes) -> Dict[str, Any]:
        """Analyze JPEG file structure"""
        markers = []
        i = 0
        
        while i < len(data) - 1:
            if data[i] == 0xFF and data[i + 1] != 0xFF and data[i + 1] != 0x00:
                marker = data[i:i+2]
                markers.append({
                    'offset': i,
                    'marker': marker.hex().upper(),
                    'type': self._get_jpeg_marker_type(data[i + 1])
                })
                
                # Skip to next potential marker
                if data[i + 1] in [0xD8, 0xD9]:  # SOI, EOI - no length
                    i += 2
                elif i + 3 < len(data):
                    length = struct.unpack('>H', data[i+2:i+4])[0]
                    i += 2 + length
                else:
                    i += 2
            else:
                i += 1
        
        return {
            'markers_found': len(markers),
            'markers': markers[:20],  # Limit to first 20 markers
            'has_soi': any(m['marker'] == 'FFD8' for m in markers),
            'has_eoi': any(m['marker'] == 'FFD9' for m in markers)
        }
    
    def _analyze_png_structure(self, data: bytes) -> Dict[str, Any]:
        """Analyze PNG file structure"""
        chunks = []
        i = 8  # Skip PNG signature
        
        while i < len(data) - 8:
            if i + 8 > len(data):
                break
                
            try:
                length = struct.unpack('>I', data[i:i+4])[0]
                chunk_type = data[i+4:i+8].decode('ascii', errors='ignore')
                
                chunks.append({
                    'offset': i,
                    'length': length,
                    'type': chunk_type,
                    'critical': chunk_type[0].isupper()
                })
                
                i += 8 + length + 4  # Length + type + data + CRC
                
                if len(chunks) > 50:  # Limit chunks analyzed
                    break
                    
            except (struct.error, UnicodeDecodeError):
                break
        
        return {
            'chunks_found': len(chunks),
            'chunks': chunks,
            'has_ihdr': any(c['type'] == 'IHDR' for c in chunks),
            'has_iend': any(c['type'] == 'IEND' for c in chunks),
            'critical_chunks': [c for c in chunks if c.get('critical', True)],
            'ancillary_chunks': [c for c in chunks if not c.get('critical', True)]
        }
    
    def _analyze_pdf_structure(self, data: bytes) -> Dict[str, Any]:
        """Analyze PDF file structure"""
        # Look for PDF objects and xref tables
        pdf_objects = []
        xref_tables = []
        
        # Find object definitions
        object_pattern = rb'\d+\s+\d+\s+obj'
        for match in re.finditer(object_pattern, data):
            pdf_objects.append({
                'offset': match.start(),
                'definition': match.group().decode('ascii', errors='ignore')
            })
        
        # Find xref tables
        xref_pattern = rb'xref'
        for match in re.finditer(xref_pattern, data):
            xref_tables.append({
                'offset': match.start()
            })
        
        return {
            'pdf_objects': len(pdf_objects),
            'xref_tables': len(xref_tables),
            'objects': pdf_objects[:20],  # Limit to first 20
            'xref_positions': xref_tables
        }
    
    def _get_jpeg_marker_type(self, marker_byte: int) -> str:
        """Get JPEG marker type description"""
        marker_types = {
            0xD8: 'SOI (Start of Image)',
            0xD9: 'EOI (End of Image)',
            0xDA: 'SOS (Start of Scan)',
            0xDB: 'DQT (Quantization Table)',
            0xC0: 'SOF0 (Start of Frame)',
            0xC4: 'DHT (Huffman Table)',
            0xE0: 'APP0 (Application Data)',
            0xE1: 'APP1 (Application Data)',
            0xFE: 'COM (Comment)'
        }
        return marker_types.get(marker_byte, f'Unknown (0x{marker_byte:02X})')
    
    def _calculate_hashes(self, data: bytes) -> Dict[str, str]:
        """Calculate various hash values for the data"""
        return {
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest()
        }
    
    def _detect_anomalies(self, data: bytes, file_path: str) -> List[Dict[str, Any]]:
        """Detect potential anomalies in the file"""
        anomalies = []
        
        # Check file extension vs signature mismatch
        file_ext = os.path.splitext(file_path)[1].lower()
        signature_analysis = self._analyze_file_signature(data)
        
        if signature_analysis['detected'] and signature_analysis['signatures']:
            expected_ext = signature_analysis['signatures'][0]['extension']
            if expected_ext and file_ext != expected_ext:
                anomalies.append({
                    'type': 'signature_mismatch',
                    'description': f'File extension "{file_ext}" does not match detected signature "{expected_ext}"',
                    'severity': 'medium',
                    'details': {
                        'file_extension': file_ext,
                        'detected_signature': signature_analysis['signatures'][0]['type']
                    }
                })
        
        # Check for multiple file signatures (polyglot files)
        if len(signature_analysis.get('signatures', [])) > 1:
            anomalies.append({
                'type': 'multiple_signatures',
                'description': 'Multiple file signatures detected - possible polyglot file',
                'severity': 'high',
                'details': {
                    'signatures': signature_analysis['signatures']
                }
            })
        
        # Check for embedded signatures
        if signature_analysis.get('embedded_signatures'):
            anomalies.append({
                'type': 'embedded_signatures',
                'description': 'Embedded file signatures found - possible steganography or hidden content',
                'severity': 'high',
                'details': {
                    'embedded_signatures': signature_analysis['embedded_signatures']
                }
            })
        
        # Check entropy anomalies
        entropy_analysis = self._calculate_entropy(data)
        if entropy_analysis['overall_entropy'] > 7.8:
            anomalies.append({
                'type': 'high_entropy',
                'description': 'Very high entropy detected - possible encryption or compression',
                'severity': 'medium',
                'details': {
                    'entropy': entropy_analysis['overall_entropy'],
                    'analysis': entropy_analysis['analysis']
                }
            })
        
        # Check for suspicious padding
        structure_analysis = self._analyze_structure(data)
        null_percentage = structure_analysis['padding_analysis']['null_percentage']
        if null_percentage > 50:
            anomalies.append({
                'type': 'excessive_padding',
                'description': f'Excessive null byte padding detected ({null_percentage:.1f}%)',
                'severity': 'low',
                'details': {
                    'null_percentage': null_percentage,
                    'null_sequences': len(structure_analysis['padding_analysis']['null_sequences'])
                }
            })
        
        # Check for truncated files
        if len(data) < 1024 and not any(data.endswith(sig) for sig in [b'\xFF\xD9', b'IEND']):
            anomalies.append({
                'type': 'possibly_truncated',
                'description': 'File appears to be truncated or corrupted',
                'severity': 'medium',
                'details': {
                    'file_size': len(data)
                }
            })
        
        return anomalies
    
    def _bytes_to_ascii(self, data: bytes) -> str:
        """Convert bytes to ASCII representation with dots for non-printable"""
        return ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
    
    def search_pattern(self, file_path: str, pattern: str, search_type: str = 'hex') -> Dict[str, Any]:
        """Search for specific patterns in the file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            matches = []
            
            if search_type == 'hex':
                # Convert hex pattern to bytes
                try:
                    pattern_bytes = bytes.fromhex(pattern.replace(' ', '').replace('0x', ''))
                except ValueError:
                    return {'error': 'Invalid hex pattern'}
                    
                # Find all occurrences
                start = 0
                while True:
                    pos = data.find(pattern_bytes, start)
                    if pos == -1:
                        break
                    matches.append({
                        'offset': pos,
                        'context_before': data[max(0, pos-16):pos].hex().upper(),
                        'match': pattern_bytes.hex().upper(),
                        'context_after': data[pos+len(pattern_bytes):pos+len(pattern_bytes)+16].hex().upper()
                    })
                    start = pos + 1
                    
            elif search_type == 'ascii':
                pattern_bytes = pattern.encode('ascii', errors='ignore')
                start = 0
                while True:
                    pos = data.find(pattern_bytes, start)
                    if pos == -1:
                        break
                    matches.append({
                        'offset': pos,
                        'context_before': self._bytes_to_ascii(data[max(0, pos-16):pos]),
                        'match': pattern,
                        'context_after': self._bytes_to_ascii(data[pos+len(pattern_bytes):pos+len(pattern_bytes)+16])
                    })
                    start = pos + 1
            
            return {
                'pattern': pattern,
                'search_type': search_type,
                'matches_found': len(matches),
                'matches': matches[:100]  # Limit to first 100 matches
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def compare_files(self, file1_path: str, file2_path: str) -> Dict[str, Any]:
        """Compare two files at byte level"""
        try:
            with open(file1_path, 'rb') as f1, open(file2_path, 'rb') as f2:
                data1 = f1.read()
                data2 = f2.read()
            
            # Basic comparison
            files_identical = data1 == data2
            size_diff = len(data2) - len(data1)
            
            # Find differences
            differences = []
            min_length = min(len(data1), len(data2))
            
            for i in range(min_length):
                if data1[i] != data2[i]:
                    differences.append({
                        'offset': i,
                        'file1_byte': f'0x{data1[i]:02X}',
                        'file2_byte': f'0x{data2[i]:02X}',
                        'context': {
                            'before': data1[max(0, i-8):i].hex().upper(),
                            'after': data1[i+1:i+9].hex().upper()
                        }
                    })
                    
                    if len(differences) >= 100:  # Limit differences shown
                        break
            
            # Calculate similarity percentage
            if min_length > 0:
                similarity = ((min_length - len(differences)) / min_length) * 100
            else:
                similarity = 0 if len(data1) != len(data2) else 100
            
            return {
                'files_identical': files_identical,
                'file1_size': len(data1),
                'file2_size': len(data2),
                'size_difference': size_diff,
                'bytes_compared': min_length,
                'differences_found': len(differences),
                'similarity_percentage': similarity,
                'differences': differences,
                'hash_comparison': {
                    'file1_md5': hashlib.md5(data1).hexdigest(),
                    'file2_md5': hashlib.md5(data2).hexdigest(),
                    'hashes_match': hashlib.md5(data1).hexdigest() == hashlib.md5(data2).hexdigest()
                }
            }
            
        except Exception as e:
            return {'error': str(e)}