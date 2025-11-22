"""
EXIF Metadata Extraction Tool
============================

Comprehensive EXIF metadata extraction for digital forensics analysis.
Extracts camera information, GPS data, timestamps, and technical details
from uploaded images.
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
import logging
from PIL import Image, ExifTags
from PIL.ExifTags import TAGS, GPSTAGS
import exifread
import base64
import io


class EXIFMetadataExtractor:
    """
    Advanced EXIF metadata extraction tool for forensic image analysis.
    Supports multiple extraction methods and comprehensive metadata parsing.
    """
    
    def __init__(self):
        """Initialize the EXIF metadata extractor"""
        self.logger = logging.getLogger(__name__)
        
        # Initialize EXIF tag mappings
        self.exif_tags = {v: k for k, v in TAGS.items()}
        self.gps_tags = {v: k for k, v in GPSTAGS.items()}
        
        # Define critical metadata categories
        self.camera_tags = [
            'Make', 'Model', 'LensModel', 'LensMake', 'LensSerialNumber',
            'SerialNumber', 'BodySerialNumber', 'CameraOwnerName'
        ]
        
        self.settings_tags = [
            'DateTime', 'DateTimeOriginal', 'DateTimeDigitized',
            'ExposureTime', 'FNumber', 'ISOSpeedRatings', 'ISO',
            'Flash', 'FocalLength', 'WhiteBalance', 'MeteringMode',
            'ExposureMode', 'SceneCaptureType', 'Contrast', 'Saturation',
            'Sharpness', 'ExposureProgram', 'ExposureBiasValue'
        ]
        
        self.technical_tags = [
            'Software', 'ProcessingSoftware', 'Orientation', 'XResolution',
            'YResolution', 'ResolutionUnit', 'ColorSpace', 'ExifVersion',
            'FlashPixVersion', 'ComponentsConfiguration', 'CompressedBitsPerPixel'
        ]

    def extract_comprehensive_metadata(self, image_path: str) -> Dict[str, Any]:
        """
        Extract comprehensive EXIF metadata from an image file.
        
        Args:
            image_path: Path to the image file
            
        Returns:
            Dictionary containing organized metadata
        """
        try:
            metadata = {
                'file_info': self._get_file_info(image_path),
                'exif_data': {},
                'camera_info': {},
                'capture_settings': {},
                'technical_info': {},
                'gps_data': {},
                'software_info': {},
                'timestamps': {},
                'thumbnail_info': {},
                'forensic_notes': []
            }
            
            # Extract using Pillow
            pillow_data = self._extract_with_pillow(image_path)
            if pillow_data:
                metadata['exif_data'].update(pillow_data)
            
            # Extract using exifread for additional details
            exifread_data = self._extract_with_exifread(image_path)
            if exifread_data:
                metadata['exif_data'].update(exifread_data)
            
            # Organize metadata into categories
            self._categorize_metadata(metadata)
            
            # Extract GPS information
            metadata['gps_data'] = self._extract_gps_data(metadata['exif_data'])
            
            # Extract thumbnail information
            metadata['thumbnail_info'] = self._extract_thumbnail_info(image_path)
            
            # Add forensic analysis notes
            metadata['forensic_notes'] = self._generate_forensic_notes(metadata)
            
            return metadata
            
        except Exception as e:
            self.logger.error(f"Error extracting metadata from {image_path}: {str(e)}")
            return {'error': str(e), 'file_path': image_path}

    def _get_file_info(self, image_path: str) -> Dict[str, Any]:
        """Extract basic file information"""
        try:
            stat = os.stat(image_path)
            file_info = {
                'filename': os.path.basename(image_path),
                'file_size': stat.st_size,
                'file_size_mb': round(stat.st_size / (1024 * 1024), 2),
                'creation_time': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modification_time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'access_time': datetime.fromtimestamp(stat.st_atime).isoformat(),
                'file_extension': os.path.splitext(image_path)[1].lower()
            }
            
            # Get image dimensions
            try:
                with Image.open(image_path) as img:
                    file_info['image_width'] = img.width
                    file_info['image_height'] = img.height
                    file_info['image_mode'] = img.mode
                    file_info['image_format'] = img.format
                    file_info['has_transparency'] = img.mode in ('RGBA', 'LA') or 'transparency' in img.info
            except Exception as e:
                self.logger.warning(f"Could not get image dimensions: {str(e)}")
            
            return file_info
            
        except Exception as e:
            self.logger.error(f"Error getting file info: {str(e)}")
            return {}

    def _extract_with_pillow(self, image_path: str) -> Dict[str, Any]:
        """Extract EXIF data using Pillow library"""
        try:
            with Image.open(image_path) as image:
                exifdata = image.getexif()
                
                if not exifdata:
                    return {}
                
                metadata = {}
                for tag_id in exifdata:
                    tag = TAGS.get(tag_id, tag_id)
                    data = exifdata.get(tag_id)
                    
                    # Handle special data types
                    if isinstance(data, bytes):
                        try:
                            data = data.decode('utf-8', errors='ignore')
                        except:
                            data = str(data)
                    elif isinstance(data, tuple) and len(data) == 2:
                        # Handle rational numbers (fractions)
                        if data[1] != 0:
                            data = f"{data[0]}/{data[1]} ({data[0]/data[1]:.3f})"
                        else:
                            data = str(data[0])
                    
                    metadata[tag] = data
                
                return metadata
                
        except Exception as e:
            self.logger.error(f"Pillow extraction error: {str(e)}")
            return {}

    def _extract_with_exifread(self, image_path: str) -> Dict[str, Any]:
        """Extract EXIF data using exifread library for additional details"""
        try:
            metadata = {}
            
            with open(image_path, 'rb') as f:
                tags = exifread.process_file(f, details=True)
                
                for tag in tags.keys():
                    if tag not in ['JPEGThumbnail', 'TIFFThumbnail', 'Filename', 'EXIF MakerNote']:
                        try:
                            value = str(tags[tag])
                            # Clean up tag name
                            clean_tag = tag.replace('EXIF ', '').replace('Image ', '').replace('GPS ', '')
                            metadata[clean_tag] = value
                        except:
                            continue
            
            return metadata
            
        except Exception as e:
            self.logger.error(f"Exifread extraction error: {str(e)}")
            return {}

    def _categorize_metadata(self, metadata: Dict[str, Any]) -> None:
        """Organize EXIF data into logical categories"""
        exif_data = metadata['exif_data']
        
        # Camera information
        for tag in self.camera_tags:
            if tag in exif_data:
                metadata['camera_info'][tag] = exif_data[tag]
        
        # Capture settings
        for tag in self.settings_tags:
            if tag in exif_data:
                metadata['capture_settings'][tag] = exif_data[tag]
        
        # Technical information
        for tag in self.technical_tags:
            if tag in exif_data:
                metadata['technical_info'][tag] = exif_data[tag]
        
        # Software information
        software_tags = ['Software', 'ProcessingSoftware', 'HostComputer', 'Artist', 'Copyright']
        for tag in software_tags:
            if tag in exif_data:
                metadata['software_info'][tag] = exif_data[tag]
        
        # Timestamps
        timestamp_tags = ['DateTime', 'DateTimeOriginal', 'DateTimeDigitized', 'SubSecTime', 
                         'SubSecTimeOriginal', 'SubSecTimeDigitized']
        for tag in timestamp_tags:
            if tag in exif_data:
                metadata['timestamps'][tag] = exif_data[tag]

    def _extract_gps_data(self, exif_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and process GPS information"""
        gps_info = {}
        
        try:
            # Look for GPS data in various formats
            gps_tags = [
                'GPSLatitude', 'GPSLatitudeRef', 'GPSLongitude', 'GPSLongitudeRef',
                'GPSAltitude', 'GPSAltitudeRef', 'GPSTimeStamp', 'GPSDateStamp',
                'GPSSpeed', 'GPSSpeedRef', 'GPSImgDirection', 'GPSImgDirectionRef',
                'GPSDestBearing', 'GPSDestBearingRef', 'GPSProcessingMethod'
            ]
            
            for tag in gps_tags:
                if tag in exif_data:
                    gps_info[tag] = exif_data[tag]
            
            # Convert GPS coordinates to decimal degrees
            if 'GPSLatitude' in gps_info and 'GPSLongitude' in gps_info:
                try:
                    lat_decimal = self._gps_to_decimal(
                        gps_info['GPSLatitude'], 
                        gps_info.get('GPSLatitudeRef', 'N')
                    )
                    lon_decimal = self._gps_to_decimal(
                        gps_info['GPSLongitude'], 
                        gps_info.get('GPSLongitudeRef', 'E')
                    )
                    
                    if lat_decimal is not None and lon_decimal is not None:
                        gps_info['decimal_latitude'] = lat_decimal
                        gps_info['decimal_longitude'] = lon_decimal
                        gps_info['coordinates_string'] = f"{lat_decimal:.6f}, {lon_decimal:.6f}"
                        
                        # Generate map link
                        gps_info['google_maps_link'] = f"https://www.google.com/maps?q={lat_decimal},{lon_decimal}"
                        
                except Exception as e:
                    self.logger.warning(f"GPS coordinate conversion error: {str(e)}")
            
            return gps_info
            
        except Exception as e:
            self.logger.error(f"GPS extraction error: {str(e)}")
            return {}

    def _gps_to_decimal(self, coordinate_str: str, reference: str) -> Optional[float]:
        """Convert GPS coordinates from DMS to decimal degrees"""
        try:
            # Handle different coordinate formats
            if isinstance(coordinate_str, str):
                # Parse coordinate string like "[41, 53, 23.77]" or "41/1, 53/1, 2377/100"
                coord_str = coordinate_str.strip('[]')
                parts = [part.strip() for part in coord_str.split(',')]
                
                degrees = float(parts[0].split('/')[0]) / float(parts[0].split('/')[1]) if '/' in parts[0] else float(parts[0])
                minutes = float(parts[1].split('/')[0]) / float(parts[1].split('/')[1]) if '/' in parts[1] else float(parts[1])
                seconds = float(parts[2].split('/')[0]) / float(parts[2].split('/')[1]) if '/' in parts[2] else float(parts[2])
                
                decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
                
                # Apply hemisphere reference
                if reference in ['S', 'W']:
                    decimal = -decimal
                
                return decimal
                
        except Exception as e:
            self.logger.warning(f"GPS coordinate parsing error: {str(e)}")
            return None

    def _extract_thumbnail_info(self, image_path: str) -> Dict[str, Any]:
        """Extract embedded thumbnail information"""
        try:
            thumbnail_info = {}
            
            with Image.open(image_path) as image:
                exifdata = image.getexif()
                
                # Check for thumbnail
                if hasattr(exifdata, 'get_ifd') and 1 in exifdata:
                    thumbnail_ifd = exifdata.get_ifd(1)
                    if thumbnail_ifd:
                        thumbnail_info['has_thumbnail'] = True
                        thumbnail_info['thumbnail_compression'] = thumbnail_ifd.get(259, 'Unknown')
                        thumbnail_info['thumbnail_width'] = thumbnail_ifd.get(256, 'Unknown')
                        thumbnail_info['thumbnail_height'] = thumbnail_ifd.get(257, 'Unknown')
                    else:
                        thumbnail_info['has_thumbnail'] = False
                else:
                    thumbnail_info['has_thumbnail'] = False
            
            return thumbnail_info
            
        except Exception as e:
            self.logger.warning(f"Thumbnail extraction error: {str(e)}")
            return {'has_thumbnail': False}

    def _generate_forensic_notes(self, metadata: Dict[str, Any]) -> List[str]:
        """Generate forensic analysis notes based on metadata"""
        notes = []
        
        try:
            # Check for software modifications
            software_info = metadata.get('software_info', {})
            if software_info.get('Software'):
                software = software_info['Software']
                if any(editor in software.lower() for editor in ['photoshop', 'gimp', 'paint', 'editor']):
                    notes.append(f"⚠️ Image processed with editing software: {software}")
            
            # Check for timestamp inconsistencies
            timestamps = metadata.get('timestamps', {})
            if len(timestamps) > 1:
                unique_times = set(timestamps.values())
                if len(unique_times) != len(timestamps):
                    notes.append("⚠️ Inconsistent timestamps detected - possible metadata manipulation")
            
            # Check for missing critical metadata
            camera_info = metadata.get('camera_info', {})
            if not camera_info.get('Make') and not camera_info.get('Model'):
                notes.append("ℹ️ Camera make/model information missing")
            
            # Check GPS data
            gps_data = metadata.get('gps_data', {})
            if gps_data and 'decimal_latitude' in gps_data:
                notes.append(f"📍 GPS location data present: {gps_data.get('coordinates_string', 'Available')}")
            
            # Check file size vs image dimensions
            file_info = metadata.get('file_info', {})
            if file_info.get('file_size') and file_info.get('image_width'):
                width = file_info['image_width']
                height = file_info['image_height']
                size_mb = file_info['file_size_mb']
                expected_size = (width * height * 3) / (1024 * 1024)  # Rough estimate
                
                if size_mb < expected_size * 0.1:  # Very compressed
                    notes.append("⚠️ Image appears heavily compressed - quality may be compromised")
            
            # Check for unusual metadata
            exif_data = metadata.get('exif_data', {})
            if 'UserComment' in exif_data:
                notes.append(f"💬 User comment present: {exif_data['UserComment']}")
            
            if not notes:
                notes.append("✅ No obvious metadata anomalies detected")
            
            return notes
            
        except Exception as e:
            self.logger.error(f"Error generating forensic notes: {str(e)}")
            return ["⚠️ Error analyzing metadata for forensic indicators"]

    def export_metadata_report(self, metadata: Dict[str, Any], output_path: str) -> bool:
        """Export comprehensive metadata report to JSON file"""
        try:
            # Add export timestamp
            export_data = {
                'export_timestamp': datetime.now().isoformat(),
                'extractor_version': '1.0.0',
                'metadata': metadata
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting metadata report: {str(e)}")
            return False

    def get_metadata_summary(self, metadata: Dict[str, Any]) -> Dict[str, str]:
        """Get a concise summary of key metadata"""
        summary = {}
        
        try:
            # Camera information
            camera_info = metadata.get('camera_info', {})
            if camera_info.get('Make') and camera_info.get('Model'):
                summary['camera'] = f"{camera_info['Make']} {camera_info['Model']}"
            elif camera_info.get('Model'):
                summary['camera'] = camera_info['Model']
            else:
                summary['camera'] = 'Unknown'
            
            # Date taken
            timestamps = metadata.get('timestamps', {})
            date_taken = timestamps.get('DateTimeOriginal') or timestamps.get('DateTime') or 'Unknown'
            summary['date_taken'] = date_taken
            
            # GPS location
            gps_data = metadata.get('gps_data', {})
            if gps_data.get('coordinates_string'):
                summary['location'] = gps_data['coordinates_string']
            else:
                summary['location'] = 'No GPS data'
            
            # Software
            software_info = metadata.get('software_info', {})
            software = software_info.get('Software') or software_info.get('ProcessingSoftware') or 'Unknown'
            summary['software'] = software
            
            # Image dimensions
            file_info = metadata.get('file_info', {})
            if file_info.get('image_width') and file_info.get('image_height'):
                summary['dimensions'] = f"{file_info['image_width']} × {file_info['image_height']}"
            else:
                summary['dimensions'] = 'Unknown'
            
            # File size
            if file_info.get('file_size_mb'):
                summary['file_size'] = f"{file_info['file_size_mb']} MB"
            else:
                summary['file_size'] = 'Unknown'
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error creating metadata summary: {str(e)}")
            return {'error': 'Could not generate summary'}