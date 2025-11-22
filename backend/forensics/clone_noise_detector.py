"""
Clone and Noise Detection Algorithms
===================================

Advanced image tampering detection through:
- Copy-Move Detection (Clone Detection)
- Block Matching Algorithms
- Noise Inconsistency Analysis
- Statistical Analysis of Image Regions
"""

import cv2
import numpy as np
from scipy import ndimage, stats
from sklearn.cluster import DBSCAN
from skimage import feature, measure, filters
from skimage.metrics import structural_similarity as ssim
import matplotlib.pyplot as plt
import io
import base64
import logging
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
import json


@dataclass
class SuspiciousRegion:
    """Data class for suspicious regions"""
    x: int
    y: int
    width: int
    height: int
    confidence: float
    detection_type: str
    similarity_score: float
    noise_variance: float


class CloneNoiseDetector:
    """
    Advanced clone and noise detection for forensic image analysis.
    Implements multiple algorithms for detecting image tampering.
    """
    
    def __init__(self):
        """Initialize the clone and noise detector"""
        self.logger = logging.getLogger(__name__)
        
        # Algorithm parameters
        self.block_size = 16  # Size of blocks for analysis
        self.overlap_threshold = 0.5  # Min overlap for block matching
        self.similarity_threshold = 0.85  # Min similarity for clone detection
        self.noise_window_size = 32  # Window size for noise analysis
        self.min_region_size = 100  # Minimum size for suspicious regions
        
        # SIFT parameters for feature matching
        self.sift_detector = cv2.SIFT_create(nfeatures=1000)
        self.matcher = cv2.BFMatcher()
        
        # ORB parameters as backup
        self.orb_detector = cv2.ORB_create(nfeatures=1000)

    def detect_tampering(self, image_path: str, methods: List[str] = None) -> Dict[str, Any]:
        """
        Comprehensive tampering detection using multiple methods.
        
        Args:
            image_path: Path to the image file
            methods: List of detection methods to use
            
        Returns:
            Dictionary containing detection results
        """
        if methods is None:
            methods = ['copy_move', 'block_matching', 'noise_analysis', 'statistical_analysis']
        
        try:
            # Load image
            image = cv2.imread(image_path)
            if image is None:
                raise ValueError("Could not load image file")
            
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            results = {
                'analysis_timestamp': self._get_timestamp(),
                'image_dimensions': image.shape[:2],
                'methods_used': methods,
                'suspicious_regions': [],
                'detection_results': {},
                'overall_assessment': {},
                'visualizations': {}
            }
            
            # Apply each detection method
            if 'copy_move' in methods:
                copy_move_results = self._detect_copy_move(image, gray)
                results['detection_results']['copy_move'] = copy_move_results
                results['suspicious_regions'].extend(copy_move_results.get('regions', []))
            
            if 'block_matching' in methods:
                block_results = self._detect_block_matching(gray)
                results['detection_results']['block_matching'] = block_results
                results['suspicious_regions'].extend(block_results.get('regions', []))
            
            if 'noise_analysis' in methods:
                noise_results = self._analyze_noise_consistency(gray)
                results['detection_results']['noise_analysis'] = noise_results
                results['suspicious_regions'].extend(noise_results.get('regions', []))
            
            if 'statistical_analysis' in methods:
                stats_results = self._statistical_analysis(gray)
                results['detection_results']['statistical_analysis'] = stats_results
                results['suspicious_regions'].extend(stats_results.get('regions', []))
            
            # Generate overall assessment
            results['overall_assessment'] = self._generate_overall_assessment(results['detection_results'])
            
            # Create visualizations
            results['visualizations'] = self._create_visualizations(image, gray, results['suspicious_regions'])
            
            return results
            
        except Exception as e:
            self.logger.error(f"Tampering detection failed: {str(e)}")
            return {'error': str(e), 'analysis_failed': True}

    def _detect_copy_move(self, image: np.ndarray, gray: np.ndarray) -> Dict[str, Any]:
        """
        Detect copy-move forgeries using SIFT/ORB feature matching.
        
        Args:
            image: Color image
            gray: Grayscale image
            
        Returns:
            Detection results with suspicious regions
        """
        try:
            results = {
                'method': 'copy_move_detection',
                'regions': [],
                'matches_found': 0,
                'confidence_scores': [],
                'feature_points': 0
            }
            
            # Extract features using SIFT
            try:
                keypoints, descriptors = self.sift_detector.detectAndCompute(gray, None)
                feature_detector = 'SIFT'
            except Exception:
                # Fallback to ORB if SIFT fails
                keypoints, descriptors = self.orb_detector.detectAndCompute(gray, None)
                feature_detector = 'ORB'
            
            if descriptors is None or len(keypoints) < 10:
                return results
            
            results['feature_points'] = len(keypoints)
            results['feature_detector_used'] = feature_detector
            
            # Match features with themselves to find duplicates
            if feature_detector == 'SIFT':
                matches = self.matcher.knnMatch(descriptors, descriptors, k=3)
            else:
                # For ORB, use Hamming distance
                bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=False)
                matches = bf.knnMatch(descriptors, descriptors, k=3)
            
            # Filter good matches (excluding self-matches)
            good_matches = []
            for match_group in matches:
                if len(match_group) >= 2:
                    m1, m2 = match_group[0], match_group[1]
                    # Skip self-matches and apply ratio test
                    if m1.queryIdx != m1.trainIdx and m1.distance < 0.7 * m2.distance:
                        good_matches.append(m1)
            
            results['matches_found'] = len(good_matches)
            
            if len(good_matches) < 4:
                return results
            
            # Group matches by spatial proximity
            match_groups = self._group_matches_spatially(keypoints, good_matches)
            
            # Analyze each group for copy-move patterns
            for group in match_groups:
                if len(group) >= 4:  # Need at least 4 matches for reliable detection
                    region_data = self._analyze_match_group(keypoints, group, gray.shape)
                    if region_data['confidence'] > 0.6:
                        suspicious_region = SuspiciousRegion(
                            x=region_data['bbox'][0],
                            y=region_data['bbox'][1],
                            width=region_data['bbox'][2],
                            height=region_data['bbox'][3],
                            confidence=region_data['confidence'],
                            detection_type='copy_move',
                            similarity_score=region_data['similarity'],
                            noise_variance=region_data.get('noise_variance', 0.0)
                        )
                        results['regions'].append(suspicious_region.__dict__)
                        results['confidence_scores'].append(region_data['confidence'])
            
            return results
            
        except Exception as e:
            self.logger.warning(f"Copy-move detection failed: {str(e)}")
            return {'method': 'copy_move_detection', 'error': str(e)}

    def _group_matches_spatially(self, keypoints: List, matches: List, distance_threshold: float = 50.0) -> List[List]:
        """Group feature matches by spatial proximity"""
        if not matches:
            return []
        
        # Extract coordinates of matched keypoints
        coords = []
        for match in matches:
            pt1 = keypoints[match.queryIdx].pt
            pt2 = keypoints[match.trainIdx].pt
            coords.append([pt1[0], pt1[1], pt2[0], pt2[1]])
        
        coords = np.array(coords)
        
        # Use DBSCAN clustering on source coordinates
        source_coords = coords[:, :2]
        clustering = DBSCAN(eps=distance_threshold, min_samples=3).fit(source_coords)
        
        # Group matches by clusters
        groups = []
        for cluster_id in set(clustering.labels_):
            if cluster_id != -1:  # Ignore noise points
                cluster_matches = [matches[i] for i in range(len(matches)) if clustering.labels_[i] == cluster_id]
                if len(cluster_matches) >= 3:
                    groups.append(cluster_matches)
        
        return groups

    def _analyze_match_group(self, keypoints: List, matches: List, image_shape: Tuple) -> Dict[str, Any]:
        """Analyze a group of matches for copy-move patterns"""
        try:
            # Extract source and target coordinates
            src_pts = []
            dst_pts = []
            
            for match in matches:
                src_pts.append(keypoints[match.queryIdx].pt)
                dst_pts.append(keypoints[match.trainIdx].pt)
            
            src_pts = np.array(src_pts)
            dst_pts = np.array(dst_pts)
            
            # Calculate bounding boxes
            src_bbox = [
                int(np.min(src_pts[:, 0])), int(np.min(src_pts[:, 1])),
                int(np.max(src_pts[:, 0]) - np.min(src_pts[:, 0])),
                int(np.max(src_pts[:, 1]) - np.min(src_pts[:, 1]))
            ]
            
            dst_bbox = [
                int(np.min(dst_pts[:, 0])), int(np.min(dst_pts[:, 1])),
                int(np.max(dst_pts[:, 0]) - np.min(dst_pts[:, 0])),
                int(np.max(dst_pts[:, 1]) - np.min(dst_pts[:, 1]))
            ]
            
            # Calculate transformation consistency
            if len(matches) >= 4:
                try:
                    # Find homography to measure transformation consistency
                    H, mask = cv2.findHomography(src_pts, dst_pts, cv2.RANSAC, 5.0)
                    consistency = np.sum(mask) / len(mask) if mask is not None else 0.0
                except:
                    consistency = 0.0
            else:
                consistency = 0.0
            
            # Calculate distance between regions (avoid self-matches)
            center_src = np.mean(src_pts, axis=0)
            center_dst = np.mean(dst_pts, axis=0)
            distance = np.linalg.norm(center_src - center_dst)
            
            # Calculate confidence based on multiple factors
            distance_factor = min(1.0, distance / 100.0)  # Favor distant matches
            consistency_factor = consistency
            size_factor = min(1.0, (src_bbox[2] * src_bbox[3]) / 1000.0)  # Favor larger regions
            
            confidence = (distance_factor * 0.4 + consistency_factor * 0.4 + size_factor * 0.2)
            
            return {
                'bbox': src_bbox,  # Return source region as primary detection
                'dst_bbox': dst_bbox,
                'confidence': confidence,
                'similarity': consistency,
                'distance': distance,
                'match_count': len(matches),
                'noise_variance': 0.0  # Will be calculated if needed
            }
            
        except Exception as e:
            self.logger.warning(f"Match group analysis failed: {str(e)}")
            return {'bbox': [0, 0, 0, 0], 'confidence': 0.0, 'similarity': 0.0}

    def _detect_block_matching(self, gray: np.ndarray) -> Dict[str, Any]:
        """
        Detect tampering using block-based matching algorithms.
        
        Args:
            gray: Grayscale image
            
        Returns:
            Detection results
        """
        try:
            results = {
                'method': 'block_matching',
                'regions': [],
                'blocks_analyzed': 0,
                'similar_blocks_found': 0,
                'similarity_threshold': self.similarity_threshold
            }
            
            height, width = gray.shape
            block_size = self.block_size
            
            # Extract overlapping blocks
            blocks = []
            positions = []
            
            for y in range(0, height - block_size, block_size // 2):
                for x in range(0, width - block_size, block_size // 2):
                    block = gray[y:y+block_size, x:x+block_size]
                    if block.shape == (block_size, block_size):
                        blocks.append(block.flatten())
                        positions.append((x, y))
            
            blocks = np.array(blocks)
            results['blocks_analyzed'] = len(blocks)
            
            if len(blocks) < 2:
                return results
            
            # Calculate pairwise similarities using normalized cross-correlation
            similar_pairs = []
            
            for i in range(len(blocks)):
                for j in range(i + 1, len(blocks)):
                    # Skip nearby blocks to avoid trivial matches
                    pos1, pos2 = positions[i], positions[j]
                    distance = np.sqrt((pos1[0] - pos2[0])**2 + (pos1[1] - pos2[1])**2)
                    
                    if distance < block_size * 2:  # Too close
                        continue
                    
                    # Calculate normalized cross-correlation
                    correlation = cv2.matchTemplate(
                        blocks[i].reshape(block_size, block_size).astype(np.float32),
                        blocks[j].reshape(block_size, block_size).astype(np.float32),
                        cv2.TM_CCOEFF_NORMED
                    )[0, 0]
                    
                    if correlation > self.similarity_threshold:
                        similar_pairs.append({
                            'block1_pos': positions[i],
                            'block2_pos': positions[j],
                            'similarity': correlation,
                            'distance': distance
                        })
            
            results['similar_blocks_found'] = len(similar_pairs)
            
            # Group similar blocks into regions
            if similar_pairs:
                regions = self._group_similar_blocks(similar_pairs, block_size)
                for region in regions:
                    if region['size'] >= self.min_region_size:
                        suspicious_region = SuspiciousRegion(
                            x=region['x'],
                            y=region['y'],
                            width=region['width'],
                            height=region['height'],
                            confidence=region['confidence'],
                            detection_type='block_matching',
                            similarity_score=region['avg_similarity'],
                            noise_variance=0.0
                        )
                        results['regions'].append(suspicious_region.__dict__)
            
            return results
            
        except Exception as e:
            self.logger.warning(f"Block matching detection failed: {str(e)}")
            return {'method': 'block_matching', 'error': str(e)}

    def _group_similar_blocks(self, similar_pairs: List[Dict], block_size: int) -> List[Dict]:
        """Group similar block pairs into regions"""
        regions = []
        
        try:
            # Extract all unique positions involved in similarities
            all_positions = set()
            for pair in similar_pairs:
                all_positions.add(pair['block1_pos'])
                all_positions.add(pair['block2_pos'])
            
            all_positions = list(all_positions)
            
            # Use DBSCAN to cluster positions
            if len(all_positions) > 1:
                clustering = DBSCAN(eps=block_size * 1.5, min_samples=2).fit(all_positions)
                
                for cluster_id in set(clustering.labels_):
                    if cluster_id != -1:
                        cluster_positions = [all_positions[i] for i in range(len(all_positions)) 
                                           if clustering.labels_[i] == cluster_id]
                        
                        if len(cluster_positions) >= 2:
                            # Calculate bounding box for cluster
                            x_coords = [pos[0] for pos in cluster_positions]
                            y_coords = [pos[1] for pos in cluster_positions]
                            
                            x_min, x_max = min(x_coords), max(x_coords) + block_size
                            y_min, y_max = min(y_coords), max(y_coords) + block_size
                            
                            # Calculate average similarity for this region
                            region_similarities = []
                            for pair in similar_pairs:
                                if (pair['block1_pos'] in cluster_positions or 
                                    pair['block2_pos'] in cluster_positions):
                                    region_similarities.append(pair['similarity'])
                            
                            avg_similarity = np.mean(region_similarities) if region_similarities else 0.0
                            
                            regions.append({
                                'x': x_min,
                                'y': y_min,
                                'width': x_max - x_min,
                                'height': y_max - y_min,
                                'size': (x_max - x_min) * (y_max - y_min),
                                'confidence': min(1.0, avg_similarity * len(cluster_positions) / 10.0),
                                'avg_similarity': avg_similarity,
                                'block_count': len(cluster_positions)
                            })
            
            return regions
            
        except Exception as e:
            self.logger.warning(f"Block grouping failed: {str(e)}")
            return []

    def _analyze_noise_consistency(self, gray: np.ndarray) -> Dict[str, Any]:
        """
        Analyze noise consistency across the image to detect tampering.
        
        Args:
            gray: Grayscale image
            
        Returns:
            Noise analysis results
        """
        try:
            results = {
                'method': 'noise_analysis',
                'regions': [],
                'noise_statistics': {},
                'inconsistent_regions': 0
            }
            
            height, width = gray.shape
            window_size = self.noise_window_size
            
            # Calculate noise variance for overlapping windows
            noise_map = np.zeros((height, width))
            variance_values = []
            
            for y in range(0, height - window_size, window_size // 2):
                for x in range(0, width - window_size, window_size // 2):
                    window = gray[y:y+window_size, x:x+window_size].astype(np.float32)
                    
                    # Apply Gaussian blur to separate signal from noise
                    blurred = cv2.GaussianBlur(window, (5, 5), 1.0)
                    noise = window - blurred
                    
                    # Calculate noise variance
                    noise_variance = np.var(noise)
                    variance_values.append(noise_variance)
                    
                    # Fill noise map
                    noise_map[y:y+window_size, x:x+window_size] = noise_variance
            
            # Calculate global noise statistics
            global_mean = np.mean(variance_values)
            global_std = np.std(variance_values)
            
            results['noise_statistics'] = {
                'global_mean_variance': float(global_mean),
                'global_std_variance': float(global_std),
                'min_variance': float(np.min(variance_values)),
                'max_variance': float(np.max(variance_values)),
                'variance_range': float(np.max(variance_values) - np.min(variance_values))
            }
            
            # Detect regions with inconsistent noise
            threshold = global_mean + 2 * global_std
            anomaly_mask = noise_map > threshold
            
            # Find connected components of anomalous regions
            labeled_mask = measure.label(anomaly_mask)
            regions_props = measure.regionprops(labeled_mask)
            
            for prop in regions_props:
                if prop.area >= self.min_region_size:
                    bbox = prop.bbox  # (min_row, min_col, max_row, max_col)
                    
                    # Calculate confidence based on deviation from normal noise
                    region_noise = noise_map[bbox[0]:bbox[2], bbox[1]:bbox[3]]
                    avg_region_noise = np.mean(region_noise)
                    deviation = (avg_region_noise - global_mean) / (global_std + 1e-8)
                    confidence = min(1.0, max(0.0, (deviation - 2.0) / 3.0))  # Normalize to [0,1]
                    
                    if confidence > 0.3:  # Only report significant anomalies
                        suspicious_region = SuspiciousRegion(
                            x=bbox[1],
                            y=bbox[0],
                            width=bbox[3] - bbox[1],
                            height=bbox[2] - bbox[0],
                            confidence=confidence,
                            detection_type='noise_inconsistency',
                            similarity_score=0.0,
                            noise_variance=float(avg_region_noise)
                        )
                        results['regions'].append(suspicious_region.__dict__)
                        results['inconsistent_regions'] += 1
            
            return results
            
        except Exception as e:
            self.logger.warning(f"Noise analysis failed: {str(e)}")
            return {'method': 'noise_analysis', 'error': str(e)}

    def _statistical_analysis(self, gray: np.ndarray) -> Dict[str, Any]:
        """
        Perform statistical analysis to detect tampering patterns.
        
        Args:
            gray: Grayscale image
            
        Returns:
            Statistical analysis results
        """
        try:
            results = {
                'method': 'statistical_analysis',
                'regions': [],
                'statistics': {},
                'anomalies_detected': 0
            }
            
            height, width = gray.shape
            
            # Divide image into grid for statistical analysis
            grid_size = 64
            stats_grid = []
            
            for y in range(0, height - grid_size, grid_size):
                row = []
                for x in range(0, width - grid_size, grid_size):
                    region = gray[y:y+grid_size, x:x+grid_size]
                    
                    # Calculate various statistical measures
                    region_stats = {
                        'mean': np.mean(region),
                        'std': np.std(region),
                        'skewness': stats.skew(region.flatten()),
                        'kurtosis': stats.kurtosis(region.flatten()),
                        'entropy': -np.sum(np.histogram(region, bins=256)[0] / (grid_size**2) * 
                                         np.log2(np.histogram(region, bins=256)[0] / (grid_size**2) + 1e-10))
                    }
                    row.append(region_stats)
                stats_grid.append(row)
            
            # Calculate global statistics
            all_means = [stat['mean'] for row in stats_grid for stat in row]
            all_stds = [stat['std'] for row in stats_grid for stat in row]
            all_skewness = [stat['skewness'] for row in stats_grid for stat in row]
            all_kurtosis = [stat['kurtosis'] for row in stats_grid for stat in row]
            all_entropy = [stat['entropy'] for row in stats_grid for stat in row]
            
            global_stats = {
                'mean_avg': np.mean(all_means),
                'mean_std': np.std(all_means),
                'std_avg': np.mean(all_stds),
                'std_std': np.std(all_stds),
                'skewness_avg': np.mean(all_skewness),
                'skewness_std': np.std(all_skewness),
                'kurtosis_avg': np.mean(all_kurtosis),
                'kurtosis_std': np.std(all_kurtosis),
                'entropy_avg': np.mean(all_entropy),
                'entropy_std': np.std(all_entropy)
            }
            
            results['statistics'] = global_stats
            
            # Detect statistical anomalies
            for i, row in enumerate(stats_grid):
                for j, region_stats in enumerate(row):
                    anomaly_score = 0.0
                    
                    # Check each statistical measure for anomalies
                    measures = [
                        ('mean', region_stats['mean'], global_stats['mean_avg'], global_stats['mean_std']),
                        ('std', region_stats['std'], global_stats['std_avg'], global_stats['std_std']),
                        ('skewness', region_stats['skewness'], global_stats['skewness_avg'], global_stats['skewness_std']),
                        ('kurtosis', region_stats['kurtosis'], global_stats['kurtosis_avg'], global_stats['kurtosis_std']),
                        ('entropy', region_stats['entropy'], global_stats['entropy_avg'], global_stats['entropy_std'])
                    ]
                    
                    for measure_name, value, global_mean, global_std in measures:
                        if global_std > 0:
                            z_score = abs((value - global_mean) / global_std)
                            if z_score > 2.5:  # Significant deviation
                                anomaly_score += z_score / 5.0  # Normalize contribution
                    
                    # If significant anomaly detected
                    if anomaly_score > 0.5:
                        confidence = min(1.0, anomaly_score / 2.0)
                        
                        suspicious_region = SuspiciousRegion(
                            x=j * grid_size,
                            y=i * grid_size,
                            width=grid_size,
                            height=grid_size,
                            confidence=confidence,
                            detection_type='statistical_anomaly',
                            similarity_score=0.0,
                            noise_variance=region_stats['std']**2
                        )
                        results['regions'].append(suspicious_region.__dict__)
                        results['anomalies_detected'] += 1
            
            return results
            
        except Exception as e:
            self.logger.warning(f"Statistical analysis failed: {str(e)}")
            return {'method': 'statistical_analysis', 'error': str(e)}

    def _generate_overall_assessment(self, detection_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate overall tampering assessment from all detection methods"""
        try:
            assessment = {
                'tampering_probability': 0.0,
                'confidence_level': 'low',
                'primary_concerns': [],
                'methods_agreement': 0.0,
                'total_suspicious_regions': 0,
                'risk_level': 'low'
            }
            
            # Count total suspicious regions and calculate scores
            method_scores = []
            method_confidences = []
            total_regions = 0
            
            for method_name, results in detection_results.items():
                if 'error' not in results and 'regions' in results:
                    regions = results['regions']
                    total_regions += len(regions)
                    
                    if regions:
                        # Calculate method score based on regions found
                        avg_confidence = np.mean([r['confidence'] for r in regions])
                        method_scores.append(min(1.0, len(regions) / 5.0))  # Normalize by region count
                        method_confidences.append(avg_confidence)
                        
                        # Add to primary concerns
                        if avg_confidence > 0.6:
                            if method_name == 'copy_move':
                                assessment['primary_concerns'].append('Copy-move forgery patterns detected')
                            elif method_name == 'block_matching':
                                assessment['primary_concerns'].append('Suspicious block similarities found')
                            elif method_name == 'noise_analysis':
                                assessment['primary_concerns'].append('Noise inconsistencies detected')
                            elif method_name == 'statistical_analysis':
                                assessment['primary_concerns'].append('Statistical anomalies identified')
                    else:
                        method_scores.append(0.0)
                        method_confidences.append(0.0)
            
            assessment['total_suspicious_regions'] = total_regions
            
            # Calculate overall tampering probability
            if method_scores:
                # Weight by method agreement
                agreement = 1.0 - np.std(method_scores) if len(method_scores) > 1 else 1.0
                avg_score = np.mean(method_scores)
                avg_confidence = np.mean(method_confidences)
                
                assessment['methods_agreement'] = float(agreement)
                assessment['tampering_probability'] = float(min(1.0, avg_score * agreement * avg_confidence))
            
            # Determine confidence and risk levels
            prob = assessment['tampering_probability']
            if prob > 0.7 and assessment['methods_agreement'] > 0.6:
                assessment['confidence_level'] = 'high'
                assessment['risk_level'] = 'high'
            elif prob > 0.4 and assessment['methods_agreement'] > 0.4:
                assessment['confidence_level'] = 'medium'
                assessment['risk_level'] = 'medium'
            else:
                assessment['confidence_level'] = 'low'
                assessment['risk_level'] = 'low'
            
            # Add default concern if none found
            if not assessment['primary_concerns']:
                if total_regions > 0:
                    assessment['primary_concerns'].append('Some suspicious patterns detected')
                else:
                    assessment['primary_concerns'].append('No significant tampering indicators found')
            
            return assessment
            
        except Exception as e:
            self.logger.warning(f"Overall assessment generation failed: {str(e)}")
            return {
                'tampering_probability': 0.0,
                'confidence_level': 'low',
                'primary_concerns': ['Assessment error occurred'],
                'methods_agreement': 0.0,
                'total_suspicious_regions': 0,
                'risk_level': 'unknown'
            }

    def _create_visualizations(self, image: np.ndarray, gray: np.ndarray, 
                             suspicious_regions: List[Dict]) -> Dict[str, str]:
        """Create visualization images for the analysis results"""
        try:
            visualizations = {}
            
            # Create annotated image with suspicious regions
            annotated_image = image.copy()
            
            # Color code by detection type
            colors = {
                'copy_move': (0, 255, 0),        # Green
                'block_matching': (255, 0, 0),   # Blue
                'noise_inconsistency': (0, 0, 255),  # Red
                'statistical_anomaly': (255, 255, 0)  # Cyan
            }
            
            for region in suspicious_regions:
                color = colors.get(region['detection_type'], (128, 128, 128))
                confidence = region['confidence']
                
                # Draw rectangle with thickness based on confidence
                thickness = max(1, int(confidence * 5))
                cv2.rectangle(annotated_image, 
                            (region['x'], region['y']), 
                            (region['x'] + region['width'], region['y'] + region['height']),
                            color, thickness)
                
                # Add confidence text
                text = f"{region['detection_type'][:8]}: {confidence:.2f}"
                cv2.putText(annotated_image, text, 
                          (region['x'], region['y'] - 10), 
                          cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 1)
            
            # Encode annotated image
            visualizations['annotated_image'] = self._encode_image_base64(annotated_image)
            
            # Create heatmap of suspicious areas
            heatmap = np.zeros_like(gray, dtype=np.float32)
            for region in suspicious_regions:
                y1, y2 = region['y'], region['y'] + region['height']
                x1, x2 = region['x'], region['x'] + region['width']
                heatmap[y1:y2, x1:x2] += region['confidence']
            
            # Normalize and colorize heatmap
            if np.max(heatmap) > 0:
                heatmap = (heatmap / np.max(heatmap) * 255).astype(np.uint8)
                heatmap_colored = cv2.applyColorMap(heatmap, cv2.COLORMAP_JET)
                visualizations['heatmap'] = self._encode_image_base64(heatmap_colored)
            else:
                visualizations['heatmap'] = ""
            
            return visualizations
            
        except Exception as e:
            self.logger.warning(f"Visualization creation failed: {str(e)}")
            return {}

    def _encode_image_base64(self, image: np.ndarray) -> str:
        """Encode image as base64 string"""
        try:
            # Convert BGR to RGB for proper encoding
            if len(image.shape) == 3:
                image_rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
            else:
                image_rgb = image
            
            # Encode as PNG
            _, buffer = cv2.imencode('.png', image_rgb)
            base64_string = base64.b64encode(buffer).decode('utf-8')
            return base64_string
            
        except Exception as e:
            self.logger.warning(f"Base64 encoding failed: {str(e)}")
            return ""

    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()

    def get_algorithm_info(self) -> Dict[str, Any]:
        """Get information about available detection algorithms"""
        return {
            'algorithms': {
                'copy_move': {
                    'name': 'Copy-Move Detection',
                    'description': 'Detects duplicated regions using SIFT/ORB feature matching',
                    'suitable_for': 'Detecting copied and pasted image regions',
                    'parameters': {
                        'feature_detector': 'SIFT (primary), ORB (fallback)',
                        'min_matches': 4,
                        'spatial_grouping': 'DBSCAN clustering'
                    }
                },
                'block_matching': {
                    'name': 'Block Matching Analysis',
                    'description': 'Analyzes image blocks for suspicious similarities',
                    'suitable_for': 'Detecting regular pattern manipulations',
                    'parameters': {
                        'block_size': self.block_size,
                        'similarity_threshold': self.similarity_threshold,
                        'overlap_analysis': True
                    }
                },
                'noise_analysis': {
                    'name': 'Noise Consistency Analysis',
                    'description': 'Detects inconsistent noise patterns across image regions',
                    'suitable_for': 'Identifying regions with different acquisition conditions',
                    'parameters': {
                        'window_size': self.noise_window_size,
                        'noise_extraction': 'Gaussian blur subtraction',
                        'anomaly_detection': 'Statistical threshold (mean + 2*std)'
                    }
                },
                'statistical_analysis': {
                    'name': 'Statistical Anomaly Detection',
                    'description': 'Analyzes statistical properties for tampering indicators',
                    'suitable_for': 'General tampering detection through statistical deviations',
                    'parameters': {
                        'grid_size': 64,
                        'measures': ['mean', 'std', 'skewness', 'kurtosis', 'entropy'],
                        'anomaly_threshold': '2.5 sigma'
                    }
                }
            },
            'detection_capabilities': [
                'Copy-move forgeries',
                'Cloned regions',
                'Noise inconsistencies', 
                'Statistical anomalies',
                'Block-based tampering',
                'Pattern irregularities'
            ],
            'output_features': [
                'Suspicious region coordinates',
                'Confidence scores',
                'Detection method attribution',
                'Visual annotations',
                'Heatmap generation',
                'Overall tampering assessment'
            ]
        }