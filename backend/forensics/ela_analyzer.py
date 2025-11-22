"""
Error Level Analysis (ELA) Implementation
========================================

Dedicated ELA module for detecting image tampering through JPEG compression
artifact analysis. ELA reveals areas of different compression levels which
can indicate manipulation or editing.
"""

import cv2
import numpy as np
from PIL import Image
import io
import base64
import os
import tempfile
from typing import Dict, Tuple, Optional, Any, List
import logging


class ErrorLevelAnalyzer:
    """
    Advanced Error Level Analysis implementation for forensic image analysis.
    Detects tampering by analyzing JPEG compression error levels.
    """
    
    def __init__(self):
        """Initialize the ELA analyzer"""
        self.logger = logging.getLogger(__name__)
        
        # ELA configuration parameters
        self.quality_levels = [95, 90, 85, 80, 75, 70]  # JPEG quality levels to test
        self.default_quality = 95  # Default quality for recompression
        self.enhancement_factor = 15  # Factor to enhance ELA differences
        self.threshold_low = 10  # Low threshold for significant differences
        self.threshold_high = 30  # High threshold for major differences

    def perform_ela_analysis(self, image_path: str, quality: int = None) -> Dict[str, Any]:
        """
        Perform comprehensive Error Level Analysis on an image.
        
        Args:
            image_path: Path to the image file
            quality: JPEG quality for recompression (default: 95)
            
        Returns:
            Dictionary containing ELA results and analysis
        """
        try:
            if quality is None:
                quality = self.default_quality
                
            # Load the original image
            original_image = cv2.imread(image_path)
            if original_image is None:
                raise ValueError("Could not load image file")
            
            # Perform ELA analysis
            ela_image, ela_stats = self._calculate_ela(image_path, quality)
            
            # Analyze ELA results
            analysis_results = self._analyze_ela_results(ela_image, ela_stats)
            
            # Generate ELA visualization
            ela_visualization = self._create_ela_visualization(ela_image)
            
            # Encode visualization as base64
            ela_base64 = self._encode_image_base64(ela_visualization)
            
            # Generate difference heatmap
            heatmap_base64 = self._create_difference_heatmap(ela_image)
            
            # Detect suspicious regions
            suspicious_regions = self._detect_suspicious_regions(ela_image)
            
            # Calculate tampering probability
            tampering_probability = self._calculate_tampering_probability(ela_stats, suspicious_regions)
            
            # Generate comprehensive report
            ela_report = {
                'analysis_timestamp': self._get_timestamp(),
                'parameters': {
                    'quality_used': quality,
                    'enhancement_factor': self.enhancement_factor,
                    'image_dimensions': original_image.shape[:2]
                },
                'ela_statistics': ela_stats,
                'analysis_results': analysis_results,
                'suspicious_regions': suspicious_regions,
                'tampering_assessment': {
                    'probability': tampering_probability,
                    'confidence': self._get_confidence_level(tampering_probability),
                    'risk_level': self._get_risk_level(tampering_probability)
                },
                'visualizations': {
                    'ela_image_base64': ela_base64,
                    'heatmap_base64': heatmap_base64
                },
                'forensic_notes': self._generate_forensic_notes(analysis_results, tampering_probability)
            }
            
            return ela_report
            
        except Exception as e:
            self.logger.error(f"ELA analysis failed: {str(e)}")
            return {'error': str(e), 'analysis_failed': True}

    def _calculate_ela(self, image_path: str, quality: int) -> Tuple[np.ndarray, Dict[str, float]]:
        """
        Calculate Error Level Analysis by recompressing the image.
        
        Args:
            image_path: Path to original image
            quality: JPEG quality for recompression
            
        Returns:
            Tuple of (ELA image array, statistics dict)
        """
        try:
            # Load original image
            original = Image.open(image_path)
            
            # Convert to RGB if needed
            if original.mode != 'RGB':
                original = original.convert('RGB')
            
            # Save at specified quality to get compressed version
            temp_path = tempfile.mktemp(suffix='.jpg')
            original.save(temp_path, 'JPEG', quality=quality)
            
            # Load both versions as numpy arrays
            original_array = np.array(original)
            compressed_array = np.array(Image.open(temp_path))
            
            # Calculate absolute difference
            ela_array = np.abs(original_array.astype(np.float32) - compressed_array.astype(np.float32))
            
            # Enhance the differences
            ela_enhanced = np.clip(ela_array * self.enhancement_factor, 0, 255).astype(np.uint8)
            
            # Calculate statistics
            ela_stats = {
                'mean_error': float(np.mean(ela_array)),
                'std_error': float(np.std(ela_array)),
                'max_error': float(np.max(ela_array)),
                'min_error': float(np.min(ela_array)),
                'median_error': float(np.median(ela_array)),
                'error_range': float(np.max(ela_array) - np.min(ela_array)),
                'significant_pixels': int(np.sum(ela_array > self.threshold_low)),
                'high_error_pixels': int(np.sum(ela_array > self.threshold_high)),
                'total_pixels': int(ela_array.size)
            }
            
            # Clean up temporary file
            try:
                os.unlink(temp_path)
            except:
                pass
            
            return ela_enhanced, ela_stats
            
        except Exception as e:
            self.logger.error(f"ELA calculation failed: {str(e)}")
            raise

    def _analyze_ela_results(self, ela_image: np.ndarray, ela_stats: Dict[str, float]) -> Dict[str, Any]:
        """
        Analyze ELA results to determine image authenticity indicators.
        
        Args:
            ela_image: ELA result image
            ela_stats: ELA statistics
            
        Returns:
            Analysis results dictionary
        """
        analysis = {
            'uniformity_score': self._calculate_uniformity_score(ela_image),
            'compression_consistency': self._assess_compression_consistency(ela_stats),
            'anomaly_detection': self._detect_anomalies(ela_image, ela_stats),
            'edge_analysis': self._analyze_edges(ela_image),
            'region_analysis': self._analyze_regions(ela_image)
        }
        
        # Overall assessment
        analysis['overall_assessment'] = self._get_overall_assessment(analysis)
        
        return analysis

    def _calculate_uniformity_score(self, ela_image: np.ndarray) -> float:
        """Calculate how uniform the ELA results are across the image"""
        try:
            # Convert to grayscale for analysis
            if len(ela_image.shape) == 3:
                gray_ela = cv2.cvtColor(ela_image, cv2.COLOR_RGB2GRAY)
            else:
                gray_ela = ela_image
            
            # Calculate local standard deviations
            kernel_size = 15
            kernel = np.ones((kernel_size, kernel_size), np.float32) / (kernel_size * kernel_size)
            
            # Calculate local means and variances
            local_mean = cv2.filter2D(gray_ela.astype(np.float32), -1, kernel)
            local_sqr_mean = cv2.filter2D((gray_ela.astype(np.float32))**2, -1, kernel)
            local_variance = local_sqr_mean - local_mean**2
            
            # Uniformity is inverse of variance of local variances
            variance_of_variances = np.var(local_variance)
            uniformity_score = 1.0 / (1.0 + variance_of_variances / 1000.0)  # Normalized
            
            return float(uniformity_score)
            
        except Exception as e:
            self.logger.warning(f"Uniformity calculation failed: {str(e)}")
            return 0.5  # Default neutral score

    def _assess_compression_consistency(self, ela_stats: Dict[str, float]) -> Dict[str, Any]:
        """Assess whether compression artifacts are consistent across the image"""
        consistency_assessment = {
            'mean_error_level': 'low' if ela_stats['mean_error'] < 5 else 'medium' if ela_stats['mean_error'] < 15 else 'high',
            'error_distribution': 'uniform' if ela_stats['std_error'] < ela_stats['mean_error'] else 'varied',
            'significant_pixel_ratio': ela_stats['significant_pixels'] / ela_stats['total_pixels'],
            'high_error_ratio': ela_stats['high_error_pixels'] / ela_stats['total_pixels']
        }
        
        # Determine consistency level
        if consistency_assessment['significant_pixel_ratio'] < 0.1 and consistency_assessment['error_distribution'] == 'uniform':
            consistency_assessment['level'] = 'high'
        elif consistency_assessment['significant_pixel_ratio'] < 0.3:
            consistency_assessment['level'] = 'medium'
        else:
            consistency_assessment['level'] = 'low'
        
        return consistency_assessment

    def _detect_anomalies(self, ela_image: np.ndarray, ela_stats: Dict[str, float]) -> List[Dict[str, Any]]:
        """Detect anomalous regions in the ELA image"""
        anomalies = []
        
        try:
            # Convert to grayscale for analysis
            if len(ela_image.shape) == 3:
                gray_ela = cv2.cvtColor(ela_image, cv2.COLOR_RGB2GRAY)
            else:
                gray_ela = ela_image
            
            # Find regions with significantly higher error levels
            threshold = ela_stats['mean_error'] + 2 * ela_stats['std_error']
            high_error_mask = gray_ela > threshold
            
            # Find connected components
            num_labels, labels, stats, centroids = cv2.connectedComponentsWithStats(
                high_error_mask.astype(np.uint8), connectivity=8
            )
            
            # Analyze each component
            for i in range(1, num_labels):  # Skip background (0)
                area = stats[i, cv2.CC_STAT_AREA]
                if area > 100:  # Only consider significant regions
                    x, y, w, h = stats[i, cv2.CC_STAT_LEFT], stats[i, cv2.CC_STAT_TOP], stats[i, cv2.CC_STAT_WIDTH], stats[i, cv2.CC_STAT_HEIGHT]
                    
                    anomaly = {
                        'region_id': i,
                        'bounding_box': {'x': int(x), 'y': int(y), 'width': int(w), 'height': int(h)},
                        'area': int(area),
                        'centroid': {'x': float(centroids[i][0]), 'y': float(centroids[i][1])},
                        'average_error': float(np.mean(gray_ela[labels == i])),
                        'max_error': float(np.max(gray_ela[labels == i])),
                        'significance': 'high' if area > 1000 else 'medium' if area > 500 else 'low'
                    }
                    anomalies.append(anomaly)
            
            return anomalies
            
        except Exception as e:
            self.logger.warning(f"Anomaly detection failed: {str(e)}")
            return []

    def _analyze_edges(self, ela_image: np.ndarray) -> Dict[str, Any]:
        """Analyze edge characteristics in ELA image"""
        try:
            # Convert to grayscale
            if len(ela_image.shape) == 3:
                gray_ela = cv2.cvtColor(ela_image, cv2.COLOR_RGB2GRAY)
            else:
                gray_ela = ela_image
            
            # Detect edges using Canny
            edges = cv2.Canny(gray_ela, 50, 150)
            
            # Calculate edge statistics
            edge_analysis = {
                'edge_density': float(np.sum(edges > 0) / edges.size),
                'edge_strength': float(np.mean(gray_ela[edges > 0])) if np.sum(edges > 0) > 0 else 0.0,
                'edge_consistency': self._calculate_edge_consistency(gray_ela, edges)
            }
            
            # Assess edge characteristics
            if edge_analysis['edge_density'] > 0.1:
                edge_analysis['assessment'] = 'high_activity'
            elif edge_analysis['edge_density'] > 0.05:
                edge_analysis['assessment'] = 'moderate_activity'
            else:
                edge_analysis['assessment'] = 'low_activity'
            
            return edge_analysis
            
        except Exception as e:
            self.logger.warning(f"Edge analysis failed: {str(e)}")
            return {'assessment': 'unknown'}

    def _calculate_edge_consistency(self, gray_ela: np.ndarray, edges: np.ndarray) -> float:
        """Calculate how consistent edge error levels are"""
        try:
            if np.sum(edges > 0) == 0:
                return 1.0  # No edges, perfectly consistent
            
            edge_values = gray_ela[edges > 0]
            consistency = 1.0 - (np.std(edge_values) / (np.mean(edge_values) + 1e-8))
            return max(0.0, min(1.0, consistency))
            
        except:
            return 0.5

    def _analyze_regions(self, ela_image: np.ndarray) -> Dict[str, Any]:
        """Analyze different regions of the image for consistency"""
        try:
            if len(ela_image.shape) == 3:
                gray_ela = cv2.cvtColor(ela_image, cv2.COLOR_RGB2GRAY)
            else:
                gray_ela = ela_image
            
            h, w = gray_ela.shape
            
            # Divide image into grid regions
            grid_size = 4
            region_stats = []
            
            for i in range(grid_size):
                for j in range(grid_size):
                    y1 = i * h // grid_size
                    y2 = (i + 1) * h // grid_size
                    x1 = j * w // grid_size
                    x2 = (j + 1) * w // grid_size
                    
                    region = gray_ela[y1:y2, x1:x2]
                    region_mean = float(np.mean(region))
                    region_std = float(np.std(region))
                    
                    region_stats.append({
                        'position': {'row': i, 'col': j},
                        'bounds': {'y1': y1, 'y2': y2, 'x1': x1, 'x2': x2},
                        'mean_error': region_mean,
                        'std_error': region_std
                    })
            
            # Calculate inter-region consistency
            region_means = [r['mean_error'] for r in region_stats]
            overall_consistency = 1.0 - (np.std(region_means) / (np.mean(region_means) + 1e-8))
            
            return {
                'region_statistics': region_stats,
                'inter_region_consistency': float(max(0.0, min(1.0, overall_consistency))),
                'assessment': 'consistent' if overall_consistency > 0.7 else 'inconsistent'
            }
            
        except Exception as e:
            self.logger.warning(f"Region analysis failed: {str(e)}")
            return {'assessment': 'unknown'}

    def _get_overall_assessment(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate overall assessment based on all analysis results"""
        try:
            # Weight factors for different aspects
            weights = {
                'uniformity': 0.3,
                'compression_consistency': 0.25,
                'anomalies': 0.25,
                'edges': 0.1,
                'regions': 0.1
            }
            
            # Calculate weighted score
            score = 0.0
            
            # Uniformity contribution
            score += weights['uniformity'] * analysis['uniformity_score']
            
            # Compression consistency contribution
            consistency_score = 1.0 if analysis['compression_consistency']['level'] == 'high' else 0.5 if analysis['compression_consistency']['level'] == 'medium' else 0.0
            score += weights['compression_consistency'] * consistency_score
            
            # Anomalies contribution (fewer anomalies = higher score)
            anomaly_count = len(analysis['anomaly_detection'])
            anomaly_score = 1.0 if anomaly_count == 0 else max(0.0, 1.0 - anomaly_count * 0.2)
            score += weights['anomalies'] * anomaly_score
            
            # Edge analysis contribution
            edge_score = 0.8 if analysis['edge_analysis']['assessment'] == 'low_activity' else 0.5
            score += weights['edges'] * edge_score
            
            # Region analysis contribution
            region_score = 1.0 if analysis['region_analysis']['assessment'] == 'consistent' else 0.3
            score += weights['regions'] * region_score
            
            # Determine authenticity assessment
            if score > 0.8:
                authenticity = 'likely_authentic'
                confidence = 'high'
            elif score > 0.6:
                authenticity = 'possibly_authentic'
                confidence = 'medium'
            elif score > 0.4:
                authenticity = 'uncertain'
                confidence = 'low'
            else:
                authenticity = 'likely_manipulated'
                confidence = 'medium' if score > 0.2 else 'high'
            
            return {
                'authenticity_score': float(score),
                'authenticity_assessment': authenticity,
                'confidence_level': confidence,
                'primary_concerns': self._identify_primary_concerns(analysis)
            }
            
        except Exception as e:
            self.logger.error(f"Overall assessment failed: {str(e)}")
            return {
                'authenticity_score': 0.5,
                'authenticity_assessment': 'uncertain',
                'confidence_level': 'low',
                'primary_concerns': ['Analysis error']
            }

    def _identify_primary_concerns(self, analysis: Dict[str, Any]) -> List[str]:
        """Identify the primary concerns from the analysis"""
        concerns = []
        
        try:
            # Check uniformity
            if analysis['uniformity_score'] < 0.5:
                concerns.append('Non-uniform error distribution detected')
            
            # Check compression consistency
            if analysis['compression_consistency']['level'] == 'low':
                concerns.append('Inconsistent compression artifacts')
            
            # Check anomalies
            anomaly_count = len(analysis['anomaly_detection'])
            if anomaly_count > 0:
                concerns.append(f'{anomaly_count} suspicious region(s) detected')
            
            # Check edge activity
            if analysis['edge_analysis']['assessment'] == 'high_activity':
                concerns.append('High edge activity may indicate manipulation')
            
            # Check region consistency
            if analysis['region_analysis']['assessment'] == 'inconsistent':
                concerns.append('Inconsistent error levels across image regions')
            
            if not concerns:
                concerns.append('No significant concerns detected')
            
            return concerns
            
        except:
            return ['Analysis incomplete']

    def _detect_suspicious_regions(self, ela_image: np.ndarray) -> List[Dict[str, Any]]:
        """Detect regions that are suspicious for tampering"""
        try:
            # This is a simplified version of anomaly detection focused on tampering
            if len(ela_image.shape) == 3:
                gray_ela = cv2.cvtColor(ela_image, cv2.COLOR_RGB2GRAY)
            else:
                gray_ela = ela_image
            
            # Use adaptive thresholding to find suspicious regions
            mean_val = np.mean(gray_ela)
            std_val = np.std(gray_ela)
            threshold = mean_val + 1.5 * std_val
            
            suspicious_mask = gray_ela > threshold
            
            # Find connected components
            num_labels, labels, stats, centroids = cv2.connectedComponentsWithStats(
                suspicious_mask.astype(np.uint8), connectivity=8
            )
            
            suspicious_regions = []
            for i in range(1, num_labels):
                area = stats[i, cv2.CC_STAT_AREA]
                if area > 50:  # Minimum area threshold
                    x, y, w, h = stats[i, cv2.CC_STAT_LEFT], stats[i, cv2.CC_STAT_TOP], stats[i, cv2.CC_STAT_WIDTH], stats[i, cv2.CC_STAT_HEIGHT]
                    
                    region = {
                        'id': i,
                        'bounding_box': {'x': int(x), 'y': int(y), 'width': int(w), 'height': int(h)},
                        'area': int(area),
                        'centroid': {'x': float(centroids[i][0]), 'y': float(centroids[i][1])},
                        'suspicion_level': 'high' if area > 500 else 'medium' if area > 200 else 'low',
                        'avg_error_level': float(np.mean(gray_ela[labels == i]))
                    }
                    suspicious_regions.append(region)
            
            return suspicious_regions
            
        except Exception as e:
            self.logger.warning(f"Suspicious region detection failed: {str(e)}")
            return []

    def _calculate_tampering_probability(self, ela_stats: Dict[str, float], suspicious_regions: List[Dict]) -> float:
        """Calculate the probability that the image has been tampered with"""
        try:
            # Base probability calculation
            probability = 0.0
            
            # Factor 1: Mean error level
            if ela_stats['mean_error'] > 20:
                probability += 0.3
            elif ela_stats['mean_error'] > 10:
                probability += 0.15
            
            # Factor 2: Error distribution
            error_variation = ela_stats['std_error'] / (ela_stats['mean_error'] + 1e-8)
            if error_variation > 2.0:
                probability += 0.25
            elif error_variation > 1.0:
                probability += 0.1
            
            # Factor 3: Suspicious regions
            if len(suspicious_regions) > 0:
                high_suspicion_count = sum(1 for r in suspicious_regions if r['suspicion_level'] == 'high')
                probability += min(0.4, high_suspicion_count * 0.15)
            
            # Factor 4: High error pixel ratio
            high_error_ratio = ela_stats['high_error_pixels'] / ela_stats['total_pixels']
            if high_error_ratio > 0.1:
                probability += 0.2
            elif high_error_ratio > 0.05:
                probability += 0.1
            
            # Normalize probability to [0, 1]
            return min(1.0, max(0.0, probability))
            
        except Exception as e:
            self.logger.warning(f"Tampering probability calculation failed: {str(e)}")
            return 0.5  # Default uncertain probability

    def _get_confidence_level(self, probability: float) -> str:
        """Determine confidence level based on probability"""
        if probability > 0.8 or probability < 0.2:
            return 'high'
        elif probability > 0.6 or probability < 0.4:
            return 'medium'
        else:
            return 'low'

    def _get_risk_level(self, probability: float) -> str:
        """Determine risk level based on tampering probability"""
        if probability > 0.7:
            return 'high'
        elif probability > 0.4:
            return 'medium'
        else:
            return 'low'

    def _create_ela_visualization(self, ela_image: np.ndarray) -> np.ndarray:
        """Create enhanced visualization of ELA results"""
        try:
            # Convert to grayscale if needed
            if len(ela_image.shape) == 3:
                gray_ela = cv2.cvtColor(ela_image, cv2.COLOR_RGB2GRAY)
            else:
                gray_ela = ela_image.copy()
            
            # Apply colormap for better visualization
            ela_colored = cv2.applyColorMap(gray_ela, cv2.COLORMAP_JET)
            
            return ela_colored
            
        except Exception as e:
            self.logger.warning(f"Visualization creation failed: {str(e)}")
            return ela_image

    def _create_difference_heatmap(self, ela_image: np.ndarray) -> str:
        """Create a heatmap visualization of error differences"""
        try:
            if len(ela_image.shape) == 3:
                gray_ela = cv2.cvtColor(ela_image, cv2.COLOR_RGB2GRAY)
            else:
                gray_ela = ela_image.copy()
            
            # Create heatmap
            heatmap = cv2.applyColorMap(gray_ela, cv2.COLORMAP_HOT)
            
            return self._encode_image_base64(heatmap)
            
        except Exception as e:
            self.logger.warning(f"Heatmap creation failed: {str(e)}")
            return ""

    def _encode_image_base64(self, image: np.ndarray) -> str:
        """Encode image as base64 string"""
        try:
            # Convert to PIL Image
            if len(image.shape) == 3:
                pil_image = Image.fromarray(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))
            else:
                pil_image = Image.fromarray(image)
            
            # Encode as base64
            buffer = io.BytesIO()
            pil_image.save(buffer, format='PNG')
            buffer.seek(0)
            
            base64_string = base64.b64encode(buffer.getvalue()).decode('utf-8')
            return base64_string
            
        except Exception as e:
            self.logger.warning(f"Base64 encoding failed: {str(e)}")
            return ""

    def _generate_forensic_notes(self, analysis_results: Dict[str, Any], tampering_probability: float) -> List[str]:
        """Generate forensic analysis notes"""
        notes = []
        
        try:
            # Overall assessment note
            if tampering_probability > 0.7:
                notes.append("⚠️ HIGH: Strong indicators of image manipulation detected")
            elif tampering_probability > 0.4:
                notes.append("⚠️ MEDIUM: Possible signs of image manipulation")
            else:
                notes.append("✅ LOW: Image appears to have consistent compression artifacts")
            
            # Specific findings
            if analysis_results['uniformity_score'] < 0.5:
                notes.append("🔍 Non-uniform error distribution suggests possible editing")
            
            anomaly_count = len(analysis_results['anomaly_detection'])
            if anomaly_count > 0:
                notes.append(f"🎯 {anomaly_count} suspicious region(s) identified for further investigation")
            
            if analysis_results['compression_consistency']['level'] == 'low':
                notes.append("📊 Inconsistent compression levels across image regions")
            
            if analysis_results['edge_analysis']['assessment'] == 'high_activity':
                notes.append("🔧 High edge activity may indicate post-processing or manipulation")
            
            # Technical notes
            notes.append(f"📈 Error level uniformity score: {analysis_results['uniformity_score']:.3f}")
            notes.append(f"🎚️ Compression consistency: {analysis_results['compression_consistency']['level']}")
            
            return notes
            
        except Exception as e:
            self.logger.warning(f"Forensic notes generation failed: {str(e)}")
            return ["⚠️ Error generating forensic analysis notes"]

    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()

    def multi_quality_ela_analysis(self, image_path: str, quality_levels: List[int] = None) -> Dict[str, Any]:
        """
        Perform ELA analysis at multiple quality levels for comprehensive assessment.
        
        Args:
            image_path: Path to the image file
            quality_levels: List of JPEG quality levels to test
            
        Returns:
            Dictionary containing multi-quality ELA results
        """
        if quality_levels is None:
            quality_levels = self.quality_levels
            
        multi_results = {
            'analysis_timestamp': self._get_timestamp(),
            'quality_levels_tested': quality_levels,
            'results_by_quality': {},
            'comparative_analysis': {},
            'overall_assessment': {}
        }
        
        try:
            # Perform ELA at each quality level
            for quality in quality_levels:
                result = self.perform_ela_analysis(image_path, quality)
                if 'error' not in result:
                    multi_results['results_by_quality'][str(quality)] = result
            
            # Perform comparative analysis
            multi_results['comparative_analysis'] = self._compare_quality_results(
                multi_results['results_by_quality']
            )
            
            # Generate overall assessment
            multi_results['overall_assessment'] = self._assess_multi_quality_results(
                multi_results['results_by_quality'],
                multi_results['comparative_analysis']
            )
            
            return multi_results
            
        except Exception as e:
            self.logger.error(f"Multi-quality ELA analysis failed: {str(e)}")
            return {'error': str(e), 'analysis_failed': True}

    def _compare_quality_results(self, results_by_quality: Dict[str, Any]) -> Dict[str, Any]:
        """Compare ELA results across different quality levels"""
        try:
            if len(results_by_quality) < 2:
                return {'comparison': 'insufficient_data'}
            
            # Extract key metrics for comparison
            qualities = list(results_by_quality.keys())
            tampering_probs = [results_by_quality[q]['tampering_assessment']['probability'] for q in qualities]
            uniformity_scores = [results_by_quality[q]['analysis_results']['uniformity_score'] for q in qualities]
            
            comparison = {
                'probability_variance': float(np.var(tampering_probs)),
                'uniformity_variance': float(np.var(uniformity_scores)),
                'most_suspicious_quality': qualities[np.argmax(tampering_probs)],
                'least_suspicious_quality': qualities[np.argmin(tampering_probs)],
                'consistency_across_qualities': 'high' if np.var(tampering_probs) < 0.05 else 'medium' if np.var(tampering_probs) < 0.15 else 'low'
            }
            
            return comparison
            
        except Exception as e:
            self.logger.warning(f"Quality comparison failed: {str(e)}")
            return {'comparison': 'failed'}

    def _assess_multi_quality_results(self, results_by_quality: Dict[str, Any], comparative_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate overall assessment from multi-quality analysis"""
        try:
            if not results_by_quality:
                return {'assessment': 'no_data'}
            
            # Calculate average metrics
            all_probs = [r['tampering_assessment']['probability'] for r in results_by_quality.values()]
            avg_probability = float(np.mean(all_probs))
            max_probability = float(np.max(all_probs))
            
            # Determine final assessment
            if comparative_analysis.get('consistency_across_qualities') == 'low':
                assessment = 'inconsistent_results_suggest_manipulation'
                confidence = 'high'
            elif avg_probability > 0.7:
                assessment = 'likely_manipulated'
                confidence = 'high' if max_probability > 0.8 else 'medium'
            elif avg_probability > 0.4:
                assessment = 'possibly_manipulated'
                confidence = 'medium'
            else:
                assessment = 'likely_authentic'
                confidence = 'high' if avg_probability < 0.2 else 'medium'
            
            return {
                'final_assessment': assessment,
                'confidence_level': confidence,
                'average_tampering_probability': avg_probability,
                'max_tampering_probability': max_probability,
                'recommended_quality_for_analysis': comparative_analysis.get('most_suspicious_quality', '95')
            }
            
        except Exception as e:
            self.logger.warning(f"Multi-quality assessment failed: {str(e)}")
            return {'assessment': 'analysis_error'}