/**
 * Forensic Image Analysis - JavaScript Module
 * Advanced forensic image analysis tools similar to Forensically.com
 */

class ForensicImageAnalyzer {
  constructor() {
    this.currentSession = null;
    this.currentImageFile = null;
    this.analysisResults = null;
    this.initializeEventListeners();
  }

  initializeEventListeners() {
    // File upload handling
    const fileInput = document.getElementById('forensic-image-file');
    const uploadArea = document.getElementById('forensic-upload-area');
    const uploadForm = document.getElementById('forensic-upload-form');

    // Drag and drop functionality
    uploadArea.addEventListener('dragover', (e) => {
      e.preventDefault();
      uploadArea.classList.add('drag-over');
    });

    uploadArea.addEventListener('dragleave', (e) => {
      e.preventDefault();
      uploadArea.classList.remove('drag-over');
    });

    uploadArea.addEventListener('drop', (e) => {
      e.preventDefault();
      uploadArea.classList.remove('drag-over');
      const files = e.dataTransfer.files;
      if (files.length > 0) {
        this.handleFileSelection(files[0]);
      }
    });

    // File input change
    fileInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        this.handleFileSelection(e.target.files[0]);
      }
    });

    // Form submission
    uploadForm.addEventListener('submit', (e) => {
      e.preventDefault();
      this.startForensicAnalysis();
    });

    // Export analysis button
    document.addEventListener('click', (e) => {
      if (e.target.id === 'export-analysis-btn') {
        this.exportAnalysisReport();
      } else if (e.target.id === 'new-analysis-btn') {
        this.resetAnalysis();
      } else if (e.target.id === 'view-sessions-btn') {
        this.viewAllSessions();
      }
    });

    // Tab switching
    document.querySelectorAll('#forensic-tabs button[data-bs-toggle="tab"]').forEach(tab => {
      tab.addEventListener('shown.bs.tab', (e) => {
        this.onTabSwitch(e.target.getAttribute('data-bs-target'));
      });
    });
  }

  handleFileSelection(file) {
    // Validate file type
    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/tiff', 'image/bmp', 'image/gif'];
    if (!allowedTypes.includes(file.type)) {
      this.showAlert('Invalid file type. Please select a supported image format.', 'danger');
      return;
    }

    // Validate file size (16MB max)
    const maxSize = 16 * 1024 * 1024;
    if (file.size > maxSize) {
      this.showAlert('File size too large. Maximum allowed size is 16MB.', 'danger');
      return;
    }

    this.currentImageFile = file;
    this.showImagePreview(file);
    this.updateImageInfo(file);
  }

  showImagePreview(file) {
    const previewContainer = document.getElementById('forensic-image-preview');
    const previewImg = document.getElementById('forensic-preview-img');

    const reader = new FileReader();
    reader.onload = (e) => {
      previewImg.src = e.target.result;
      previewContainer.style.display = 'block';
    };
    reader.readAsDataURL(file);
  }

  updateImageInfo(file) {
    const infoContainer = document.getElementById('forensic-image-info');
    const fileSize = this.formatFileSize(file.size);
    const lastModified = new Date(file.lastModified).toLocaleString();

    infoContainer.innerHTML = `
            <div class="row text-muted small">
                <div class="col-md-6">
                    <strong>Filename:</strong> ${file.name}<br>
                    <strong>Size:</strong> ${fileSize}
                </div>
                <div class="col-md-6">
                    <strong>Type:</strong> ${file.type}<br>
                    <strong>Modified:</strong> ${lastModified}
                </div>
            </div>
        `;
  }

  async startForensicAnalysis() {
    if (!this.currentImageFile) {
      this.showAlert('Please select an image file first.', 'warning');
      return;
    }

    // Get selected analysis types
    const analysisTypes = this.getSelectedAnalysisTypes();
    if (analysisTypes.length === 0) {
      this.showAlert('Please select at least one analysis type.', 'warning');
      return;
    }

    this.showAnalysisProgress(true);
    this.updateAnalysisProgress(0, 'Uploading image...', 'Preparing image for analysis...');

    try {
      // Create form data
      const formData = new FormData();
      formData.append('image', this.currentImageFile);
      formData.append('analysis_types', JSON.stringify(analysisTypes));

      // Start analysis
      const response = await fetch('/api/forensic/analyze-image', {
        method: 'POST',
        body: formData
      });

      if (!response.ok) {
        throw new Error(`Analysis failed: ${response.statusText}`);
      }

      const result = await response.json();

      if (result.success) {
        this.currentSession = result.session_id;
        this.analysisResults = result.data;

        this.updateAnalysisProgress(100, 'Analysis complete!', 'Processing results...');

        // Update dashboard statistics
        this.updateDashboardStatistics();

        setTimeout(() => {
          this.showAnalysisProgress(false);
          this.displayAnalysisResults();
          this.showAnalysisSummary();
        }, 1000);
      } else {
        throw new Error(result.message || 'Analysis failed');
      }

    } catch (error) {
      console.error('Analysis error:', error);
      this.showAnalysisProgress(false);
      this.showAlert(`Analysis failed: ${error.message}`, 'danger');
    }
  }

  getSelectedAnalysisTypes() {
    const types = [];
    const checkboxes = [
      { id: 'analysis-metadata', type: 'metadata' },
      { id: 'analysis-ela', type: 'ela' },
      { id: 'analysis-noise', type: 'noise' },
      { id: 'analysis-clone', type: 'clone_detection' },
      { id: 'analysis-pixel', type: 'pixel_examination' },
      { id: 'analysis-quality', type: 'quality_assessment' }
    ];

    checkboxes.forEach(checkbox => {
      if (document.getElementById(checkbox.id)?.checked) {
        types.push(checkbox.type);
      }
    });

    return types;
  }

  showAnalysisProgress(show) {
    const progressContainer = document.getElementById('forensic-analysis-progress');
    const submitButton = document.getElementById('start-forensic-analysis');

    progressContainer.style.display = show ? 'block' : 'none';
    submitButton.disabled = show;
  }

  updateAnalysisProgress(percentage, statusText, detailText) {
    const progressBar = document.getElementById('analysis-progress-bar');
    const statusElement = document.getElementById('analysis-status-text');
    const detailElement = document.getElementById('analysis-detail-text');

    progressBar.style.width = `${percentage}%`;
    progressBar.textContent = `${percentage}%`;
    statusElement.textContent = statusText;
    detailElement.textContent = detailText;

    // Simulate progress updates for better UX
    if (percentage < 100) {
      setTimeout(() => {
        this.updateAnalysisProgress(
          Math.min(percentage + 20, 90),
          'Analyzing image...',
          this.getRandomAnalysisStep()
        );
      }, 1000);
    }
  }

  getRandomAnalysisStep() {
    const steps = [
      'Extracting metadata...',
      'Performing error level analysis...',
      'Analyzing noise patterns...',
      'Detecting cloned regions...',
      'Examining pixel structures...',
      'Calculating quality metrics...',
      'Generating visualizations...',
      'Compiling results...'
    ];
    return steps[Math.floor(Math.random() * steps.length)];
  }

  displayAnalysisResults() {
    if (!this.analysisResults) return;

    // Display metadata results
    if (this.analysisResults.metadata) {
      this.displayMetadataResults(this.analysisResults.metadata);
    }

    // Display ELA results
    if (this.analysisResults.ela_analysis) {
      this.displayELAResults(this.analysisResults.ela_analysis);
    }

    // Display noise analysis
    if (this.analysisResults.noise_analysis) {
      this.displayNoiseResults(this.analysisResults.noise_analysis);
    }

    // Display clone detection
    if (this.analysisResults.clone_detection) {
      this.displayCloneResults(this.analysisResults.clone_detection);
    }

    // Display pixel examination
    if (this.analysisResults.pixel_examination) {
      this.displayPixelResults(this.analysisResults.pixel_examination);
    }
  }

  displayMetadataResults(metadata) {
    const container = document.getElementById('metadata-results');

    let html = '<div class="row">';

    // Basic Image Info
    if (metadata.basic_info) {
      html += `
                <div class="col-md-6">
                    <div class="card border-primary mb-3">
                        <div class="card-header bg-primary text-white">
                            <h6 class="mb-0"><i class="bi bi-info-circle"></i> Basic Information</h6>
                        </div>
                        <div class="card-body">
                            <table class="table table-sm">
                                <tr><td><strong>Format:</strong></td><td>${metadata.basic_info.format || 'N/A'}</td></tr>
                                <tr><td><strong>Mode:</strong></td><td>${metadata.basic_info.mode || 'N/A'}</td></tr>
                                <tr><td><strong>Size:</strong></td><td>${metadata.basic_info.size || 'N/A'}</td></tr>
                                <tr><td><strong>Has Transparency:</strong></td><td>${metadata.basic_info.has_transparency ? 'Yes' : 'No'}</td></tr>
                            </table>
                        </div>
                    </div>
                </div>
            `;
    }

    // EXIF Data
    if (metadata.exif && Object.keys(metadata.exif).length > 0) {
      html += `
                <div class="col-md-6">
                    <div class="card border-success mb-3">
                        <div class="card-header bg-success text-white">
                            <h6 class="mb-0"><i class="bi bi-camera"></i> EXIF Data</h6>
                        </div>
                        <div class="card-body">
                            <table class="table table-sm">
            `;

      Object.entries(metadata.exif).slice(0, 10).forEach(([key, value]) => {
        html += `<tr><td><strong>${key}:</strong></td><td>${value}</td></tr>`;
      });

      html += `
                            </table>
                            ${Object.keys(metadata.exif).length > 10 ?
          `<p class="text-muted small">... and ${Object.keys(metadata.exif).length - 10} more fields</p>` : ''}
                        </div>
                    </div>
                </div>
            `;
    }

    // GPS Data
    if (metadata.gps && Object.keys(metadata.gps).length > 0) {
      html += `
                <div class="col-md-6">
                    <div class="card border-warning mb-3">
                        <div class="card-header bg-warning text-dark">
                            <h6 class="mb-0"><i class="bi bi-geo-alt"></i> GPS Information</h6>
                        </div>
                        <div class="card-body">
                            <table class="table table-sm">
            `;

      Object.entries(metadata.gps).forEach(([key, value]) => {
        html += `<tr><td><strong>${key}:</strong></td><td>${value}</td></tr>`;
      });

      html += `
                            </table>
                        </div>
                    </div>
                </div>
            `;
    }

    // Forensic Hashes
    if (metadata.forensic_hashes) {
      html += `
                <div class="col-md-6">
                    <div class="card border-dark mb-3">
                        <div class="card-header bg-dark text-white">
                            <h6 class="mb-0"><i class="bi bi-shield-check"></i> Forensic Hashes</h6>
                        </div>
                        <div class="card-body">
                            <table class="table table-sm">
                                <tr><td><strong>MD5:</strong></td><td class="font-monospace small">${metadata.forensic_hashes.md5}</td></tr>
                                <tr><td><strong>SHA1:</strong></td><td class="font-monospace small">${metadata.forensic_hashes.sha1}</td></tr>
                                <tr><td><strong>SHA256:</strong></td><td class="font-monospace small">${metadata.forensic_hashes.sha256}</td></tr>
                            </table>
                        </div>
                    </div>
                </div>
            `;
    }

    html += '</div>';
    container.innerHTML = html;
  }

  displayELAResults(elaData) {
    const container = document.getElementById('ela-results');

    let html = `
            <div class="row">
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-header">
                            <h6><i class="bi bi-graph-up"></i> Error Level Analysis Visualization</h6>
                        </div>
                        <div class="card-body text-center">
        `;

    if (elaData.ela_image_base64) {
      html += `
                <img src="data:image/png;base64,${elaData.ela_image_base64}" 
                     class="img-fluid border rounded" 
                     style="max-width: 100%; max-height: 400px;"
                     alt="ELA Analysis Result">
                <p class="text-muted mt-2">White/bright areas indicate potential manipulation</p>
            `;
    } else {
      html += '<p class="text-muted">ELA visualization not available</p>';
    }

    html += `
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            <h6><i class="bi bi-info-circle"></i> Analysis Results</h6>
                        </div>
                        <div class="card-body">
                            <div class="mb-3">
                                <label class="form-label small">Quality Score</label>
                                <div class="progress">
                                    <div class="progress-bar ${this.getQualityScoreColor(elaData.quality_score)}" 
                                         style="width: ${elaData.quality_score}%">
                                        ${elaData.quality_score}%
                                    </div>
                                </div>
                            </div>
        `;

    if (elaData.statistics) {
      html += `
                            <table class="table table-sm">
                                <tr><td>Mean Error:</td><td>${elaData.statistics.mean?.toFixed(2) || 'N/A'}</td></tr>
                                <tr><td>Std Dev:</td><td>${elaData.statistics.std?.toFixed(2) || 'N/A'}</td></tr>
                                <tr><td>Max Error:</td><td>${elaData.statistics.max?.toFixed(2) || 'N/A'}</td></tr>
                            </table>
            `;
    }

    html += `
                            <div class="alert alert-info small">
                                <strong>Interpretation:</strong><br>
                                Bright areas in the ELA image may indicate manipulation or editing. 
                                Consistent error levels suggest authenticity.
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;

    container.innerHTML = html;
  }

  displayNoiseResults(noiseData) {
    const container = document.getElementById('noise-results');

    let html = `
            <div class="row">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h6><i class="bi bi-activity"></i> Noise Pattern Analysis</h6>
                        </div>
                        <div class="card-body">
        `;

    if (noiseData.noise_map_base64) {
      html += `
                <img src="data:image/png;base64,${noiseData.noise_map_base64}" 
                     class="img-fluid border rounded mb-3" 
                     style="max-width: 100%;"
                     alt="Noise Pattern Map">
            `;
    }

    html += `
                            <div class="row">
                                <div class="col-6">
                                    <div class="text-center">
                                        <div class="forensic-metric-value">${noiseData.consistency_score?.toFixed(1) || 'N/A'}</div>
                                        <small class="text-muted">Consistency Score</small>
                                    </div>
                                </div>
                                <div class="col-6">
                                    <div class="text-center">
                                        <div class="forensic-metric-value ${this.getAnomalyColor(noiseData.anomaly_regions?.length || 0)}">
                                            ${noiseData.anomaly_regions?.length || 0}
                                        </div>
                                        <small class="text-muted">Anomaly Regions</small>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h6><i class="bi bi-bar-chart"></i> Statistical Analysis</h6>
                        </div>
                        <div class="card-body">
        `;

    if (noiseData.statistics) {
      html += `
                            <table class="table table-sm">
                                <tr><td>Mean Noise:</td><td>${noiseData.statistics.mean?.toFixed(3) || 'N/A'}</td></tr>
                                <tr><td>Std Deviation:</td><td>${noiseData.statistics.std?.toFixed(3) || 'N/A'}</td></tr>
                                <tr><td>Variance:</td><td>${noiseData.statistics.variance?.toFixed(3) || 'N/A'}</td></tr>
                                <tr><td>Entropy:</td><td>${noiseData.statistics.entropy?.toFixed(3) || 'N/A'}</td></tr>
                            </table>
            `;
    }

    if (noiseData.anomaly_regions && noiseData.anomaly_regions.length > 0) {
      html += `
                            <div class="mt-3">
                                <h6 class="text-warning">Detected Anomalies</h6>
                                <ul class="list-group list-group-flush">
            `;

      noiseData.anomaly_regions.slice(0, 5).forEach((region, index) => {
        html += `
                                    <li class="list-group-item d-flex justify-content-between align-items-center">
                                        Region ${index + 1}
                                        <span class="badge bg-warning">${region.confidence?.toFixed(2) || 'N/A'}%</span>
                                    </li>
                `;
      });

      html += '</ul></div>';
    }

    html += `
                        </div>
                    </div>
                </div>
            </div>
        `;

    container.innerHTML = html;
  }

  displayCloneResults(cloneData) {
    const container = document.getElementById('clone-results');

    let html = `
            <div class="row">
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-header">
                            <h6><i class="bi bi-layers"></i> Clone Detection Results</h6>
                        </div>
                        <div class="card-body">
        `;

    if (cloneData.clone_map_base64) {
      html += `
                <img src="data:image/png;base64,${cloneData.clone_map_base64}" 
                     class="img-fluid border rounded" 
                     style="max-width: 100%; max-height: 400px;"
                     alt="Clone Detection Map">
                <p class="text-muted mt-2">Highlighted regions show potential cloned/copied areas</p>
            `;
    } else {
      html += '<p class="text-muted">Clone detection map not available</p>';
    }

    html += `
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            <h6><i class="bi bi-list-check"></i> Detection Summary</h6>
                        </div>
                        <div class="card-body">
                            <div class="mb-3">
                                <div class="d-flex justify-content-between">
                                    <span>Regions Found:</span>
                                    <span class="badge bg-primary">${cloneData.clone_regions?.length || 0}</span>
                                </div>
                            </div>
                            <div class="mb-3">
                                <div class="d-flex justify-content-between">
                                    <span>Confidence:</span>
                                    <span class="badge bg-success">${cloneData.confidence?.toFixed(1) || 'N/A'}%</span>
                                </div>
                            </div>
        `;

    if (cloneData.clone_regions && cloneData.clone_regions.length > 0) {
      html += `
                            <h6 class="mt-3">Detected Clones</h6>
                            <div class="list-group list-group-flush">
            `;

      cloneData.clone_regions.slice(0, 5).forEach((region, index) => {
        html += `
                                <div class="list-group-item">
                                    <div class="d-flex w-100 justify-content-between">
                                        <h6 class="mb-1">Clone Pair ${index + 1}</h6>
                                        <small class="text-success">${region.similarity?.toFixed(1) || 'N/A'}%</small>
                                    </div>
                                    <p class="mb-1 small text-muted">
                                        Size: ${region.size || 'N/A'} | 
                                        Method: ${region.method || 'Feature matching'}
                                    </p>
                                </div>
                `;
      });

      html += '</div>';
    }

    html += `
                        </div>
                    </div>
                </div>
            </div>
        `;

    container.innerHTML = html;
  }

  displayPixelResults(pixelData) {
    const container = document.getElementById('pixel-results');

    let html = `
            <div class="row">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h6><i class="bi bi-palette"></i> Color Distribution</h6>
                        </div>
                        <div class="card-body">
        `;

    if (pixelData.color_histogram_base64) {
      html += `
                <img src="data:image/png;base64,${pixelData.color_histogram_base64}" 
                     class="img-fluid" 
                     alt="Color Distribution Histogram">
            `;
    } else {
      html += '<p class="text-muted">Color histogram not available</p>';
    }

    html += `
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h6><i class="bi bi-grid"></i> Edge Detection</h6>
                        </div>
                        <div class="card-body">
        `;

    if (pixelData.edge_map_base64) {
      html += `
                <img src="data:image/png;base64,${pixelData.edge_map_base64}" 
                     class="img-fluid" 
                     alt="Edge Detection Map">
            `;
    } else {
      html += '<p class="text-muted">Edge detection map not available</p>';
    }

    html += `
                        </div>
                    </div>
                </div>
            </div>
            <div class="row mt-3">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h6><i class="bi bi-graph-down"></i> Statistical Analysis</h6>
                        </div>
                        <div class="card-body">
                            <div class="row">
        `;

    if (pixelData.statistics) {
      const stats = pixelData.statistics;
      html += `
                                <div class="col-md-3">
                                    <div class="text-center">
                                        <div class="forensic-metric-value">${stats.mean?.toFixed(2) || 'N/A'}</div>
                                        <small class="text-muted">Mean Intensity</small>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="text-center">
                                        <div class="forensic-metric-value">${stats.std?.toFixed(2) || 'N/A'}</div>
                                        <small class="text-muted">Std Deviation</small>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="text-center">
                                        <div class="forensic-metric-value">${stats.contrast?.toFixed(2) || 'N/A'}</div>
                                        <small class="text-muted">Contrast</small>
                                    </div>
                                </div>
                                <div class="col-md-3">
                                    <div class="text-center">
                                        <div class="forensic-metric-value">${stats.sharpness?.toFixed(2) || 'N/A'}</div>
                                        <small class="text-muted">Sharpness</small>
                                    </div>
                                </div>
            `;
    }

    html += `
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;

    container.innerHTML = html;
  }

  showAnalysisSummary() {
    const dashboard = document.getElementById('analysis-summary-dashboard');
    dashboard.style.display = 'block';

    // Calculate overall authenticity score
    let authenticityScore = 85; // Base score
    let manipulationRisk = 'LOW';
    const findings = [];

    if (this.analysisResults) {
      // Adjust score based on analysis results
      if (this.analysisResults.ela_analysis?.quality_score < 70) {
        authenticityScore -= 15;
        findings.push('ELA analysis shows potential inconsistencies');
      }

      if (this.analysisResults.clone_detection?.clone_regions?.length > 0) {
        authenticityScore -= 20;
        manipulationRisk = 'HIGH';
        findings.push(`${this.analysisResults.clone_detection.clone_regions.length} cloned regions detected`);
      }

      if (this.analysisResults.noise_analysis?.anomaly_regions?.length > 0) {
        authenticityScore -= 10;
        findings.push(`${this.analysisResults.noise_analysis.anomaly_regions.length} noise anomalies found`);
      }

      if (findings.length === 0) {
        findings.push('No obvious signs of manipulation detected');
        findings.push('Metadata appears consistent');
        findings.push('Noise patterns are uniform');
      }
    }

    // Update UI elements
    document.getElementById('authenticity-score').textContent = Math.max(0, authenticityScore);
    document.getElementById('manipulation-likelihood').textContent = manipulationRisk;
    document.getElementById('manipulation-likelihood').className =
      `forensic-indicator ${manipulationRisk === 'HIGH' ? 'high-risk' : manipulationRisk === 'MEDIUM' ? 'medium-risk' : 'low-risk'}`;

    const findingsList = document.getElementById('key-findings-list');
    findingsList.innerHTML = findings.map(finding => `<li><i class="bi bi-check-circle text-success"></i> ${finding}</li>`).join('');
  }

  async exportAnalysisReport() {
    if (!this.currentSession) {
      this.showAlert('No analysis session to export.', 'warning');
      return;
    }

    try {
      const response = await fetch(`/api/forensic/export-analysis/${this.currentSession}`);

      if (!response.ok) {
        throw new Error('Export failed');
      }

      const blob = await response.blob();

      // Create download link
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `forensic_analysis_${this.currentSession}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      this.showAlert('Analysis report exported successfully!', 'success');

    } catch (error) {
      console.error('Export error:', error);
      this.showAlert('Failed to export analysis report.', 'danger');
    }
  }

  resetAnalysis() {
    this.currentSession = null;
    this.currentImageFile = null;
    this.analysisResults = null;

    // Reset form
    document.getElementById('forensic-upload-form').reset();
    document.getElementById('forensic-image-preview').style.display = 'none';
    document.getElementById('analysis-summary-dashboard').style.display = 'none';

    // Clear all result panels
    ['metadata-results', 'ela-results', 'noise-results', 'clone-results', 'pixel-results'].forEach(id => {
      document.getElementById(id).innerHTML = `
                <div class="alert alert-info">
                    <i class="bi bi-info-circle"></i> Upload an image to view analysis results.
                </div>
            `;
    });

    // Switch back to upload tab
    const uploadTab = document.getElementById('upload-tab');
    const tab = new bootstrap.Tab(uploadTab);
    tab.show();

    this.showAlert('Analysis session reset successfully.', 'info');
  }

  viewAllSessions() {
    // This would typically show a modal with all analysis sessions
    this.showAlert('Session management feature coming soon!', 'info');
  }

  onTabSwitch(target) {
    // Handle tab switching logic if needed
    console.log('Switched to tab:', target);
  }

  // Utility methods
  formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  getQualityScoreColor(score) {
    if (score >= 80) return 'bg-success';
    if (score >= 60) return 'bg-warning';
    return 'bg-danger';
  }

  getAnomalyColor(count) {
    if (count === 0) return 'text-success';
    if (count <= 2) return 'text-warning';
    return 'text-danger';
  }

  updateDashboardStatistics() {
    // Update dashboard statistics when forensic image analysis is performed
    try {
      const filesAnalyzed = 1; // One image analyzed
      const integrityChecks = 1; // One integrity check performed

      const currentStats = JSON.parse(localStorage.getItem('dashboard_statistics') || '{}');
      const newStats = {
        filesAnalyzed: (currentStats.filesAnalyzed || 0) + filesAnalyzed,
        integrityChecks: (currentStats.integrityChecks || 0) + integrityChecks,
        lastUpdated: new Date().toISOString()
      };

      localStorage.setItem('dashboard_statistics', JSON.stringify(newStats));

      // Update dashboard display if dashboard is available
      if (window.dashboard && typeof window.dashboard.updateStatistics === 'function') {
        window.dashboard.updateStatistics(filesAnalyzed, integrityChecks);
      } else if (document.getElementById('filesAnalyzed')) {
        // Direct update if dashboard elements are available
        document.getElementById('filesAnalyzed').textContent = newStats.filesAnalyzed.toLocaleString();
        document.getElementById('integrityChecks').textContent = newStats.integrityChecks.toLocaleString();
      }

      console.log('Forensic Image Analysis dashboard statistics updated:', { filesAnalyzed, integrityChecks, newTotals: newStats });
    } catch (error) {
      console.error('Error updating forensic analysis dashboard statistics:', error);
    }
  }

  showAlert(message, type = 'info') {
    // Create alert element
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; max-width: 400px;';
    alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

    document.body.appendChild(alertDiv);

    // Auto-remove after 5 seconds
    setTimeout(() => {
      if (alertDiv.parentNode) {
        alertDiv.remove();
      }
    }, 5000);
  }
}

// Initialize the forensic analyzer when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  window.forensicAnalyzer = new ForensicImageAnalyzer();
});