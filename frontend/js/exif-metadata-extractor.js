/**
 * EXIF Metadata Extraction - JavaScript Module
 * Comprehensive EXIF metadata extraction and analysis for digital forensics
 */

class EXIFMetadataExtractor {
    constructor() {
        this.currentImageFile = null;
        this.extractionResults = null;
        this.currentExtractionType = 'full';
        this.initializeEventListeners();
    }

    initializeEventListeners() {
        // File upload handling
        const fileInput = document.getElementById('exif-image-file');
        const uploadArea = document.getElementById('exif-upload-area');
        const uploadForm = document.getElementById('exif-upload-form');

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
            this.startMetadataExtraction();
        });

        // Extraction type selection
        document.querySelectorAll('input[name="extractionType"]').forEach(radio => {
            radio.addEventListener('change', (e) => {
                this.currentExtractionType = e.target.value;
            });
        });

        // Action buttons
        document.addEventListener('click', (e) => {
            if (e.target.id === 'export-metadata-btn') {
                this.exportMetadataReport();
            } else if (e.target.id === 'new-metadata-analysis-btn') {
                this.resetAnalysis();
            } else if (e.target.id === 'copy-metadata-btn') {
                this.copyMetadataToClipboard();
            }
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
        const previewContainer = document.getElementById('exif-image-preview');
        const previewImg = document.getElementById('exif-preview-img');

        const reader = new FileReader();
        reader.onload = (e) => {
            previewImg.src = e.target.result;
            previewContainer.style.display = 'block';
        };
        reader.readAsDataURL(file);
    }

    updateImageInfo(file) {
        const infoContainer = document.getElementById('exif-image-info');
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

    async startMetadataExtraction() {
        if (!this.currentImageFile) {
            this.showAlert('Please select an image file first.', 'warning');
            return;
        }

        this.showAnalysisProgress(true);
        this.updateAnalysisProgress(0, 'Uploading image...', 'Preparing for metadata extraction...');

        try {
            // Create form data
            const formData = new FormData();
            formData.append('image', this.currentImageFile);

            // Determine endpoint based on extraction type
            let endpoint = '/api/exif/extract-metadata';

            switch (this.currentExtractionType) {
                case 'summary':
                    endpoint = '/api/exif/metadata-summary';
                    break;
                case 'gps':
                    endpoint = '/api/exif/extract-gps';
                    break;
                case 'camera':
                    endpoint = '/api/exif/camera-info';
                    break;
                default:
                    endpoint = '/api/exif/extract-metadata';
            }

            this.updateAnalysisProgress(30, 'Extracting metadata...', 'Processing EXIF data...');

            // Start extraction
            const response = await fetch(endpoint, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error(`Extraction failed: ${response.statusText}`);
            }

            const result = await response.json();

            if (result.success) {
                this.extractionResults = result;

                this.updateAnalysisProgress(100, 'Extraction complete!', 'Processing results...');

                setTimeout(() => {
                    this.showAnalysisProgress(false);
                    this.displayExtractionResults();
                    this.showResultsSection();
                }, 1000);
            } else {
                throw new Error(result.error || 'Extraction failed');
            }

        } catch (error) {
            console.error('Extraction error:', error);
            this.showAnalysisProgress(false);
            this.showAlert(`Extraction failed: ${error.message}`, 'danger');
        }
    }

    showAnalysisProgress(show) {
        const progressContainer = document.getElementById('exif-analysis-progress');
        const submitButton = document.getElementById('start-exif-extraction');

        progressContainer.style.display = show ? 'block' : 'none';
        submitButton.disabled = show;
    }

    updateAnalysisProgress(percentage, statusText, detailText) {
        const progressBar = document.getElementById('exif-progress-bar');
        const statusElement = document.getElementById('exif-status-text');
        const detailElement = document.getElementById('exif-detail-text');

        progressBar.style.width = `${percentage}%`;
        progressBar.textContent = `${percentage}%`;
        statusElement.textContent = statusText;
        detailElement.textContent = detailText;

        // Simulate progress updates for better UX
        if (percentage < 100 && percentage > 0) {
            setTimeout(() => {
                if (percentage < 90) {
                    this.updateAnalysisProgress(
                        Math.min(percentage + 15, 90),
                        'Extracting metadata...',
                        this.getRandomExtractionStep()
                    );
                }
            }, 800);
        }
    }

    getRandomExtractionStep() {
        const steps = [
            'Reading EXIF headers...',
            'Processing camera information...',
            'Extracting GPS coordinates...',
            'Analyzing timestamps...',
            'Reading technical metadata...',
            'Processing lens information...',
            'Extracting software data...',
            'Performing forensic analysis...'
        ];
        return steps[Math.floor(Math.random() * steps.length)];
    }

    displayExtractionResults() {
        if (!this.extractionResults) return;

        // Display results based on extraction type
        switch (this.currentExtractionType) {
            case 'summary':
                this.displaySummaryResults();
                break;
            case 'gps':
                this.displayGPSResults();
                break;
            case 'camera':
                this.displayCameraResults();
                break;
            default:
                this.displayComprehensiveResults();
        }
    }

    displaySummaryResults() {
        const container = document.getElementById('metadata-summary-content');
        const summary = this.extractionResults.summary || {};

        let html = `
            <div class="row">
                <div class="col-12">
                    <h5><i class="bi bi-speedometer2 text-primary"></i> Quick Metadata Summary</h5>
                    <div class="card">
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-6">
                                    <table class="table table-borderless">
                                        <tr>
                                            <td><strong><i class="bi bi-camera"></i> Camera:</strong></td>
                                            <td>${summary.camera || 'Unknown'}</td>
                                        </tr>
                                        <tr>
                                            <td><strong><i class="bi bi-calendar"></i> Date Taken:</strong></td>
                                            <td>${summary.date_taken || 'Unknown'}</td>
                                        </tr>
                                        <tr>
                                            <td><strong><i class="bi bi-geo-alt"></i> Location:</strong></td>
                                            <td>${summary.location || 'No GPS data'}</td>
                                        </tr>
                                    </table>
                                </div>
                                <div class="col-md-6">
                                    <table class="table table-borderless">
                                        <tr>
                                            <td><strong><i class="bi bi-gear"></i> Software:</strong></td>
                                            <td>${summary.software || 'Unknown'}</td>
                                        </tr>
                                        <tr>
                                            <td><strong><i class="bi bi-aspect-ratio"></i> Dimensions:</strong></td>
                                            <td>${summary.dimensions || 'Unknown'}</td>
                                        </tr>
                                        <tr>
                                            <td><strong><i class="bi bi-file-earmark"></i> File Size:</strong></td>
                                            <td>${summary.file_size || 'Unknown'}</td>
                                        </tr>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;

        container.innerHTML = html;
    }

    displayGPSResults() {
        const container = document.getElementById('location-info-content');
        const gpsData = this.extractionResults.gps_data || {};
        const locationSummary = this.extractionResults.location_summary || {};

        let html = `
            <div class="row">
                <div class="col-12">
                    <h5><i class="bi bi-geo-alt text-success"></i> GPS Location Analysis</h5>
        `;

        if (locationSummary.coordinates) {
            html += `
                    <div class="card border-success mb-3">
                        <div class="card-header bg-success text-white">
                            <h6 class="mb-0"><i class="bi bi-geo-alt"></i> Location Found</h6>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-6">
                                    <p><strong>Coordinates:</strong> ${locationSummary.coordinates}</p>
                                    <p><strong>Forensic Value:</strong> 
                                        <span class="badge bg-success">${locationSummary.forensic_value.toUpperCase()}</span>
                                    </p>
                                    ${locationSummary.has_altitude ? '<p><i class="bi bi-check-circle text-success"></i> Altitude data available</p>' : ''}
                                    ${locationSummary.has_timestamp ? '<p><i class="bi bi-check-circle text-success"></i> GPS timestamp available</p>' : ''}
                                </div>
                                <div class="col-md-6">
                                    ${locationSummary.google_maps_link ?
                    `<a href="${locationSummary.google_maps_link}" target="_blank" class="btn btn-primary">
                                            <i class="bi bi-map"></i> View on Google Maps
                                        </a>` : ''}
                                </div>
                            </div>
                        </div>
                    </div>
            `;

            if (Object.keys(gpsData).length > 0) {
                html += `
                    <div class="card">
                        <div class="card-header">
                            <h6><i class="bi bi-list"></i> Detailed GPS Data</h6>
                        </div>
                        <div class="card-body">
                            <table class="table table-sm">
                `;

                Object.entries(gpsData).forEach(([key, value]) => {
                    if (key !== 'google_maps_link') {
                        html += `<tr><td><strong>${key}:</strong></td><td>${value}</td></tr>`;
                    }
                });

                html += `
                            </table>
                        </div>
                    </div>
                `;
            }
        } else {
            html += `
                    <div class="alert alert-warning">
                        <i class="bi bi-exclamation-triangle"></i>
                        <strong>No GPS Data Found</strong><br>
                        ${locationSummary.note || 'This image does not contain GPS location information.'}
                    </div>
            `;
        }

        html += `
                </div>
            </div>
        `;

        container.innerHTML = html;

        // Switch to location tab
        const locationTab = document.getElementById('location-tab');
        const tab = new bootstrap.Tab(locationTab);
        tab.show();
    }

    displayCameraResults() {
        const container = document.getElementById('camera-info-content');
        const cameraData = this.extractionResults.camera_data || {};

        let html = `
            <div class="row">
                <div class="col-md-6">
                    <div class="card border-primary mb-3">
                        <div class="card-header bg-primary text-white">
                            <h6 class="mb-0"><i class="bi bi-camera"></i> Camera Identification</h6>
                        </div>
                        <div class="card-body">
                            <table class="table table-sm">
        `;

        const cameraId = cameraData.camera_identification || {};
        Object.entries(cameraId).forEach(([key, value]) => {
            if (value) {
                const displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                html += `<tr><td><strong>${displayKey}:</strong></td><td>${value}</td></tr>`;
            }
        });

        html += `
                            </table>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card border-success mb-3">
                        <div class="card-header bg-success text-white">
                            <h6 class="mb-0"><i class="bi bi-sliders"></i> Capture Settings</h6>
                        </div>
                        <div class="card-body">
                            <table class="table table-sm">
        `;

        const captureSettings = cameraData.capture_settings || {};
        Object.entries(captureSettings).forEach(([key, value]) => {
            if (value) {
                const displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                html += `<tr><td><strong>${displayKey}:</strong></td><td>${value}</td></tr>`;
            }
        });

        html += `
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Forensic Assessment
        const forensicAssessment = cameraData.forensic_assessment || {};
        if (Object.keys(forensicAssessment).length > 0) {
            html += `
                <div class="row">
                    <div class="col-12">
                        <div class="card border-warning">
                            <div class="card-header bg-warning text-dark">
                                <h6 class="mb-0"><i class="bi bi-shield-check"></i> Forensic Assessment</h6>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-4">
                                        <div class="text-center">
                                            <div class="forensic-indicator ${forensicAssessment.camera_identified ? 'success' : 'warning'}">
                                                ${forensicAssessment.camera_identified ? 'IDENTIFIED' : 'UNKNOWN'}
                                            </div>
                                            <small class="text-muted">Camera Identification</small>
                                        </div>
                                    </div>
                                    <div class="col-md-4">
                                        <div class="text-center">
                                            <div class="forensic-indicator ${forensicAssessment.professional_equipment ? 'info' : 'secondary'}">
                                                ${forensicAssessment.professional_equipment ? 'PROFESSIONAL' : 'CONSUMER'}
                                            </div>
                                            <small class="text-muted">Equipment Type</small>
                                        </div>
                                    </div>
                                    <div class="col-md-4">
                                        <div class="text-center">
                                            <div class="forensic-indicator ${this.getCompletenessColor(forensicAssessment.metadata_completeness)}">
                                                ${forensicAssessment.metadata_completeness?.toUpperCase() || 'UNKNOWN'}
                                            </div>
                                            <small class="text-muted">Metadata Completeness</small>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }

        container.innerHTML = html;

        // Switch to camera tab
        const cameraTab = document.getElementById('camera-tab');
        const tab = new bootstrap.Tab(cameraTab);
        tab.show();
    }

    displayComprehensiveResults() {
        const metadata = this.extractionResults.metadata || {};

        // Display summary
        this.displayMetadataSummary(this.extractionResults.summary || {});

        // Display camera info
        this.displayCameraInfo(metadata.camera_info || {}, metadata.capture_settings || {});

        // Display location info
        this.displayLocationInfo(metadata.gps_data || {});

        // Display technical info
        this.displayTechnicalInfo(metadata.technical_info || {}, metadata.file_info || {});

        // Display forensic analysis
        this.displayForensicAnalysis(metadata.forensic_notes || []);
    }

    displayMetadataSummary(summary) {
        const container = document.getElementById('metadata-summary-content');

        let html = `
            <div class="row">
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-6">
                                    <h6><i class="bi bi-info-circle text-primary"></i> Basic Information</h6>
                                    <table class="table table-sm table-borderless">
                                        <tr><td><strong>Camera:</strong></td><td>${summary.camera || 'Unknown'}</td></tr>
                                        <tr><td><strong>Date Taken:</strong></td><td>${summary.date_taken || 'Unknown'}</td></tr>
                                        <tr><td><strong>Dimensions:</strong></td><td>${summary.dimensions || 'Unknown'}</td></tr>
                                    </table>
                                </div>
                                <div class="col-md-6">
                                    <h6><i class="bi bi-geo-alt text-success"></i> Additional Details</h6>
                                    <table class="table table-sm table-borderless">
                                        <tr><td><strong>Location:</strong></td><td>${summary.location || 'No GPS data'}</td></tr>
                                        <tr><td><strong>Software:</strong></td><td>${summary.software || 'Unknown'}</td></tr>
                                        <tr><td><strong>File Size:</strong></td><td>${summary.file_size || 'Unknown'}</td></tr>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card border-info">
                        <div class="card-header bg-info text-white">
                            <h6 class="mb-0">Extraction Stats</h6>
                        </div>
                        <div class="card-body text-center">
                            <div class="forensic-metric-value">${this.extractionResults.metadata_count || 0}</div>
                            <small class="text-muted">Total Metadata Fields</small>
                            <hr>
                            <small class="text-muted">
                                Extracted: ${new Date(this.extractionResults.extraction_timestamp).toLocaleString()}
                            </small>
                        </div>
                    </div>
                </div>
            </div>
        `;

        container.innerHTML = html;
    }

    displayCameraInfo(cameraInfo, captureSettings) {
        const container = document.getElementById('camera-info-content');

        let html = `
            <div class="row">
                <div class="col-md-6">
                    <div class="card border-primary">
                        <div class="card-header bg-primary text-white">
                            <h6 class="mb-0"><i class="bi bi-camera"></i> Camera Details</h6>
                        </div>
                        <div class="card-body">
                            <table class="table table-sm">
        `;

        Object.entries(cameraInfo).forEach(([key, value]) => {
            if (value) {
                const displayKey = key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
                html += `<tr><td><strong>${displayKey}:</strong></td><td>${value}</td></tr>`;
            }
        });

        html += `
                            </table>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card border-success">
                        <div class="card-header bg-success text-white">
                            <h6 class="mb-0"><i class="bi bi-sliders"></i> Capture Settings</h6>
                        </div>
                        <div class="card-body">
                            <table class="table table-sm">
        `;

        Object.entries(captureSettings).forEach(([key, value]) => {
            if (value) {
                const displayKey = key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
                html += `<tr><td><strong>${displayKey}:</strong></td><td>${value}</td></tr>`;
            }
        });

        html += `
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        `;

        container.innerHTML = html;
    }

    displayLocationInfo(gpsData) {
        const container = document.getElementById('location-info-content');

        if (Object.keys(gpsData).length === 0) {
            container.innerHTML = `
                <div class="alert alert-warning">
                    <i class="bi bi-exclamation-triangle"></i>
                    <strong>No GPS Data Available</strong><br>
                    This image does not contain GPS location information.
                </div>
            `;
            return;
        }

        let html = `<div class="card">
            <div class="card-header">
                <h6><i class="bi bi-geo-alt"></i> GPS Location Data</h6>
            </div>
            <div class="card-body">
        `;

        if (gpsData.coordinates_string) {
            html += `
                <div class="row mb-3">
                    <div class="col-md-6">
                        <h6>Coordinates</h6>
                        <p class="lead">${gpsData.coordinates_string}</p>
                        ${gpsData.google_maps_link ?
                    `<a href="${gpsData.google_maps_link}" target="_blank" class="btn btn-primary">
                                <i class="bi bi-map"></i> View on Google Maps
                            </a>` : ''}
                    </div>
                    <div class="col-md-6">
                        <table class="table table-sm">
                            <tr><td><strong>Latitude:</strong></td><td>${gpsData.decimal_latitude || 'N/A'}</td></tr>
                            <tr><td><strong>Longitude:</strong></td><td>${gpsData.decimal_longitude || 'N/A'}</td></tr>
                        </table>
                    </div>
                </div>
            `;
        }

        html += `<table class="table table-sm">`;
        Object.entries(gpsData).forEach(([key, value]) => {
            if (key !== 'google_maps_link' && key !== 'coordinates_string' && key !== 'decimal_latitude' && key !== 'decimal_longitude') {
                html += `<tr><td><strong>${key}:</strong></td><td>${value}</td></tr>`;
            }
        });
        html += `</table></div></div>`;

        container.innerHTML = html;
    }

    displayTechnicalInfo(technicalInfo, fileInfo) {
        const container = document.getElementById('technical-info-content');

        let html = `
            <div class="row">
                <div class="col-md-6">
                    <div class="card border-info">
                        <div class="card-header bg-info text-white">
                            <h6 class="mb-0"><i class="bi bi-gear"></i> Technical Metadata</h6>
                        </div>
                        <div class="card-body">
                            <table class="table table-sm">
        `;

        Object.entries(technicalInfo).forEach(([key, value]) => {
            if (value) {
                const displayKey = key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
                html += `<tr><td><strong>${displayKey}:</strong></td><td>${value}</td></tr>`;
            }
        });

        html += `
                            </table>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card border-secondary">
                        <div class="card-header bg-secondary text-white">
                            <h6 class="mb-0"><i class="bi bi-file-earmark"></i> File Information</h6>
                        </div>
                        <div class="card-body">
                            <table class="table table-sm">
        `;

        Object.entries(fileInfo).forEach(([key, value]) => {
            if (value) {
                const displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                html += `<tr><td><strong>${displayKey}:</strong></td><td>${value}</td></tr>`;
            }
        });

        html += `
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        `;

        container.innerHTML = html;
    }

    displayForensicAnalysis(forensicNotes) {
        const container = document.getElementById('forensic-analysis-content');

        let html = `
            <div class="card border-warning">
                <div class="card-header bg-warning text-dark">
                    <h6 class="mb-0"><i class="bi bi-shield-check"></i> Forensic Analysis Notes</h6>
                </div>
                <div class="card-body">
        `;

        if (forensicNotes.length > 0) {
            html += `<ul class="list-group list-group-flush">`;
            forensicNotes.forEach(note => {
                const alertType = note.includes('⚠️') ? 'warning' : note.includes('ℹ️') ? 'info' : 'success';
                html += `<li class="list-group-item border-0"><span class="badge bg-${alertType} me-2">${alertType.toUpperCase()}</span>${note}</li>`;
            });
            html += `</ul>`;
        } else {
            html += `<p class="text-muted">No specific forensic notes available for this image.</p>`;
        }

        html += `
                </div>
            </div>
        `;

        container.innerHTML = html;
    }

    showResultsSection() {
        const resultsSection = document.getElementById('exif-results-section');
        resultsSection.style.display = 'block';

        // Scroll to results
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    async exportMetadataReport() {
        if (!this.extractionResults) {
            this.showAlert('No metadata to export.', 'warning');
            return;
        }

        try {
            // Create downloadable JSON report
            const reportData = {
                export_timestamp: new Date().toISOString(),
                filename: this.currentImageFile.name,
                extraction_type: this.currentExtractionType,
                results: this.extractionResults
            };

            const blob = new Blob([JSON.stringify(reportData, null, 2)], {
                type: 'application/json'
            });

            // Create download link
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `exif_metadata_${this.currentImageFile.name}_${new Date().toISOString().split('T')[0]}.json`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);

            this.showAlert('Metadata report exported successfully!', 'success');

        } catch (error) {
            console.error('Export error:', error);
            this.showAlert('Failed to export metadata report.', 'danger');
        }
    }

    async copyMetadataToClipboard() {
        if (!this.extractionResults) {
            this.showAlert('No metadata to copy.', 'warning');
            return;
        }

        try {
            const textData = JSON.stringify(this.extractionResults, null, 2);
            await navigator.clipboard.writeText(textData);
            this.showAlert('Metadata copied to clipboard!', 'success');
        } catch (error) {
            console.error('Copy error:', error);
            this.showAlert('Failed to copy metadata to clipboard.', 'danger');
        }
    }

    resetAnalysis() {
        this.currentImageFile = null;
        this.extractionResults = null;

        // Reset form
        document.getElementById('exif-upload-form').reset();
        document.getElementById('exif-image-preview').style.display = 'none';
        document.getElementById('exif-results-section').style.display = 'none';

        // Reset extraction type
        document.getElementById('full-extraction').checked = true;
        this.currentExtractionType = 'full';

        this.showAlert('Analysis reset successfully.', 'info');
    }

    // Utility methods
    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    getCompletenessColor(level) {
        switch (level) {
            case 'high': return 'success';
            case 'medium': return 'warning';
            case 'low': return 'danger';
            default: return 'secondary';
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

// Initialize the EXIF extractor when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.exifExtractor = new EXIFMetadataExtractor();
});