/**
 * Error Level Analysis (ELA) JavaScript Module
 * ============================================
 * 
 * Handles ELA image tampering detection interface including:
 * - File upload and validation
 * - Multiple analysis types (single, multi-quality, quick scan, batch)
 * - Results visualization and interpretation
 * - Progress tracking and error handling
 */

class ELAAnalyzer {
    constructor() {
        this.apiBaseUrl = 'http://localhost:5000/api/ela';
        this.maxFileSize = 10 * 1024 * 1024; // 10MB
        this.allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/bmp', 'image/tiff', 'image/gif'];

        this.initializeElements();
        this.setupEventListeners();
    }

    initializeElements() {
        // Get DOM elements
        this.uploadArea = document.getElementById('ela-upload-area');
        this.fileInput = document.getElementById('ela-file-input');
        this.batchFileInput = document.getElementById('ela-batch-file-input');
        this.analysisType = document.getElementById('ela-analysis-type');
        this.qualitySlider = document.getElementById('ela-quality-slider');
        this.qualityValue = document.getElementById('ela-quality-value');
        this.qualityLevels = document.getElementById('ela-quality-levels');
        this.analyzeBtn = document.getElementById('ela-analyze-btn');
        this.progressContainer = document.getElementById('ela-progress-container');
        this.progressBar = document.getElementById('ela-progress-bar');
        this.progressText = document.getElementById('ela-progress-text');
        this.resultsContainer = document.getElementById('ela-results-container');
        this.resultsContent = document.getElementById('ela-results-content');

        // Initialize quality slider value display
        if (this.qualityValue && this.qualitySlider) {
            this.qualityValue.textContent = this.qualitySlider.value;
        }
    }

    setupEventListeners() {
        // File upload area drag and drop
        if (this.uploadArea) {
            this.uploadArea.addEventListener('dragover', (e) => this.handleDragOver(e));
            this.uploadArea.addEventListener('dragleave', (e) => this.handleDragLeave(e));
            this.uploadArea.addEventListener('drop', (e) => this.handleDrop(e));
            this.uploadArea.addEventListener('click', () => this.triggerFileInput());
        }

        // File input change
        if (this.fileInput) {
            this.fileInput.addEventListener('change', (e) => this.handleFileSelect(e));
        }

        if (this.batchFileInput) {
            this.batchFileInput.addEventListener('change', (e) => this.handleBatchFileSelect(e));
        }

        // Analysis type change
        if (this.analysisType) {
            this.analysisType.addEventListener('change', (e) => this.handleAnalysisTypeChange(e));
        }

        // Quality slider
        if (this.qualitySlider) {
            this.qualitySlider.addEventListener('input', (e) => this.updateQualityValue(e));
        }

        // Analyze button
        if (this.analyzeBtn) {
            this.analyzeBtn.addEventListener('click', () => this.startAnalysis());
        }
    }

    handleDragOver(e) {
        e.preventDefault();
        this.uploadArea.classList.add('drag-over');
    }

    handleDragLeave(e) {
        e.preventDefault();
        this.uploadArea.classList.remove('drag-over');
    }

    handleDrop(e) {
        e.preventDefault();
        this.uploadArea.classList.remove('drag-over');

        const files = Array.from(e.dataTransfer.files);
        if (this.analysisType.value === 'batch') {
            this.handleFiles(files, true);
        } else {
            this.handleFiles([files[0]], false);
        }
    }

    triggerFileInput() {
        if (this.analysisType.value === 'batch') {
            this.batchFileInput.click();
        } else {
            this.fileInput.click();
        }
    }

    handleFileSelect(e) {
        const files = Array.from(e.target.files);
        this.handleFiles(files, false);
    }

    handleBatchFileSelect(e) {
        const files = Array.from(e.target.files);
        this.handleFiles(files, true);
    }

    handleAnalysisTypeChange(e) {
        const type = e.target.value;

        // Show/hide relevant controls
        const qualityControls = document.getElementById('ela-quality-controls');
        const multiQualityControls = document.getElementById('ela-multi-quality-controls');

        if (qualityControls) {
            qualityControls.style.display = (type === 'single' || type === 'batch' || type === 'regions') ? 'block' : 'none';
        }

        if (multiQualityControls) {
            multiQualityControls.style.display = (type === 'multi-quality') ? 'block' : 'none';
        }

        // Update upload area text
        this.updateUploadAreaText(type);

        // Clear previous results
        this.clearResults();
    }

    updateUploadAreaText(type) {
        const uploadText = document.querySelector('#ela-upload-area .upload-text');
        if (uploadText) {
            switch (type) {
                case 'batch':
                    uploadText.textContent = 'Drop multiple images here or click to select files for batch analysis';
                    break;
                case 'multi-quality':
                    uploadText.textContent = 'Drop image here or click to select file for multi-quality analysis';
                    break;
                case 'quick':
                    uploadText.textContent = 'Drop image here or click to select file for quick tampering scan';
                    break;
                case 'regions':
                    uploadText.textContent = 'Drop image here or click to select file for region-focused analysis';
                    break;
                default:
                    uploadText.textContent = 'Drop image here or click to select file for ELA analysis';
            }
        }
    }

    updateQualityValue(e) {
        if (this.qualityValue) {
            this.qualityValue.textContent = e.target.value;
        }
    }

    handleFiles(files, isBatch) {
        if (!files || files.length === 0) {
            this.showError('No files selected');
            return;
        }

        // Validate files
        const validFiles = [];
        const errors = [];

        for (const file of files) {
            if (!this.allowedTypes.includes(file.type)) {
                errors.push(`${file.name}: Invalid file type`);
                continue;
            }

            if (file.size > this.maxFileSize) {
                errors.push(`${file.name}: File too large (max 10MB)`);
                continue;
            }

            validFiles.push(file);
        }

        if (errors.length > 0) {
            this.showError(errors.join('\n'));
        }

        if (validFiles.length === 0) {
            return;
        }

        // Store files for analysis
        this.selectedFiles = validFiles;

        // Update UI
        this.updateFileInfo(validFiles, isBatch);
        this.analyzeBtn.disabled = false;
    }

    updateFileInfo(files, isBatch) {
        const fileInfo = document.getElementById('ela-file-info');
        if (fileInfo) {
            if (isBatch) {
                fileInfo.innerHTML = `
                    <div class="alert alert-info">
                        <strong>${files.length} files selected for batch analysis</strong>
                        <ul class="mb-0 mt-2">
                            ${files.slice(0, 5).map(f => `<li>${f.name} (${this.formatFileSize(f.size)})</li>`).join('')}
                            ${files.length > 5 ? `<li><em>... and ${files.length - 5} more files</em></li>` : ''}
                        </ul>
                    </div>
                `;
            } else {
                const file = files[0];
                fileInfo.innerHTML = `
                    <div class="alert alert-info">
                        <strong>File selected:</strong> ${file.name}<br>
                        <strong>Size:</strong> ${this.formatFileSize(file.size)}<br>
                        <strong>Type:</strong> ${file.type}
                    </div>
                `;
            }
        }
    }

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async startAnalysis() {
        if (!this.selectedFiles || this.selectedFiles.length === 0) {
            this.showError('Please select files for analysis');
            return;
        }

        const analysisType = this.analysisType.value;

        try {
            this.showProgress('Initializing analysis...');
            this.analyzeBtn.disabled = true;

            let results;
            switch (analysisType) {
                case 'single':
                    results = await this.performSingleAnalysis();
                    break;
                case 'multi-quality':
                    results = await this.performMultiQualityAnalysis();
                    break;
                case 'quick':
                    results = await this.performQuickScan();
                    break;
                case 'batch':
                    results = await this.performBatchAnalysis();
                    break;
                case 'regions':
                    results = await this.performRegionAnalysis();
                    break;
                default:
                    throw new Error('Unknown analysis type');
            }

            this.displayResults(results, analysisType);

        } catch (error) {
            console.error('Analysis error:', error);
            this.showError(`Analysis failed: ${error.message}`);
        } finally {
            this.hideProgress();
            this.analyzeBtn.disabled = false;
        }
    }

    async performSingleAnalysis() {
        const formData = new FormData();
        formData.append('image', this.selectedFiles[0]);
        formData.append('quality', this.qualitySlider.value);

        this.updateProgress('Performing ELA analysis...', 50);

        const response = await fetch(`${this.apiBaseUrl}/analyze`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`Analysis failed: ${response.statusText}`);
        }

        const result = await response.json();

        // Log the analysis activity if forensics logger is available
        if (window.forensicsLogger) {
            window.forensicsLogger.logFileAnalysis(
                this.selectedFiles[0].name,
                'ela_analysis',
                {
                    tampering_detected: result.tampering_detected,
                    confidence_score: result.confidence_score,
                    quality: this.qualitySlider.value
                }
            );
        }

        return result;
    }

    async performMultiQualityAnalysis() {
        const formData = new FormData();
        formData.append('image', this.selectedFiles[0]);

        const qualityLevelsInput = this.qualityLevels.value.trim();
        if (qualityLevelsInput) {
            formData.append('quality_levels', qualityLevelsInput);
        }

        this.updateProgress('Performing multi-quality ELA analysis...', 30);

        const response = await fetch(`${this.apiBaseUrl}/multi-quality-analyze`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`Multi-quality analysis failed: ${response.statusText}`);
        }

        return await response.json();
    }

    async performQuickScan() {
        const formData = new FormData();
        formData.append('image', this.selectedFiles[0]);

        this.updateProgress('Performing quick tampering scan...', 60);

        const response = await fetch(`${this.apiBaseUrl}/quick-scan`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`Quick scan failed: ${response.statusText}`);
        }

        return await response.json();
    }

    async performBatchAnalysis() {
        const formData = new FormData();

        for (let i = 0; i < this.selectedFiles.length; i++) {
            formData.append('images', this.selectedFiles[i]);
        }
        formData.append('quality', this.qualitySlider.value);

        this.updateProgress(`Analyzing ${this.selectedFiles.length} files...`, 20);

        const response = await fetch(`${this.apiBaseUrl}/batch-analyze`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`Batch analysis failed: ${response.statusText}`);
        }

        return await response.json();
    }

    async performRegionAnalysis() {
        const formData = new FormData();
        formData.append('image', this.selectedFiles[0]);
        formData.append('quality', this.qualitySlider.value);

        this.updateProgress('Performing region-focused ELA analysis...', 50);

        const response = await fetch(`${this.apiBaseUrl}/analyze-regions`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`Region analysis failed: ${response.statusText}`);
        }

        return await response.json();
    }

    displayResults(results, analysisType) {
        if (results.error) {
            this.showError(results.error);
            return;
        }

        this.resultsContainer.style.display = 'block';

        // Update dashboard statistics based on analysis type
        this.updateDashboardStatistics(results, analysisType);

        switch (analysisType) {
            case 'single':
            case 'regions':
                this.displaySingleAnalysisResults(results);
                break;
            case 'multi-quality':
                this.displayMultiQualityResults(results);
                break;
            case 'quick':
                this.displayQuickScanResults(results);
                break;
            case 'batch':
                this.displayBatchResults(results);
                break;
        }

        // Scroll to results
        this.resultsContainer.scrollIntoView({ behavior: 'smooth' });
    }

    displaySingleAnalysisResults(results) {
        const tamperingProb = results.tampering_assessment.probability;
        const riskLevel = results.tampering_assessment.risk_level;
        const suspiciousRegions = results.suspicious_regions.length;

        let riskClass = 'success';
        if (riskLevel === 'medium') riskClass = 'warning';
        if (riskLevel === 'high') riskClass = 'danger';

        this.resultsContent.innerHTML = `
            <div class="row">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-chart-line"></i> Tampering Assessment</h5>
                        </div>
                        <div class="card-body">
                            <div class="alert alert-${riskClass}">
                                <h6><strong>Risk Level: ${riskLevel.toUpperCase()}</strong></h6>
                                <p class="mb-1">Tampering Probability: <strong>${(tamperingProb * 100).toFixed(1)}%</strong></p>
                                <p class="mb-0">Confidence: <strong>${results.tampering_assessment.confidence}</strong></p>
                            </div>
                            
                            <div class="mb-3">
                                <label>Tampering Probability</label>
                                <div class="progress">
                                    <div class="progress-bar bg-${riskClass}" style="width: ${tamperingProb * 100}%"></div>
                                </div>
                                <small class="text-muted">${(tamperingProb * 100).toFixed(1)}%</small>
                            </div>

                            <p><strong>Suspicious Regions:</strong> ${suspiciousRegions}</p>
                            <p><strong>Overall Assessment:</strong> ${results.analysis_results.overall_assessment.authenticity_assessment}</p>
                        </div>
                    </div>
                </div>

                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-chart-bar"></i> ELA Statistics</h5>
                        </div>
                        <div class="card-body">
                            <table class="table table-sm">
                                <tr>
                                    <td>Mean Error Level</td>
                                    <td>${results.ela_statistics.mean_error.toFixed(2)}</td>
                                </tr>
                                <tr>
                                    <td>Max Error Level</td>
                                    <td>${results.ela_statistics.max_error.toFixed(2)}</td>
                                </tr>
                                <tr>
                                    <td>Significant Pixels</td>
                                    <td>${results.ela_statistics.significant_pixels.toLocaleString()}</td>
                                </tr>
                                <tr>
                                    <td>High Error Pixels</td>
                                    <td>${results.ela_statistics.high_error_pixels.toLocaleString()}</td>
                                </tr>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row mt-3">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-image"></i> ELA Visualization</h5>
                        </div>
                        <div class="card-body text-center">
                            ${results.visualizations.ela_image_base64 ?
                `<img src="data:image/png;base64,${results.visualizations.ela_image_base64}" 
                                     class="img-fluid" alt="ELA Visualization" style="max-height: 300px;">` :
                '<p class="text-muted">Visualization not available</p>'
            }
                        </div>
                    </div>
                </div>

                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-fire"></i> Error Heatmap</h5>
                        </div>
                        <div class="card-body text-center">
                            ${results.visualizations.heatmap_base64 ?
                `<img src="data:image/png;base64,${results.visualizations.heatmap_base64}" 
                                     class="img-fluid" alt="Error Heatmap" style="max-height: 300px;">` :
                '<p class="text-muted">Heatmap not available</p>'
            }
                        </div>
                    </div>
                </div>
            </div>

            <div class="row mt-3">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-clipboard-list"></i> Forensic Analysis Notes</h5>
                        </div>
                        <div class="card-body">
                            <ul class="list-unstyled">
                                ${results.forensic_notes.map(note => `<li class="mb-2">${note}</li>`).join('')}
                            </ul>
                        </div>
                    </div>
                </div>
            </div>

            ${suspiciousRegions > 0 ? this.displaySuspiciousRegions(results.suspicious_regions) : ''}

            <div class="row mt-3">
                <div class="col-12">
                    <button class="btn btn-outline-primary me-2" onclick="elaAnalyzer.exportResults(${JSON.stringify(results).replace(/"/g, '&quot;')})">
                        <i class="fas fa-download"></i> Export Results
                    </button>
                    <button class="btn btn-outline-secondary" onclick="elaAnalyzer.clearResults()">
                        <i class="fas fa-trash"></i> Clear Results
                    </button>
                </div>
            </div>
        `;
    }

    displaySuspiciousRegions(regions) {
        return `
            <div class="row mt-3">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-exclamation-triangle"></i> Suspicious Regions (${regions.length})</h5>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-sm table-striped">
                                    <thead>
                                        <tr>
                                            <th>Region</th>
                                            <th>Location</th>
                                            <th>Size</th>
                                            <th>Suspicion Level</th>
                                            <th>Avg Error</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${regions.map((region, index) => `
                                            <tr>
                                                <td>#${index + 1}</td>
                                                <td>(${region.bounding_box.x}, ${region.bounding_box.y})</td>
                                                <td>${region.bounding_box.width} × ${region.bounding_box.height}</td>
                                                <td>
                                                    <span class="badge bg-${region.suspicion_level === 'high' ? 'danger' :
                region.suspicion_level === 'medium' ? 'warning' : 'info'}">
                                                        ${region.suspicion_level}
                                                    </span>
                                                </td>
                                                <td>${region.avg_error_level.toFixed(2)}</td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    displayMultiQualityResults(results) {
        const overallAssessment = results.overall_assessment;
        const qualityResults = results.results_by_quality;

        let assessmentClass = 'success';
        if (overallAssessment.final_assessment.includes('possibly')) assessmentClass = 'warning';
        if (overallAssessment.final_assessment.includes('likely_manipulated')) assessmentClass = 'danger';

        this.resultsContent.innerHTML = `
            <div class="row">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-chart-line"></i> Multi-Quality Assessment</h5>
                        </div>
                        <div class="card-body">
                            <div class="alert alert-${assessmentClass}">
                                <h6><strong>Final Assessment:</strong></h6>
                                <p class="mb-1">${overallAssessment.final_assessment.replace(/_/g, ' ').toUpperCase()}</p>
                                <p class="mb-1"><strong>Confidence:</strong> ${overallAssessment.confidence_level}</p>
                                <p class="mb-0"><strong>Avg Probability:</strong> ${(overallAssessment.average_tampering_probability * 100).toFixed(1)}%</p>
                            </div>
                            
                            <div class="mb-3">
                                <label>Average Tampering Probability</label>
                                <div class="progress">
                                    <div class="progress-bar bg-${assessmentClass}" 
                                         style="width: ${overallAssessment.average_tampering_probability * 100}%"></div>
                                </div>
                            </div>

                            <p><strong>Qualities Tested:</strong> ${results.quality_levels_tested.join(', ')}</p>
                            <p><strong>Most Suspicious Quality:</strong> ${overallAssessment.recommended_quality_for_analysis}</p>
                        </div>
                    </div>
                </div>

                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-chart-bar"></i> Quality Comparison</h5>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-sm">
                                    <thead>
                                        <tr>
                                            <th>Quality</th>
                                            <th>Tampering %</th>
                                            <th>Risk Level</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${Object.entries(qualityResults).map(([quality, result]) => `
                                            <tr>
                                                <td>${quality}</td>
                                                <td>${(result.tampering_assessment.probability * 100).toFixed(1)}%</td>
                                                <td>
                                                    <span class="badge bg-${result.tampering_assessment.risk_level === 'high' ? 'danger' :
                result.tampering_assessment.risk_level === 'medium' ? 'warning' : 'success'}">
                                                        ${result.tampering_assessment.risk_level}
                                                    </span>
                                                </td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row mt-3">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-info-circle"></i> Comparative Analysis</h5>
                        </div>
                        <div class="card-body">
                            <p><strong>Consistency Across Qualities:</strong> 
                               <span class="badge bg-${results.comparative_analysis.consistency_across_qualities === 'high' ? 'success' :
                results.comparative_analysis.consistency_across_qualities === 'medium' ? 'warning' : 'danger'}">
                                   ${results.comparative_analysis.consistency_across_qualities}
                               </span>
                            </p>
                            <p><strong>Probability Variance:</strong> ${results.comparative_analysis.probability_variance.toFixed(4)}</p>
                            <p><strong>Most Suspicious Quality:</strong> ${results.comparative_analysis.most_suspicious_quality}</p>
                            <p><strong>Least Suspicious Quality:</strong> ${results.comparative_analysis.least_suspicious_quality}</p>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row mt-3">
                <div class="col-12">
                    <button class="btn btn-outline-primary me-2" onclick="elaAnalyzer.exportResults(${JSON.stringify(results).replace(/"/g, '&quot;')})">
                        <i class="fas fa-download"></i> Export Results
                    </button>
                    <button class="btn btn-outline-secondary" onclick="elaAnalyzer.clearResults()">
                        <i class="fas fa-trash"></i> Clear Results
                    </button>
                </div>
            </div>
        `;
    }

    displayQuickScanResults(results) {
        const tamperingProb = results.tampering_assessment.probability;
        const riskLevel = results.tampering_assessment.risk_level;

        let riskClass = 'success';
        if (riskLevel === 'medium') riskClass = 'warning';
        if (riskLevel === 'high') riskClass = 'danger';

        this.resultsContent.innerHTML = `
            <div class="row">
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-tachometer-alt"></i> Quick Tampering Scan Results</h5>
                        </div>
                        <div class="card-body">
                            <div class="alert alert-${riskClass}">
                                <h4><i class="fas fa-${riskLevel === 'high' ? 'exclamation-triangle' :
                riskLevel === 'medium' ? 'exclamation-circle' : 'check-circle'}"></i> 
                                    Risk Level: ${riskLevel.toUpperCase()}</h4>
                                <p class="mb-1">Tampering Probability: <strong>${(tamperingProb * 100).toFixed(1)}%</strong></p>
                                <p class="mb-0">Assessment: <strong>${results.overall_assessment.authenticity_assessment.replace(/_/g, ' ')}</strong></p>
                            </div>
                            
                            <div class="mb-3">
                                <div class="progress" style="height: 25px;">
                                    <div class="progress-bar bg-${riskClass}" style="width: ${tamperingProb * 100}%">
                                        ${(tamperingProb * 100).toFixed(1)}%
                                    </div>
                                </div>
                            </div>

                            <div class="row">
                                <div class="col-6">
                                    <p><strong>Suspicious Regions:</strong> ${results.suspicious_regions_count}</p>
                                    <p><strong>Confidence:</strong> ${results.tampering_assessment.confidence}</p>
                                </div>
                                <div class="col-6">
                                    <p><strong>Overall Score:</strong> ${results.overall_assessment.authenticity_score.toFixed(3)}</p>
                                    <p><strong>Recommendation:</strong> ${results.recommendation}</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-clipboard-list"></i> Key Findings</h5>
                        </div>
                        <div class="card-body">
                            <ul class="list-unstyled">
                                ${results.primary_concerns.map(concern => `<li class="mb-2"><i class="fas fa-arrow-right text-primary"></i> ${concern}</li>`).join('')}
                            </ul>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row mt-3">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-notes-medical"></i> Forensic Summary</h5>
                        </div>
                        <div class="card-body">
                            <ul class="list-unstyled">
                                ${results.forensic_summary.map(note => `<li class="mb-2">${note}</li>`).join('')}
                            </ul>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row mt-3">
                <div class="col-12">
                    <button class="btn btn-outline-primary me-2" onclick="elaAnalyzer.exportResults(${JSON.stringify(results).replace(/"/g, '&quot;')})">
                        <i class="fas fa-download"></i> Export Results
                    </button>
                    <button class="btn btn-outline-secondary" onclick="elaAnalyzer.clearResults()">
                        <i class="fas fa-trash"></i> Clear Results
                    </button>
                </div>
            </div>
        `;
    }

    displayBatchResults(results) {
        const summary = results.summary;
        const totalFiles = results.total_files;

        this.resultsContent.innerHTML = `
            <div class="row">
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-chart-pie"></i> Batch Summary</h5>
                        </div>
                        <div class="card-body">
                            <h4 class="text-center">${totalFiles} Files Analyzed</h4>
                            <div class="row text-center">
                                <div class="col-6">
                                    <h5 class="text-success">${summary.processed}</h5>
                                    <small>Processed</small>
                                </div>
                                <div class="col-6">
                                    <h5 class="text-danger">${summary.failed}</h5>
                                    <small>Failed</small>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-md-8">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-chart-bar"></i> Analysis Distribution</h5>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-4 text-center">
                                    <h4 class="text-success">${summary.likely_authentic}</h4>
                                    <small>Likely Authentic</small>
                                    <div class="progress mt-2">
                                        <div class="progress-bar bg-success" 
                                             style="width: ${(summary.likely_authentic / summary.processed * 100) || 0}%"></div>
                                    </div>
                                </div>
                                <div class="col-4 text-center">
                                    <h4 class="text-warning">${summary.possibly_manipulated}</h4>
                                    <small>Possibly Manipulated</small>
                                    <div class="progress mt-2">
                                        <div class="progress-bar bg-warning" 
                                             style="width: ${(summary.possibly_manipulated / summary.processed * 100) || 0}%"></div>
                                    </div>
                                </div>
                                <div class="col-4 text-center">
                                    <h4 class="text-danger">${summary.likely_manipulated}</h4>
                                    <small>Likely Manipulated</small>
                                    <div class="progress mt-2">
                                        <div class="progress-bar bg-danger" 
                                             style="width: ${(summary.likely_manipulated / summary.processed * 100) || 0}%"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row mt-3">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-list"></i> Detailed Results</h5>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-striped">
                                    <thead>
                                        <tr>
                                            <th>File</th>
                                            <th>Status</th>
                                            <th>Tampering Probability</th>
                                            <th>Risk Level</th>
                                            <th>Suspicious Regions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${Object.entries(results.results).map(([fileKey, result]) => `
                                            <tr>
                                                <td>${result.filename}</td>
                                                <td>
                                                    ${result.error ?
                `<span class="badge bg-danger">Error</span>` :
                `<span class="badge bg-success">Analyzed</span>`
            }
                                                </td>
                                                <td>
                                                    ${result.error ?
                'N/A' :
                `${(result.tampering_assessment.probability * 100).toFixed(1)}%`
            }
                                                </td>
                                                <td>
                                                    ${result.error ?
                result.error :
                `<span class="badge bg-${result.tampering_assessment.risk_level === 'high' ? 'danger' :
                    result.tampering_assessment.risk_level === 'medium' ? 'warning' : 'success'}">
                                                            ${result.tampering_assessment.risk_level}
                                                        </span>`
            }
                                                </td>
                                                <td>
                                                    ${result.error ? 'N/A' : result.suspicious_regions_count}
                                                </td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row mt-3">
                <div class="col-12">
                    <button class="btn btn-outline-primary me-2" onclick="elaAnalyzer.exportResults(${JSON.stringify(results).replace(/"/g, '&quot;')})">
                        <i class="fas fa-download"></i> Export Results
                    </button>
                    <button class="btn btn-outline-secondary" onclick="elaAnalyzer.clearResults()">
                        <i class="fas fa-trash"></i> Clear Results
                    </button>
                </div>
            </div>
        `;
    }

    showProgress(message) {
        if (this.progressContainer) {
            this.progressContainer.style.display = 'block';
            this.updateProgress(message, 0);
        }
    }

    updateProgress(message, percentage) {
        if (this.progressText) {
            this.progressText.textContent = message;
        }
        if (this.progressBar) {
            this.progressBar.style.width = `${percentage}%`;
            this.progressBar.setAttribute('aria-valuenow', percentage);
        }
    }

    hideProgress() {
        if (this.progressContainer) {
            this.progressContainer.style.display = 'none';
        }
    }

    showError(message) {
        const errorAlert = document.createElement('div');
        errorAlert.className = 'alert alert-danger alert-dismissible fade show mt-3';
        errorAlert.innerHTML = `
            <i class="fas fa-exclamation-circle"></i> <strong>Error:</strong> ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        // Insert before results container
        if (this.resultsContainer) {
            this.resultsContainer.parentNode.insertBefore(errorAlert, this.resultsContainer);
        } else {
            document.querySelector('#ela-container').appendChild(errorAlert);
        }

        // Auto-remove after 10 seconds
        setTimeout(() => {
            if (errorAlert.parentNode) {
                errorAlert.remove();
            }
        }, 10000);
    }

    exportResults(results) {
        const dataStr = JSON.stringify(results, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });

        const link = document.createElement('a');
        link.href = URL.createObjectURL(dataBlob);
        link.download = `ela_analysis_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;

        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }

    updateDashboardStatistics(results, analysisType) {
        // Update dashboard statistics when ELA analysis is performed
        try {
            let filesAnalyzed = 0;
            let integrityChecks = 1; // Each analysis is one integrity check

            // Count files based on analysis type
            if (analysisType === 'batch' && results.batch_results) {
                filesAnalyzed = Object.keys(results.batch_results).length;
            } else if (results.filename || results.original_filename) {
                filesAnalyzed = 1;
            }

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

            console.log('ELA Dashboard statistics updated:', { filesAnalyzed, integrityChecks, newTotals: newStats });
        } catch (error) {
            console.error('Error updating ELA dashboard statistics:', error);
        }
    }

    clearResults() {
        if (this.resultsContainer) {
            this.resultsContainer.style.display = 'none';
        }
        if (this.resultsContent) {
            this.resultsContent.innerHTML = '';
        }

        // Clear file selections
        this.selectedFiles = null;
        if (this.fileInput) this.fileInput.value = '';
        if (this.batchFileInput) this.batchFileInput.value = '';

        // Clear file info
        const fileInfo = document.getElementById('ela-file-info');
        if (fileInfo) {
            fileInfo.innerHTML = '';
        }

        // Disable analyze button
        if (this.analyzeBtn) {
            this.analyzeBtn.disabled = true;
        }

        // Remove any error alerts
        const alerts = document.querySelectorAll('.alert-danger');
        alerts.forEach(alert => alert.remove());
    }
}

// Initialize ELA analyzer when page loads
document.addEventListener('DOMContentLoaded', function () {
    if (document.getElementById('ela-container')) {
        window.elaAnalyzer = new ELAAnalyzer();
    }
});