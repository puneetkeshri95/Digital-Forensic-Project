/**
 * Clone and Noise Detection JavaScript Module
 * ===========================================
 * 
 * Handles advanced tampering detection interface including:
 * - Copy-move detection
 * - Block matching analysis
 * - Noise consistency analysis
 * - Statistical anomaly detection
 * - Batch processing and visualization
 */

class CloneNoiseDetector {
    constructor() {
        this.apiBaseUrl = 'http://localhost:5000/api/clone-noise';
        this.maxFileSize = 10 * 1024 * 1024; // 10MB
        this.allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/bmp', 'image/tiff', 'image/gif'];

        this.initializeElements();
        this.setupEventListeners();
    }

    initializeElements() {
        // Get DOM elements
        this.uploadArea = document.getElementById('clone-noise-upload-area');
        this.fileInput = document.getElementById('clone-noise-file-input');
        this.batchFileInput = document.getElementById('clone-noise-batch-file-input');
        this.analysisType = document.getElementById('clone-noise-analysis-type');
        this.detectionMethods = document.getElementById('clone-noise-methods');
        this.analyzeBtn = document.getElementById('clone-noise-analyze-btn');
        this.progressContainer = document.getElementById('clone-noise-progress-container');
        this.progressBar = document.getElementById('clone-noise-progress-bar');
        this.progressText = document.getElementById('clone-noise-progress-text');
        this.resultsContainer = document.getElementById('clone-noise-results-container');
        this.resultsContent = document.getElementById('clone-noise-results-content');
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

        // Analyze button
        if (this.analyzeBtn) {
            this.analyzeBtn.addEventListener('click', () => this.startAnalysis());
        }

        // Method checkboxes
        const methodCheckboxes = document.querySelectorAll('input[name="detection-method"]');
        methodCheckboxes.forEach(checkbox => {
            checkbox.addEventListener('change', () => this.updateMethodSelection());
        });
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

        // Show/hide method selection for comprehensive analysis
        const methodsContainer = document.getElementById('clone-noise-methods-container');
        if (methodsContainer) {
            methodsContainer.style.display = (type === 'comprehensive') ? 'block' : 'none';
        }

        // Update upload area text
        this.updateUploadAreaText(type);

        // Clear previous results
        this.clearResults();
    }

    updateUploadAreaText(type) {
        const uploadText = document.querySelector('#clone-noise-upload-area .upload-text');
        if (uploadText) {
            switch (type) {
                case 'batch':
                    uploadText.textContent = 'Drop multiple images here or click to select files for batch analysis';
                    break;
                case 'copy-move':
                    uploadText.textContent = 'Drop image here or click to select file for copy-move detection';
                    break;
                case 'noise':
                    uploadText.textContent = 'Drop image here or click to select file for noise analysis';
                    break;
                case 'block-matching':
                    uploadText.textContent = 'Drop image here or click to select file for block matching analysis';
                    break;
                case 'statistical':
                    uploadText.textContent = 'Drop image here or click to select file for statistical analysis';
                    break;
                default:
                    uploadText.textContent = 'Drop image here or click to select file for comprehensive tampering analysis';
            }
        }
    }

    updateMethodSelection() {
        const checkboxes = document.querySelectorAll('input[name="detection-method"]:checked');
        const methodsSelected = checkboxes.length > 0;

        // Update analyze button state if needed
        if (this.analysisType.value === 'comprehensive') {
            // Could add validation here if needed
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
        const fileInfo = document.getElementById('clone-noise-file-info');
        if (fileInfo) {
            if (isBatch) {
                fileInfo.innerHTML = `
                    <div class="alert alert-info">
                        <strong>${files.length} files selected for batch tampering analysis</strong>
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
            this.showProgress('Initializing tampering analysis...');
            this.analyzeBtn.disabled = true;

            let results;
            switch (analysisType) {
                case 'comprehensive':
                    results = await this.performComprehensiveAnalysis();
                    break;
                case 'copy-move':
                    results = await this.performCopyMoveAnalysis();
                    break;
                case 'noise':
                    results = await this.performNoiseAnalysis();
                    break;
                case 'block-matching':
                    results = await this.performBlockMatchingAnalysis();
                    break;
                case 'statistical':
                    results = await this.performStatisticalAnalysis();
                    break;
                case 'batch':
                    results = await this.performBatchAnalysis();
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

    async performComprehensiveAnalysis() {
        const formData = new FormData();
        formData.append('image', this.selectedFiles[0]);

        // Get selected methods
        const selectedMethods = [];
        const checkboxes = document.querySelectorAll('input[name="detection-method"]:checked');
        checkboxes.forEach(cb => selectedMethods.push(cb.value));

        if (selectedMethods.length > 0) {
            formData.append('methods', selectedMethods.join(','));
        }

        this.updateProgress('Performing comprehensive tampering analysis...', 30);

        const response = await fetch(`${this.apiBaseUrl}/analyze`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`Comprehensive analysis failed: ${response.statusText}`);
        }

        return await response.json();
    }

    async performCopyMoveAnalysis() {
        const formData = new FormData();
        formData.append('image', this.selectedFiles[0]);

        this.updateProgress('Detecting copy-move patterns...', 50);

        const response = await fetch(`${this.apiBaseUrl}/copy-move`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`Copy-move analysis failed: ${response.statusText}`);
        }

        return await response.json();
    }

    async performNoiseAnalysis() {
        const formData = new FormData();
        formData.append('image', this.selectedFiles[0]);

        this.updateProgress('Analyzing noise consistency...', 50);

        const response = await fetch(`${this.apiBaseUrl}/noise-analysis`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`Noise analysis failed: ${response.statusText}`);
        }

        return await response.json();
    }

    async performBlockMatchingAnalysis() {
        const formData = new FormData();
        formData.append('image', this.selectedFiles[0]);

        this.updateProgress('Analyzing block similarities...', 50);

        const response = await fetch(`${this.apiBaseUrl}/block-matching`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`Block matching analysis failed: ${response.statusText}`);
        }

        return await response.json();
    }

    async performStatisticalAnalysis() {
        const formData = new FormData();
        formData.append('image', this.selectedFiles[0]);

        this.updateProgress('Performing statistical analysis...', 50);

        const response = await fetch(`${this.apiBaseUrl}/statistical`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`Statistical analysis failed: ${response.statusText}`);
        }

        return await response.json();
    }

    async performBatchAnalysis() {
        const formData = new FormData();

        for (let i = 0; i < this.selectedFiles.length; i++) {
            formData.append('images', this.selectedFiles[i]);
        }

        // Get selected methods if comprehensive
        const selectedMethods = [];
        const checkboxes = document.querySelectorAll('input[name="detection-method"]:checked');
        checkboxes.forEach(cb => selectedMethods.push(cb.value));

        if (selectedMethods.length > 0) {
            formData.append('methods', selectedMethods.join(','));
        }

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

    displayResults(results, analysisType) {
        if (results.error) {
            this.showError(results.error);
            return;
        }

        this.resultsContainer.style.display = 'block';

        switch (analysisType) {
            case 'comprehensive':
                this.displayComprehensiveResults(results);
                break;
            case 'copy-move':
                this.displayCopyMoveResults(results);
                break;
            case 'noise':
                this.displayNoiseResults(results);
                break;
            case 'block-matching':
                this.displayBlockMatchingResults(results);
                break;
            case 'statistical':
                this.displayStatisticalResults(results);
                break;
            case 'batch':
                this.displayBatchResults(results);
                break;
        }

        // Scroll to results
        this.resultsContainer.scrollIntoView({ behavior: 'smooth' });
    }

    displayComprehensiveResults(results) {
        const overallAssessment = results.overall_assessment;
        const tamperingProb = overallAssessment.tampering_probability;
        const riskLevel = overallAssessment.risk_level;
        const totalRegions = overallAssessment.total_suspicious_regions;

        let riskClass = 'success';
        if (riskLevel === 'medium') riskClass = 'warning';
        if (riskLevel === 'high') riskClass = 'danger';

        this.resultsContent.innerHTML = `
            <div class="row">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-shield-alt"></i> Overall Tampering Assessment</h5>
                        </div>
                        <div class="card-body">
                            <div class="alert alert-${riskClass}">
                                <h6><strong>Risk Level: ${riskLevel.toUpperCase()}</strong></h6>
                                <p class="mb-1">Tampering Probability: <strong>${(tamperingProb * 100).toFixed(1)}%</strong></p>
                                <p class="mb-0">Confidence: <strong>${overallAssessment.confidence_level}</strong></p>
                            </div>
                            
                            <div class="mb-3">
                                <label>Tampering Probability</label>
                                <div class="progress">
                                    <div class="progress-bar bg-${riskClass}" style="width: ${tamperingProb * 100}%"></div>
                                </div>
                                <small class="text-muted">${(tamperingProb * 100).toFixed(1)}%</small>
                            </div>

                            <p><strong>Suspicious Regions:</strong> ${totalRegions}</p>
                            <p><strong>Methods Agreement:</strong> ${(overallAssessment.methods_agreement * 100).toFixed(0)}%</p>
                        </div>
                    </div>
                </div>

                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-exclamation-triangle"></i> Primary Concerns</h5>
                        </div>
                        <div class="card-body">
                            <ul class="list-unstyled">
                                ${overallAssessment.primary_concerns.map(concern =>
            `<li class="mb-2"><i class="fas fa-arrow-right text-primary"></i> ${concern}</li>`
        ).join('')}
                            </ul>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row mt-3">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-search"></i> Detection Methods Results</h5>
                        </div>
                        <div class="card-body">
                            <div class="table-responsive">
                                <table class="table table-striped">
                                    <thead>
                                        <tr>
                                            <th>Method</th>
                                            <th>Regions Found</th>
                                            <th>Status</th>
                                            <th>Details</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${this.generateMethodResultsTable(results.detection_results)}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            ${this.generateVisualizationsSection(results.visualizations)}
            ${totalRegions > 0 ? this.generateSuspiciousRegionsSection(results.suspicious_regions) : ''}

            <div class="row mt-3">
                <div class="col-12">
                    <button class="btn btn-outline-primary me-2" onclick="cloneNoiseDetector.exportResults(${JSON.stringify(results).replace(/"/g, '&quot;')})">
                        <i class="fas fa-download"></i> Export Results
                    </button>
                    <button class="btn btn-outline-secondary" onclick="cloneNoiseDetector.clearResults()">
                        <i class="fas fa-trash"></i> Clear Results
                    </button>
                </div>
            </div>
        `;
    }

    generateMethodResultsTable(detectionResults) {
        const methodNames = {
            'copy_move': 'Copy-Move Detection',
            'block_matching': 'Block Matching',
            'noise_analysis': 'Noise Analysis',
            'statistical_analysis': 'Statistical Analysis'
        };

        let tableRows = '';
        for (const [method, results] of Object.entries(detectionResults)) {
            const regionCount = results.regions ? results.regions.length : 0;
            const status = results.error ? 'Error' : regionCount > 0 ? 'Suspicious' : 'Clean';
            const statusClass = results.error ? 'danger' : regionCount > 0 ? 'warning' : 'success';

            let details = '';
            if (results.error) {
                details = results.error;
            } else if (method === 'copy_move' && results.feature_points) {
                details = `${results.feature_points} features, ${results.matches_found} matches`;
            } else if (method === 'block_matching' && results.blocks_analyzed) {
                details = `${results.blocks_analyzed} blocks analyzed, ${results.similar_blocks_found} similar`;
            } else if (method === 'noise_analysis' && results.inconsistent_regions !== undefined) {
                details = `${results.inconsistent_regions} inconsistent regions`;
            } else if (method === 'statistical_analysis' && results.anomalies_detected !== undefined) {
                details = `${results.anomalies_detected} anomalies detected`;
            }

            tableRows += `
                <tr>
                    <td>${methodNames[method] || method}</td>
                    <td>${regionCount}</td>
                    <td><span class="badge bg-${statusClass}">${status}</span></td>
                    <td>${details}</td>
                </tr>
            `;
        }

        return tableRows;
    }

    generateVisualizationsSection(visualizations) {
        if (!visualizations || (!visualizations.annotated_image && !visualizations.heatmap)) {
            return '';
        }

        return `
            <div class="row mt-3">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-image"></i> Visual Analysis</h5>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                ${visualizations.annotated_image ? `
                                    <div class="col-md-6 text-center">
                                        <h6>Annotated Image</h6>
                                        <img src="data:image/png;base64,${visualizations.annotated_image}" 
                                             class="img-fluid" alt="Annotated Image" style="max-height: 400px;">
                                    </div>
                                ` : ''}
                                ${visualizations.heatmap ? `
                                    <div class="col-md-6 text-center">
                                        <h6>Suspicious Regions Heatmap</h6>
                                        <img src="data:image/png;base64,${visualizations.heatmap}" 
                                             class="img-fluid" alt="Heatmap" style="max-height: 400px;">
                                    </div>
                                ` : ''}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    generateSuspiciousRegionsSection(regions) {
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
                                            <th>Detection Type</th>
                                            <th>Location</th>
                                            <th>Size</th>
                                            <th>Confidence</th>
                                            <th>Similarity</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${regions.map((region, index) => `
                                            <tr>
                                                <td>#${index + 1}</td>
                                                <td>
                                                    <span class="badge bg-info">${region.detection_type.replace('_', ' ')}</span>
                                                </td>
                                                <td>(${region.x}, ${region.y})</td>
                                                <td>${region.width} × ${region.height}</td>
                                                <td>
                                                    <span class="badge bg-${region.confidence > 0.7 ? 'danger' :
                region.confidence > 0.4 ? 'warning' : 'success'}">
                                                        ${(region.confidence * 100).toFixed(0)}%
                                                    </span>
                                                </td>
                                                <td>${region.similarity_score.toFixed(3)}</td>
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

    displayCopyMoveResults(results) {
        const assessment = results.overall_assessment;
        const copyMoveData = results.copy_move_detection;

        this.resultsContent.innerHTML = `
            <div class="row">
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-copy"></i> Copy-Move Detection Results</h5>
                        </div>
                        <div class="card-body">
                            <div class="alert alert-${assessment.regions_found > 0 ? 'warning' : 'success'}">
                                <h6><strong>${assessment.assessment}</strong></h6>
                                <p class="mb-1">Regions Found: <strong>${assessment.regions_found}</strong></p>
                                <p class="mb-0">Max Confidence: <strong>${(assessment.max_confidence * 100).toFixed(1)}%</strong></p>
                            </div>
                            
                            ${copyMoveData.feature_points ? `
                                <div class="row">
                                    <div class="col-6">
                                        <p><strong>Feature Points:</strong> ${copyMoveData.feature_points}</p>
                                        <p><strong>Feature Detector:</strong> ${copyMoveData.feature_detector_used || 'SIFT'}</p>
                                    </div>
                                    <div class="col-6">
                                        <p><strong>Matches Found:</strong> ${copyMoveData.matches_found}</p>
                                        <p><strong>Avg Confidence:</strong> ${copyMoveData.confidence_scores ?
                    (copyMoveData.confidence_scores.reduce((a, b) => a + b, 0) / copyMoveData.confidence_scores.length * 100).toFixed(1) + '%' : 'N/A'}</p>
                                    </div>
                                </div>
                            ` : ''}
                        </div>
                    </div>
                </div>

                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-chart-pie"></i> Detection Summary</h5>
                        </div>
                        <div class="card-body">
                            <div class="text-center">
                                <h4 class="${assessment.regions_found > 0 ? 'text-warning' : 'text-success'}">
                                    ${assessment.regions_found}
                                </h4>
                                <p>Suspicious Regions</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            ${this.generateVisualizationsSection(results.visualizations)}
            ${assessment.regions_found > 0 ? this.generateSuspiciousRegionsSection(results.suspicious_regions) : ''}

            <div class="row mt-3">
                <div class="col-12">
                    <button class="btn btn-outline-primary me-2" onclick="cloneNoiseDetector.exportResults(${JSON.stringify(results).replace(/"/g, '&quot;')})">
                        <i class="fas fa-download"></i> Export Results
                    </button>
                    <button class="btn btn-outline-secondary" onclick="cloneNoiseDetector.clearResults()">
                        <i class="fas fa-trash"></i> Clear Results
                    </button>
                </div>
            </div>
        `;
    }

    displayNoiseResults(results) {
        const assessment = results.overall_assessment;
        const noiseData = results.noise_analysis;

        this.resultsContent.innerHTML = `
            <div class="row">
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-wave-square"></i> Noise Consistency Analysis</h5>
                        </div>
                        <div class="card-body">
                            <div class="alert alert-${assessment.inconsistent_regions > 0 ? 'warning' : 'success'}">
                                <h6><strong>${assessment.assessment}</strong></h6>
                                <p class="mb-1">Inconsistent Regions: <strong>${assessment.inconsistent_regions}</strong></p>
                                <p class="mb-0">Max Noise Variance: <strong>${assessment.max_noise_variance.toFixed(4)}</strong></p>
                            </div>
                            
                            ${noiseData.noise_statistics ? `
                                <h6>Noise Statistics:</h6>
                                <div class="row">
                                    <div class="col-6">
                                        <p><strong>Global Mean:</strong> ${noiseData.noise_statistics.global_mean_variance.toFixed(4)}</p>
                                        <p><strong>Global Std:</strong> ${noiseData.noise_statistics.global_std_variance.toFixed(4)}</p>
                                        <p><strong>Min Variance:</strong> ${noiseData.noise_statistics.min_variance.toFixed(4)}</p>
                                    </div>
                                    <div class="col-6">
                                        <p><strong>Max Variance:</strong> ${noiseData.noise_statistics.max_variance.toFixed(4)}</p>
                                        <p><strong>Variance Range:</strong> ${noiseData.noise_statistics.variance_range.toFixed(4)}</p>
                                    </div>
                                </div>
                            ` : ''}
                        </div>
                    </div>
                </div>

                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-chart-pie"></i> Analysis Summary</h5>
                        </div>
                        <div class="card-body">
                            <div class="text-center">
                                <h4 class="${assessment.inconsistent_regions > 0 ? 'text-warning' : 'text-success'}">
                                    ${assessment.inconsistent_regions}
                                </h4>
                                <p>Inconsistent Regions</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            ${this.generateVisualizationsSection(results.visualizations)}
            ${assessment.inconsistent_regions > 0 ? this.generateSuspiciousRegionsSection(results.suspicious_regions) : ''}

            <div class="row mt-3">
                <div class="col-12">
                    <button class="btn btn-outline-primary me-2" onclick="cloneNoiseDetector.exportResults(${JSON.stringify(results).replace(/"/g, '&quot;')})">
                        <i class="fas fa-download"></i> Export Results
                    </button>
                    <button class="btn btn-outline-secondary" onclick="cloneNoiseDetector.clearResults()">
                        <i class="fas fa-trash"></i> Clear Results
                    </button>
                </div>
            </div>
        `;
    }

    displayBlockMatchingResults(results) {
        const assessment = results.overall_assessment;
        const blockData = results.block_matching;

        this.resultsContent.innerHTML = `
            <div class="row">
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-th"></i> Block Matching Analysis</h5>
                        </div>
                        <div class="card-body">
                            <div class="alert alert-${assessment.similar_regions > 0 ? 'warning' : 'success'}">
                                <h6><strong>${assessment.assessment}</strong></h6>
                                <p class="mb-1">Similar Regions: <strong>${assessment.similar_regions}</strong></p>
                                <p class="mb-0">Max Similarity: <strong>${(assessment.max_similarity * 100).toFixed(1)}%</strong></p>
                            </div>
                            
                            ${blockData.blocks_analyzed ? `
                                <div class="row">
                                    <div class="col-6">
                                        <p><strong>Blocks Analyzed:</strong> ${blockData.blocks_analyzed}</p>
                                        <p><strong>Similar Blocks:</strong> ${blockData.similar_blocks_found}</p>
                                    </div>
                                    <div class="col-6">
                                        <p><strong>Similarity Threshold:</strong> ${(blockData.similarity_threshold * 100).toFixed(0)}%</p>
                                    </div>
                                </div>
                            ` : ''}
                        </div>
                    </div>
                </div>

                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-chart-pie"></i> Analysis Summary</h5>
                        </div>
                        <div class="card-body">
                            <div class="text-center">
                                <h4 class="${assessment.similar_regions > 0 ? 'text-warning' : 'text-success'}">
                                    ${assessment.similar_regions}
                                </h4>
                                <p>Similar Regions</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            ${this.generateVisualizationsSection(results.visualizations)}
            ${assessment.similar_regions > 0 ? this.generateSuspiciousRegionsSection(results.suspicious_regions) : ''}

            <div class="row mt-3">
                <div class="col-12">
                    <button class="btn btn-outline-primary me-2" onclick="cloneNoiseDetector.exportResults(${JSON.stringify(results).replace(/"/g, '&quot;')})">
                        <i class="fas fa-download"></i> Export Results
                    </button>
                    <button class="btn btn-outline-secondary" onclick="cloneNoiseDetector.clearResults()">
                        <i class="fas fa-trash"></i> Clear Results
                    </button>
                </div>
            </div>
        `;
    }

    displayStatisticalResults(results) {
        const assessment = results.overall_assessment;
        const statsData = results.statistical_analysis;

        this.resultsContent.innerHTML = `
            <div class="row">
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-chart-line"></i> Statistical Analysis Results</h5>
                        </div>
                        <div class="card-body">
                            <div class="alert alert-${assessment.anomalous_regions > 0 ? 'warning' : 'success'}">
                                <h6><strong>${assessment.assessment}</strong></h6>
                                <p class="mb-1">Anomalous Regions: <strong>${assessment.anomalous_regions}</strong></p>
                                <p class="mb-0">Max Confidence: <strong>${(assessment.max_confidence * 100).toFixed(1)}%</strong></p>
                            </div>
                            
                            ${statsData.statistics ? `
                                <h6>Global Statistics:</h6>
                                <div class="row">
                                    <div class="col-6">
                                        <p><strong>Mean Average:</strong> ${statsData.statistics.mean_avg.toFixed(2)}</p>
                                        <p><strong>Std Average:</strong> ${statsData.statistics.std_avg.toFixed(2)}</p>
                                        <p><strong>Skewness Avg:</strong> ${statsData.statistics.skewness_avg.toFixed(3)}</p>
                                    </div>
                                    <div class="col-6">
                                        <p><strong>Kurtosis Avg:</strong> ${statsData.statistics.kurtosis_avg.toFixed(3)}</p>
                                        <p><strong>Entropy Avg:</strong> ${statsData.statistics.entropy_avg.toFixed(3)}</p>
                                    </div>
                                </div>
                            ` : ''}
                        </div>
                    </div>
                </div>

                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-chart-pie"></i> Analysis Summary</h5>
                        </div>
                        <div class="card-body">
                            <div class="text-center">
                                <h4 class="${assessment.anomalous_regions > 0 ? 'text-warning' : 'text-success'}">
                                    ${assessment.anomalous_regions}
                                </h4>
                                <p>Anomalous Regions</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            ${this.generateVisualizationsSection(results.visualizations)}
            ${assessment.anomalous_regions > 0 ? this.generateSuspiciousRegionsSection(results.suspicious_regions) : ''}

            <div class="row mt-3">
                <div class="col-12">
                    <button class="btn btn-outline-primary me-2" onclick="cloneNoiseDetector.exportResults(${JSON.stringify(results).replace(/"/g, '&quot;')})">
                        <i class="fas fa-download"></i> Export Results
                    </button>
                    <button class="btn btn-outline-secondary" onclick="cloneNoiseDetector.clearResults()">
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
                            <h5><i class="fas fa-chart-bar"></i> Risk Distribution</h5>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-3 text-center">
                                    <h4 class="text-success">${summary.clean_images}</h4>
                                    <small>Clean Images</small>
                                    <div class="progress mt-2">
                                        <div class="progress-bar bg-success" 
                                             style="width: ${(summary.clean_images / summary.processed * 100) || 0}%"></div>
                                    </div>
                                </div>
                                <div class="col-3 text-center">
                                    <h4 class="text-info">${summary.low_risk}</h4>
                                    <small>Low Risk</small>
                                    <div class="progress mt-2">
                                        <div class="progress-bar bg-info" 
                                             style="width: ${(summary.low_risk / summary.processed * 100) || 0}%"></div>
                                    </div>
                                </div>
                                <div class="col-3 text-center">
                                    <h4 class="text-warning">${summary.medium_risk}</h4>
                                    <small>Medium Risk</small>
                                    <div class="progress mt-2">
                                        <div class="progress-bar bg-warning" 
                                             style="width: ${(summary.medium_risk / summary.processed * 100) || 0}%"></div>
                                    </div>
                                </div>
                                <div class="col-3 text-center">
                                    <h4 class="text-danger">${summary.high_risk}</h4>
                                    <small>High Risk</small>
                                    <div class="progress mt-2">
                                        <div class="progress-bar bg-danger" 
                                             style="width: ${(summary.high_risk / summary.processed * 100) || 0}%"></div>
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
                                            <th>Primary Concerns</th>
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
                `${(result.tampering_probability * 100).toFixed(1)}%`
            }
                                                </td>
                                                <td>
                                                    ${result.error ?
                result.error :
                `<span class="badge bg-${result.risk_level === 'high' ? 'danger' :
                    result.risk_level === 'medium' ? 'warning' : 'success'}">
                                                            ${result.risk_level}
                                                        </span>`
            }
                                                </td>
                                                <td>
                                                    ${result.error ? 'N/A' : result.suspicious_regions_count}
                                                </td>
                                                <td>
                                                    ${result.error ? 'N/A' :
                result.primary_concerns ? result.primary_concerns.slice(0, 2).join(', ') : 'None'
            }
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
                    <button class="btn btn-outline-primary me-2" onclick="cloneNoiseDetector.exportResults(${JSON.stringify(results).replace(/"/g, '&quot;')})">
                        <i class="fas fa-download"></i> Export Results
                    </button>
                    <button class="btn btn-outline-secondary" onclick="cloneNoiseDetector.clearResults()">
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
            document.querySelector('#clone-noise-container').appendChild(errorAlert);
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
        link.download = `clone_noise_analysis_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;

        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
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
        const fileInfo = document.getElementById('clone-noise-file-info');
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

// Initialize clone/noise detector when page loads
document.addEventListener('DOMContentLoaded', function () {
    if (document.getElementById('clone-noise-container')) {
        window.cloneNoiseDetector = new CloneNoiseDetector();
    }
});