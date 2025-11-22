/**
 * Hex Viewer & Byte-Level Inspector JavaScript Module
 * ==================================================
 * 
 * Advanced binary file analysis interface providing:
 * - Interactive hex dump display with ASCII representation
 * - File signature detection and validation
 * - Byte pattern searching capabilities
 * - Binary file comparison tools
 * - Entropy analysis and anomaly detection
 * - String extraction and analysis
 * - Hash calculation and verification
 */

class HexViewer {
    constructor() {
        this.apiBaseUrl = 'http://localhost:5000/api/hex-viewer';
        this.maxFileSize = 50 * 1024 * 1024; // 50MB
        this.currentAnalysis = null;
        this.currentSearchResults = null;

        this.initializeElements();
        this.setupEventListeners();
        this.loadSupportedFormats();
    }

    initializeElements() {
        // Get DOM elements
        this.uploadArea = document.getElementById('hex-viewer-upload-area');
        this.fileInput = document.getElementById('hex-viewer-file-input');
        this.compareFile1Input = document.getElementById('hex-compare-file1-input');
        this.compareFile2Input = document.getElementById('hex-compare-file2-input');

        this.analysisType = document.getElementById('hex-analysis-type');
        this.analyzeBtn = document.getElementById('hex-analyze-btn');
        this.compareBtn = document.getElementById('hex-compare-btn');

        this.progressContainer = document.getElementById('hex-progress-container');
        this.progressBar = document.getElementById('hex-progress-bar');
        this.progressText = document.getElementById('hex-progress-text');

        this.resultsContainer = document.getElementById('hex-results-container');
        this.resultsContent = document.getElementById('hex-results-content');

        // Search elements
        this.searchPattern = document.getElementById('hex-search-pattern');
        this.searchType = document.getElementById('hex-search-type');
        this.searchBtn = document.getElementById('hex-search-btn');
    }

    setupEventListeners() {
        // File upload drag and drop
        if (this.uploadArea) {
            this.uploadArea.addEventListener('dragover', (e) => this.handleDragOver(e));
            this.uploadArea.addEventListener('dragleave', (e) => this.handleDragLeave(e));
            this.uploadArea.addEventListener('drop', (e) => this.handleDrop(e));
            this.uploadArea.addEventListener('click', () => this.triggerFileInput());
        }

        // File input changes
        if (this.fileInput) {
            this.fileInput.addEventListener('change', (e) => this.handleFileSelect(e));
        }

        if (this.compareFile1Input) {
            this.compareFile1Input.addEventListener('change', (e) => this.handleCompareFileSelect(e, 1));
        }

        if (this.compareFile2Input) {
            this.compareFile2Input.addEventListener('change', (e) => this.handleCompareFileSelect(e, 2));
        }

        // Analysis type change
        if (this.analysisType) {
            this.analysisType.addEventListener('change', (e) => this.handleAnalysisTypeChange(e));
        }

        // Button clicks
        if (this.analyzeBtn) {
            this.analyzeBtn.addEventListener('click', () => this.startAnalysis());
        }

        if (this.compareBtn) {
            this.compareBtn.addEventListener('click', () => this.startComparison());
        }

        if (this.searchBtn) {
            this.searchBtn.addEventListener('click', () => this.startPatternSearch());
        }

        // Enter key for search
        if (this.searchPattern) {
            this.searchPattern.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.startPatternSearch();
                }
            });
        }
    }

    async loadSupportedFormats() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/supported-formats`);
            if (response.ok) {
                const data = await response.json();
                this.updateSupportedFormatsDisplay(data);
            }
        } catch (error) {
            console.warn('Could not load supported formats:', error);
        }
    }

    updateSupportedFormatsDisplay(data) {
        const formatsContainer = document.getElementById('hex-supported-formats');
        if (formatsContainer && data.categories) {
            let html = '<div class="row">';

            for (const [category, extensions] of Object.entries(data.categories)) {
                html += `
                    <div class="col-md-2">
                        <h6 class="text-capitalize">${category}</h6>
                        <small class="text-muted">${extensions.join(', ')}</small>
                    </div>
                `;
            }

            html += '</div>';
            formatsContainer.innerHTML = html;
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
        if (files.length > 0) {
            this.handleFiles([files[0]]);
        }
    }

    triggerFileInput() {
        this.fileInput.click();
    }

    handleFileSelect(e) {
        const files = Array.from(e.target.files);
        this.handleFiles(files);
    }

    handleCompareFileSelect(e, fileNumber) {
        const files = Array.from(e.target.files);
        if (files.length > 0) {
            this.updateCompareFileInfo(files[0], fileNumber);
        }
    }

    handleAnalysisTypeChange(e) {
        const type = e.target.value;

        // Show/hide relevant sections
        const analysisSection = document.getElementById('hex-analysis-section');
        const compareSection = document.getElementById('hex-compare-section');
        const searchSection = document.getElementById('hex-search-section');

        if (analysisSection) analysisSection.style.display = (type === 'analysis') ? 'block' : 'none';
        if (compareSection) compareSection.style.display = (type === 'compare') ? 'block' : 'none';
        if (searchSection) searchSection.style.display = (type === 'search') ? 'block' : 'none';

        this.clearResults();
    }

    handleFiles(files) {
        if (!files || files.length === 0) {
            this.showError('No files selected');
            return;
        }

        const file = files[0];

        // Validate file size
        if (file.size > this.maxFileSize) {
            this.showError(`File too large. Maximum size is ${this.maxFileSize / (1024 * 1024)}MB`);
            return;
        }

        if (file.size === 0) {
            this.showError('Empty file selected');
            return;
        }

        // Store file and update UI
        this.selectedFile = file;
        this.updateFileInfo(file);
        this.analyzeBtn.disabled = false;
        this.searchBtn.disabled = false;
    }

    updateFileInfo(file) {
        const fileInfo = document.getElementById('hex-file-info');
        if (fileInfo) {
            fileInfo.innerHTML = `
                <div class="alert alert-info">
                    <h6><i class="fas fa-file"></i> Selected File</h6>
                    <p class="mb-1"><strong>Name:</strong> ${file.name}</p>
                    <p class="mb-1"><strong>Size:</strong> ${this.formatFileSize(file.size)}</p>
                    <p class="mb-0"><strong>Type:</strong> ${file.type || 'Unknown'}</p>
                </div>
            `;
        }
    }

    updateCompareFileInfo(file, fileNumber) {
        const fileInfo = document.getElementById(`hex-compare-file${fileNumber}-info`);
        if (fileInfo) {
            fileInfo.innerHTML = `
                <div class="alert alert-info">
                    <p class="mb-1"><strong>File ${fileNumber}:</strong> ${file.name}</p>
                    <p class="mb-0"><strong>Size:</strong> ${this.formatFileSize(file.size)}</p>
                </div>
            `;
        }

        // Store files
        if (fileNumber === 1) {
            this.compareFile1 = file;
        } else {
            this.compareFile2 = file;
        }

        // Enable compare button if both files selected
        if (this.compareFile1 && this.compareFile2) {
            this.compareBtn.disabled = false;
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
        if (!this.selectedFile) {
            this.showError('Please select a file for analysis');
            return;
        }

        try {
            this.showProgress('Starting hex analysis...');
            this.analyzeBtn.disabled = true;

            const formData = new FormData();
            formData.append('file', this.selectedFile);

            // Add analysis parameters
            formData.append('max_bytes', '1048576'); // 1MB default
            formData.append('include_strings', 'true');
            formData.append('include_structure', 'true');
            formData.append('hex_lines', '200');

            this.updateProgress('Analyzing binary data...', 50);

            const response = await fetch(`${this.apiBaseUrl}/analyze`, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Analysis failed');
            }

            const results = await response.json();
            this.currentAnalysis = results;

            this.displayAnalysisResults(results);

        } catch (error) {
            console.error('Analysis error:', error);
            this.showError(`Analysis failed: ${error.message}`);
        } finally {
            this.hideProgress();
            this.analyzeBtn.disabled = false;
        }
    }

    async startPatternSearch() {
        if (!this.selectedFile) {
            this.showError('Please select a file for pattern search');
            return;
        }

        const pattern = this.searchPattern.value.trim();
        if (!pattern) {
            this.showError('Please enter a search pattern');
            return;
        }

        const searchType = this.searchType.value;

        try {
            this.showProgress('Searching for pattern...');
            this.searchBtn.disabled = true;

            const formData = new FormData();
            formData.append('file', this.selectedFile);
            formData.append('pattern', pattern);
            formData.append('search_type', searchType);

            this.updateProgress('Scanning file for pattern matches...', 70);

            const response = await fetch(`${this.apiBaseUrl}/search`, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Search failed');
            }

            const results = await response.json();
            this.currentSearchResults = results;

            this.displaySearchResults(results);

        } catch (error) {
            console.error('Search error:', error);
            this.showError(`Search failed: ${error.message}`);
        } finally {
            this.hideProgress();
            this.searchBtn.disabled = false;
        }
    }

    async startComparison() {
        if (!this.compareFile1 || !this.compareFile2) {
            this.showError('Please select both files for comparison');
            return;
        }

        try {
            this.showProgress('Comparing files...');
            this.compareBtn.disabled = true;

            const formData = new FormData();
            formData.append('file1', this.compareFile1);
            formData.append('file2', this.compareFile2);

            this.updateProgress('Analyzing differences...', 60);

            const response = await fetch(`${this.apiBaseUrl}/compare`, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Comparison failed');
            }

            const results = await response.json();
            this.displayComparisonResults(results);

        } catch (error) {
            console.error('Comparison error:', error);
            this.showError(`Comparison failed: ${error.message}`);
        } finally {
            this.hideProgress();
            this.compareBtn.disabled = false;
        }
    }

    displayAnalysisResults(results) {
        if (results.error) {
            this.showError(results.error);
            return;
        }

        this.resultsContainer.style.display = 'block';

        const fileInfo = results.file_info;
        const signature = results.file_signature;
        const hexDump = results.hex_dump;
        const byteAnalysis = results.byte_analysis;
        const stringAnalysis = results.string_analysis;
        const entropyAnalysis = results.entropy_analysis;
        const anomalies = results.anomalies;

        this.resultsContent.innerHTML = `
            <!-- File Overview -->
            <div class="row mb-4">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-info-circle"></i> File Information</h5>
                        </div>
                        <div class="card-body">
                            <table class="table table-sm">
                                <tr><td><strong>Name:</strong></td><td>${fileInfo.name}</td></tr>
                                <tr><td><strong>Size:</strong></td><td>${this.formatFileSize(fileInfo.size)}</td></tr>
                                <tr><td><strong>Analyzed:</strong></td><td>${this.formatFileSize(fileInfo.analyzed_bytes)}</td></tr>
                                ${fileInfo.is_truncated ? '<tr><td colspan="2"><span class="badge bg-warning">Large file - analysis truncated</span></td></tr>' : ''}
                            </table>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-fingerprint"></i> File Signature</h5>
                        </div>
                        <div class="card-body">
                            ${this.generateSignatureDisplay(signature)}
                        </div>
                    </div>
                </div>
            </div>

            <!-- Hex Dump -->
            <div class="row mb-4">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h5><i class="fas fa-code"></i> Hex Dump</h5>
                            <small class="text-muted">${hexDump.lines.length} lines shown</small>
                        </div>
                        <div class="card-body">
                            <div class="hex-dump-container">
                                ${this.generateHexDumpDisplay(hexDump)}
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Analysis Results -->
            <div class="row mb-4">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-chart-bar"></i> Byte Analysis</h5>
                        </div>
                        <div class="card-body">
                            ${this.generateByteAnalysisDisplay(byteAnalysis)}
                        </div>
                    </div>
                </div>
                
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-random"></i> Entropy Analysis</h5>
                        </div>
                        <div class="card-body">
                            ${this.generateEntropyDisplay(entropyAnalysis)}
                        </div>
                    </div>
                </div>
            </div>

            ${stringAnalysis ? this.generateStringAnalysisSection(stringAnalysis) : ''}
            ${anomalies && anomalies.length > 0 ? this.generateAnomaliesSection(anomalies) : ''}

            <!-- Hash Values -->
            <div class="row mb-4">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-lock"></i> Hash Values</h5>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-4">
                                    <label class="form-label">MD5:</label>
                                    <div class="input-group">
                                        <input type="text" class="form-control font-monospace" value="${results.hash_values.md5}" readonly>
                                        <button class="btn btn-outline-secondary" onclick="navigator.clipboard.writeText('${results.hash_values.md5}')">
                                            <i class="fas fa-copy"></i>
                                        </button>
                                    </div>
                                </div>
                                <div class="col-md-4">
                                    <label class="form-label">SHA1:</label>
                                    <div class="input-group">
                                        <input type="text" class="form-control font-monospace" value="${results.hash_values.sha1}" readonly>
                                        <button class="btn btn-outline-secondary" onclick="navigator.clipboard.writeText('${results.hash_values.sha1}')">
                                            <i class="fas fa-copy"></i>
                                        </button>
                                    </div>
                                </div>
                                <div class="col-md-4">
                                    <label class="form-label">SHA256:</label>
                                    <div class="input-group">
                                        <input type="text" class="form-control font-monospace" value="${results.hash_values.sha256}" readonly>
                                        <button class="btn btn-outline-secondary" onclick="navigator.clipboard.writeText('${results.hash_values.sha256}')">
                                            <i class="fas fa-copy"></i>
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Action Buttons -->
            <div class="row">
                <div class="col-12">
                    <button class="btn btn-outline-primary me-2" onclick="hexViewer.exportResults()">
                        <i class="fas fa-download"></i> Export Analysis
                    </button>
                    <button class="btn btn-outline-secondary" onclick="hexViewer.clearResults()">
                        <i class="fas fa-trash"></i> Clear Results
                    </button>
                </div>
            </div>
        `;

        // Scroll to results
        this.resultsContainer.scrollIntoView({ behavior: 'smooth' });
    }

    generateSignatureDisplay(signature) {
        if (!signature.detected) {
            return `
                <div class="alert alert-warning">
                    <i class="fas fa-exclamation-triangle"></i> No known file signature detected
                </div>
                <div class="font-monospace small">
                    <strong>Header:</strong> ${signature.header_hex || 'N/A'}
                </div>
            `;
        }

        let html = '';
        signature.signatures.forEach(sig => {
            html += `
                <div class="alert alert-success mb-2">
                    <strong>${sig.type}</strong> - ${sig.description}<br>
                    <small>Signature: ${sig.signature}</small>
                </div>
            `;
        });

        if (signature.embedded_signatures && signature.embedded_signatures.length > 0) {
            html += '<h6 class="mt-3">Embedded Signatures:</h6>';
            signature.embedded_signatures.forEach(sig => {
                html += `
                    <div class="alert alert-warning mb-1">
                        <small><strong>@${sig.offset}:</strong> ${sig.type} - ${sig.description}</small>
                    </div>
                `;
            });
        }

        return html;
    }

    generateHexDumpDisplay(hexDump) {
        if (!hexDump.lines || hexDump.lines.length === 0) {
            return '<div class="text-muted">No hex data available</div>';
        }

        let html = '<pre class="hex-dump font-monospace small">';

        hexDump.lines.forEach(line => {
            html += `<span class="hex-offset">${line.offset}</span>  `;
            html += `<span class="hex-bytes">${line.hex}</span>  `;
            html += `<span class="hex-ascii">${line.ascii}</span>\n`;
        });

        html += '</pre>';

        if (hexDump.is_truncated) {
            html += '<div class="alert alert-info mt-2"><small><i class="fas fa-info-circle"></i> Hex dump truncated for display</small></div>';
        }

        return html;
    }

    generateByteAnalysisDisplay(analysis) {
        if (analysis.error) {
            return `<div class="text-muted">${analysis.error}</div>`;
        }

        return `
            <div class="mb-3">
                <div class="row">
                    <div class="col-6">
                        <small><strong>Total Bytes:</strong> ${analysis.total_bytes.toLocaleString()}</small>
                    </div>
                    <div class="col-6">
                        <small><strong>Unique Bytes:</strong> ${analysis.unique_bytes}</small>
                    </div>
                </div>
                <div class="row">
                    <div class="col-6">
                        <small><strong>Null Bytes:</strong> ${analysis.null_percentage.toFixed(1)}%</small>
                    </div>
                    <div class="col-6">
                        <small><strong>Coverage:</strong> ${(analysis.byte_coverage * 100).toFixed(1)}%</small>
                    </div>
                </div>
            </div>
            
            <h6>Most Common Bytes:</h6>
            <div class="table-responsive">
                <table class="table table-sm">
                    <thead><tr><th>Byte</th><th>Count</th><th>%</th></tr></thead>
                    <tbody>
                        ${analysis.most_common_bytes.slice(0, 5).map(item =>
            `<tr><td class="font-monospace">${item.byte}</td><td>${item.count}</td><td>${item.percentage.toFixed(2)}%</td></tr>`
        ).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    generateEntropyDisplay(entropy) {
        const entropyPercentage = entropy.entropy_percentage;
        let progressClass = 'bg-success';
        if (entropyPercentage > 75) progressClass = 'bg-danger';
        else if (entropyPercentage > 50) progressClass = 'bg-warning';

        return `
            <div class="mb-3">
                <label>Overall Entropy: <strong>${entropy.overall_entropy.toFixed(3)}</strong></label>
                <div class="progress mb-2">
                    <div class="progress-bar ${progressClass}" style="width: ${entropyPercentage}%"></div>
                </div>
                <small class="text-muted">${entropy.analysis}</small>
            </div>
            
            ${entropy.chunk_entropies && entropy.chunk_entropies.length > 0 ? `
                <h6>Entropy Distribution:</h6>
                <div class="entropy-chunks">
                    ${entropy.chunk_entropies.slice(0, 10).map(chunk => `
                        <div class="d-flex justify-content-between">
                            <small>@${chunk.offset.toString(16).toUpperCase().padStart(6, '0')}</small>
                            <small>${chunk.entropy.toFixed(2)}</small>
                        </div>
                    `).join('')}
                </div>
            ` : ''}
        `;
    }

    generateStringAnalysisSection(stringAnalysis) {
        return `
            <div class="row mb-4">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-font"></i> String Analysis</h5>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-6">
                                    <h6>ASCII Strings (${stringAnalysis.total_ascii_strings}):</h6>
                                    <div class="string-list">
                                        ${stringAnalysis.ascii_strings.slice(0, 20).map(str =>
            `<div class="font-monospace small text-truncate" title="${this.escapeHtml(str)}">${this.escapeHtml(str)}</div>`
        ).join('')}
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <h6>Interesting Patterns:</h6>
                                    ${Object.entries(stringAnalysis.interesting_patterns).map(([type, items]) =>
            items.length > 0 ? `
                                            <div class="mb-2">
                                                <strong class="text-capitalize">${type}:</strong>
                                                ${items.slice(0, 3).map(item =>
                `<div class="font-monospace small text-truncate">${this.escapeHtml(item)}</div>`
            ).join('')}
                                            </div>
                                        ` : ''
        ).join('')}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    generateAnomaliesSection(anomalies) {
        return `
            <div class="row mb-4">
                <div class="col-12">
                    <div class="card border-warning">
                        <div class="card-header bg-warning text-dark">
                            <h5><i class="fas fa-exclamation-triangle"></i> Anomalies Detected (${anomalies.length})</h5>
                        </div>
                        <div class="card-body">
                            ${anomalies.map(anomaly => {
            let badgeClass = 'bg-info';
            if (anomaly.severity === 'high') badgeClass = 'bg-danger';
            else if (anomaly.severity === 'medium') badgeClass = 'bg-warning';

            return `
                                    <div class="alert alert-warning mb-2">
                                        <div class="d-flex justify-content-between align-items-start">
                                            <div>
                                                <strong>${anomaly.type.replace('_', ' ').toUpperCase()}</strong>
                                                <span class="badge ${badgeClass} ms-2">${anomaly.severity}</span>
                                            </div>
                                        </div>
                                        <p class="mb-1">${anomaly.description}</p>
                                        ${anomaly.details ? `<small class="text-muted">${JSON.stringify(anomaly.details, null, 2)}</small>` : ''}
                                    </div>
                                `;
        }).join('')}
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    displaySearchResults(results) {
        if (results.error) {
            this.showError(results.error);
            return;
        }

        this.resultsContainer.style.display = 'block';

        this.resultsContent.innerHTML = `
            <div class="card">
                <div class="card-header">
                    <h5><i class="fas fa-search"></i> Pattern Search Results</h5>
                </div>
                <div class="card-body">
                    <div class="alert alert-info">
                        <div class="row">
                            <div class="col-md-3"><strong>Pattern:</strong> ${this.escapeHtml(results.pattern)}</div>
                            <div class="col-md-3"><strong>Type:</strong> ${results.search_type.toUpperCase()}</div>
                            <div class="col-md-3"><strong>Matches:</strong> ${results.matches_found}</div>
                            <div class="col-md-3"><strong>File:</strong> ${results.search_metadata.original_filename}</div>
                        </div>
                    </div>

                    ${results.matches_found === 0 ?
                '<div class="alert alert-warning"><i class="fas fa-info-circle"></i> No matches found</div>' :
                `
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>Offset</th>
                                        <th>Context Before</th>
                                        <th>Match</th>
                                        <th>Context After</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${results.matches.map(match => `
                                        <tr>
                                            <td class="font-monospace">0x${match.offset.toString(16).toUpperCase().padStart(8, '0')}</td>
                                            <td class="font-monospace small">${match.context_before}</td>
                                            <td class="font-monospace text-primary"><strong>${match.match}</strong></td>
                                            <td class="font-monospace small">${match.context_after}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                        `
            }
                </div>
            </div>

            <div class="row mt-3">
                <div class="col-12">
                    <button class="btn btn-outline-primary me-2" onclick="hexViewer.exportSearchResults()">
                        <i class="fas fa-download"></i> Export Search Results
                    </button>
                    <button class="btn btn-outline-secondary" onclick="hexViewer.clearResults()">
                        <i class="fas fa-trash"></i> Clear Results
                    </button>
                </div>
            </div>
        `;

        this.resultsContainer.scrollIntoView({ behavior: 'smooth' });
    }

    displayComparisonResults(results) {
        if (results.error) {
            this.showError(results.error);
            return;
        }

        this.resultsContainer.style.display = 'block';

        const similarityClass = results.similarity_percentage > 95 ? 'success' :
            results.similarity_percentage > 80 ? 'warning' : 'danger';

        this.resultsContent.innerHTML = `
            <div class="row">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-balance-scale"></i> Comparison Summary</h5>
                        </div>
                        <div class="card-body">
                            <div class="text-center mb-3">
                                <h3 class="text-${similarityClass}">${results.similarity_percentage.toFixed(1)}%</h3>
                                <p>File Similarity</p>
                            </div>
                            
                            <table class="table table-sm">
                                <tr><td><strong>Files Identical:</strong></td><td>${results.files_identical ? 'Yes' : 'No'}</td></tr>
                                <tr><td><strong>File 1 Size:</strong></td><td>${this.formatFileSize(results.file1_size)}</td></tr>
                                <tr><td><strong>File 2 Size:</strong></td><td>${this.formatFileSize(results.file2_size)}</td></tr>
                                <tr><td><strong>Size Difference:</strong></td><td>${results.size_difference} bytes</td></tr>
                                <tr><td><strong>Bytes Compared:</strong></td><td>${results.bytes_compared.toLocaleString()}</td></tr>
                                <tr><td><strong>Differences Found:</strong></td><td>${results.differences_found}</td></tr>
                            </table>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h5><i class="fas fa-fingerprint"></i> Hash Comparison</h5>
                        </div>
                        <div class="card-body">
                            <div class="mb-3">
                                <strong>Hashes Match:</strong> 
                                <span class="badge bg-${results.hash_comparison.hashes_match ? 'success' : 'danger'}">
                                    ${results.hash_comparison.hashes_match ? 'Yes' : 'No'}
                                </span>
                            </div>
                            
                            <div class="mb-2">
                                <label class="form-label small">File 1 MD5:</label>
                                <input type="text" class="form-control form-control-sm font-monospace" 
                                       value="${results.hash_comparison.file1_md5}" readonly>
                            </div>
                            
                            <div class="mb-2">
                                <label class="form-label small">File 2 MD5:</label>
                                <input type="text" class="form-control form-control-sm font-monospace" 
                                       value="${results.hash_comparison.file2_md5}" readonly>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            ${results.differences_found > 0 ? `
                <div class="row mt-4">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                <h5><i class="fas fa-not-equal"></i> Byte Differences (${results.differences_found})</h5>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-sm table-striped">
                                        <thead>
                                            <tr>
                                                <th>Offset</th>
                                                <th>File 1 Byte</th>
                                                <th>File 2 Byte</th>
                                                <th>Context</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            ${results.differences.slice(0, 50).map(diff => `
                                                <tr>
                                                    <td class="font-monospace">0x${diff.offset.toString(16).toUpperCase().padStart(8, '0')}</td>
                                                    <td class="font-monospace text-danger">${diff.file1_byte}</td>
                                                    <td class="font-monospace text-success">${diff.file2_byte}</td>
                                                    <td class="font-monospace small">${diff.context.before} [${diff.file1_byte}→${diff.file2_byte}] ${diff.context.after}</td>
                                                </tr>
                                            `).join('')}
                                        </tbody>
                                    </table>
                                </div>
                                ${results.differences_found > 50 ?
                    '<div class="alert alert-info mt-2"><small>Showing first 50 differences</small></div>' :
                    ''
                }
                            </div>
                        </div>
                    </div>
                </div>
            ` : ''}

            <div class="row mt-3">
                <div class="col-12">
                    <button class="btn btn-outline-primary me-2" onclick="hexViewer.exportComparisonResults()">
                        <i class="fas fa-download"></i> Export Comparison
                    </button>
                    <button class="btn btn-outline-secondary" onclick="hexViewer.clearResults()">
                        <i class="fas fa-trash"></i> Clear Results
                    </button>
                </div>
            </div>
        `;

        this.resultsContainer.scrollIntoView({ behavior: 'smooth' });
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

        if (this.resultsContainer) {
            this.resultsContainer.parentNode.insertBefore(errorAlert, this.resultsContainer);
        } else {
            document.querySelector('#hex-viewer-container').appendChild(errorAlert);
        }

        setTimeout(() => {
            if (errorAlert.parentNode) {
                errorAlert.remove();
            }
        }, 10000);
    }

    escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }

    exportResults() {
        if (this.currentAnalysis) {
            const dataStr = JSON.stringify(this.currentAnalysis, null, 2);
            this.downloadFile(dataStr, 'hex_analysis_results.json', 'application/json');
        }
    }

    exportSearchResults() {
        if (this.currentSearchResults) {
            const dataStr = JSON.stringify(this.currentSearchResults, null, 2);
            this.downloadFile(dataStr, 'hex_search_results.json', 'application/json');
        }
    }

    exportComparisonResults() {
        // Implementation would depend on storing comparison results
        console.log('Export comparison results');
    }

    downloadFile(content, filename, contentType) {
        const blob = new Blob([content], { type: contentType });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = filename;
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

        // Reset state
        this.currentAnalysis = null;
        this.currentSearchResults = null;

        // Clear file selections
        this.selectedFile = null;
        this.compareFile1 = null;
        this.compareFile2 = null;

        if (this.fileInput) this.fileInput.value = '';
        if (this.compareFile1Input) this.compareFile1Input.value = '';
        if (this.compareFile2Input) this.compareFile2Input.value = '';

        // Clear file info displays
        const fileInfoElements = ['hex-file-info', 'hex-compare-file1-info', 'hex-compare-file2-info'];
        fileInfoElements.forEach(id => {
            const element = document.getElementById(id);
            if (element) element.innerHTML = '';
        });

        // Disable buttons
        if (this.analyzeBtn) this.analyzeBtn.disabled = true;
        if (this.compareBtn) this.compareBtn.disabled = true;
        if (this.searchBtn) this.searchBtn.disabled = true;

        // Remove error alerts
        const alerts = document.querySelectorAll('.alert-danger');
        alerts.forEach(alert => alert.remove());
    }
}

// Initialize hex viewer when page loads
document.addEventListener('DOMContentLoaded', function () {
    if (document.getElementById('hex-viewer-container')) {
        window.hexViewer = new HexViewer();
    }
});