/**
 * File Integrity Verification JavaScript Module
 * =============================================
 * 
 * Provides client-side functionality for file integrity checking
 * including hash calculation, verification, and batch processing.
 */

class IntegrityManager {
    constructor() {
        this.apiUrl = '/api/integrity';
        this.supportedAlgorithms = [];
        this.activeOperations = new Map();
        this.init();
    }

    async init() {
        // Load supported algorithms on initialization
        await this.loadSupportedAlgorithms();
        this.setupEventListeners();
        this.createIntegrityUI();
    }

    async loadSupportedAlgorithms() {
        try {
            const response = await fetch(`${this.apiUrl}/supported-algorithms`);
            const data = await response.json();

            if (data.success) {
                this.supportedAlgorithms = data.algorithms;
                console.log('Loaded supported algorithms:', this.supportedAlgorithms);
            }
        } catch (error) {
            console.error('Error loading supported algorithms:', error);
            // Fallback to common algorithms
            this.supportedAlgorithms = [
                { name: 'sha256', display_name: 'SHA-256', recommended: true },
                { name: 'md5', display_name: 'MD5', recommended: false }
            ];
        }
    }

    setupEventListeners() {
        // Listen for file drops on integrity section
        document.addEventListener('dragover', (e) => {
            if (e.target.closest('.integrity-drop-zone')) {
                e.preventDefault();
                e.target.classList.add('drag-over');
            }
        });

        document.addEventListener('dragleave', (e) => {
            if (e.target.closest('.integrity-drop-zone')) {
                e.target.classList.remove('drag-over');
            }
        });

        document.addEventListener('drop', (e) => {
            if (e.target.closest('.integrity-drop-zone')) {
                e.preventDefault();
                e.target.classList.remove('drag-over');
                const files = Array.from(e.dataTransfer.files);
                this.handleFileIntegrityCheck(files);
            }
        });
    }

    createIntegrityUI() {
        // Add integrity checking section to main interface
        const integrityHTML = `
            <div class="integrity-section mb-4">
                <h4><i class="fas fa-shield-alt"></i> File Integrity Verification</h4>
                
                <!-- Quick Hash Calculator -->
                <div class="card mb-3">
                    <div class="card-header">
                        <h6 class="mb-0">Quick Hash Calculator</h6>
                    </div>
                    <div class="card-body">
                        <div class="integrity-drop-zone border border-dashed rounded p-4 text-center mb-3" 
                             style="border-color: #007bff !important; background-color: #f8f9fa;">
                            <i class="fas fa-upload fa-2x text-muted mb-2"></i>
                            <p class="mb-2">Drop files here or click to select</p>
                            <input type="file" id="integrityFileInput" multiple accept="*/*" style="display: none;">
                            <button type="button" class="btn btn-outline-primary btn-sm" onclick="document.getElementById('integrityFileInput').click()">
                                Select Files
                            </button>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-8">
                                <label class="form-label">Hash Algorithms:</label>
                                <div id="algorithmCheckboxes" class="mb-2">
                                    <!-- Algorithm checkboxes will be inserted here -->
                                </div>
                            </div>
                            <div class="col-md-4">
                                <label class="form-label">Context:</label>
                                <select id="integrityContext" class="form-select">
                                    <option value="manual_check">Manual Check</option>
                                    <option value="pre_analysis">Pre-Analysis</option>
                                    <option value="post_analysis">Post-Analysis</option>
                                    <option value="evidence_intake">Evidence Intake</option>
                                    <option value="archive_preparation">Archive Preparation</option>
                                </select>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Integrity Results -->
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h6 class="mb-0">Integrity Check Results</h6>
                        <div>
                            <button id="clearIntegrityResults" class="btn btn-outline-secondary btn-sm">
                                <i class="fas fa-trash"></i> Clear
                            </button>
                            <button id="exportIntegrityResults" class="btn btn-outline-success btn-sm">
                                <i class="fas fa-download"></i> Export
                            </button>
                        </div>
                    </div>
                    <div class="card-body">
                        <div id="integrityResults">
                            <div class="text-muted text-center py-4">
                                <i class="fas fa-info-circle"></i>
                                No integrity checks performed yet. Upload files to calculate hash values.
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Verification Section -->
                <div class="card mt-3">
                    <div class="card-header">
                        <h6 class="mb-0">Hash Verification</h6>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <label class="form-label">Original Hash Record (JSON):</label>
                                <textarea id="originalHashRecord" class="form-control" rows="4" 
                                          placeholder="Paste integrity record JSON here..."></textarea>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label">Verification File:</label>
                                <input type="file" id="verificationFileInput" class="form-control mb-2">
                                <div class="text-center">
                                    <button id="verifyIntegrityBtn" class="btn btn-warning">
                                        <i class="fas fa-check-circle"></i> Verify Integrity
                                    </button>
                                </div>
                            </div>
                        </div>
                        <div id="verificationResults" class="mt-3"></div>
                    </div>
                </div>
            </div>
        `;

        // Insert integrity UI after the existing forensic tools
        const mainContent = document.querySelector('.container-fluid .row:first-child');
        if (mainContent) {
            const integrityDiv = document.createElement('div');
            integrityDiv.className = 'col-12';
            integrityDiv.innerHTML = integrityHTML;
            mainContent.appendChild(integrityDiv);
        }

        // Populate algorithm checkboxes
        this.populateAlgorithmCheckboxes();

        // Setup additional event listeners
        this.setupIntegrityEventListeners();
    }

    populateAlgorithmCheckboxes() {
        const container = document.getElementById('algorithmCheckboxes');
        if (!container) return;

        container.innerHTML = '';

        this.supportedAlgorithms.forEach(alg => {
            const isChecked = alg.recommended ? 'checked' : '';
            const warningBadge = !alg.recommended && alg.note ?
                `<small class="text-warning"><i class="fas fa-exclamation-triangle"></i> ${alg.note}</small>` : '';

            const checkboxHTML = `
                <div class="form-check form-check-inline">
                    <input class="form-check-input" type="checkbox" id="alg_${alg.name}" value="${alg.name}" ${isChecked}>
                    <label class="form-check-label" for="alg_${alg.name}">
                        ${alg.display_name}
                        ${warningBadge}
                    </label>
                </div>
            `;
            container.innerHTML += checkboxHTML;
        });
    }

    setupIntegrityEventListeners() {
        // File input change
        document.getElementById('integrityFileInput')?.addEventListener('change', (e) => {
            const files = Array.from(e.target.files);
            this.handleFileIntegrityCheck(files);
        });

        // Clear results
        document.getElementById('clearIntegrityResults')?.addEventListener('click', () => {
            this.clearIntegrityResults();
        });

        // Export results
        document.getElementById('exportIntegrityResults')?.addEventListener('click', () => {
            this.exportIntegrityResults();
        });

        // Verify integrity
        document.getElementById('verifyIntegrityBtn')?.addEventListener('click', () => {
            this.handleIntegrityVerification();
        });
    }

    async handleFileIntegrityCheck(files) {
        if (!files || files.length === 0) return;

        // Get selected algorithms
        const selectedAlgorithms = this.getSelectedAlgorithms();
        if (selectedAlgorithms.length === 0) {
            this.showAlert('Please select at least one hash algorithm.', 'warning');
            return;
        }

        // Get context
        const context = document.getElementById('integrityContext')?.value || 'manual_check';

        // Show loading state
        this.showIntegrityLoading(files.length);

        try {
            if (files.length === 1) {
                await this.calculateSingleFileHash(files[0], selectedAlgorithms, context);
            } else {
                await this.calculateBatchHashes(files, selectedAlgorithms, context);
            }
        } catch (error) {
            console.error('Error calculating hashes:', error);
            this.showAlert('Error calculating file hashes: ' + error.message, 'danger');
        }
    }

    async calculateSingleFileHash(file, algorithms, context) {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('algorithms', algorithms.join(','));
        formData.append('context', context);

        const operationId = this.generateOperationId();
        this.activeOperations.set(operationId, { file: file.name, type: 'single' });

        try {
            const response = await fetch(`${this.apiUrl}/calculate`, {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (result.success) {
                this.displayIntegrityResult(result, 'single');
                this.showAlert(`Hash calculation completed for ${file.name}`, 'success');
            } else {
                this.showAlert(`Error: ${result.error}`, 'danger');
            }
        } finally {
            this.activeOperations.delete(operationId);
        }
    }

    async calculateBatchHashes(files, algorithms, context) {
        const formData = new FormData();
        files.forEach(file => formData.append('files', file));
        formData.append('algorithms', algorithms.join(','));
        formData.append('context', context);

        const operationId = this.generateOperationId();
        this.activeOperations.set(operationId, { files: files.map(f => f.name), type: 'batch' });

        try {
            const response = await fetch(`${this.apiUrl}/batch-calculate`, {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (result.success) {
                this.displayBatchIntegrityResults(result);
                this.showAlert(`Batch hash calculation completed for ${files.length} files`, 'success');
            } else {
                this.showAlert(`Error: ${result.error}`, 'danger');
            }
        } finally {
            this.activeOperations.delete(operationId);
        }
    }

    async handleIntegrityVerification() {
        const originalRecordText = document.getElementById('originalHashRecord')?.value;
        const verificationFile = document.getElementById('verificationFileInput')?.files[0];

        if (!originalRecordText) {
            this.showAlert('Please provide the original hash record.', 'warning');
            return;
        }

        if (!verificationFile) {
            this.showAlert('Please select a file for verification.', 'warning');
            return;
        }

        try {
            const originalRecord = JSON.parse(originalRecordText);

            const formData = new FormData();
            formData.append('file', verificationFile);

            const response = await fetch(`${this.apiUrl}/verify`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    original_record: originalRecord
                })
            });

            const result = await response.json();

            if (result.success) {
                this.displayVerificationResult(result.verification_result);
            } else {
                this.showAlert(`Verification error: ${result.error}`, 'danger');
            }
        } catch (error) {
            this.showAlert('Invalid JSON format in original hash record.', 'danger');
        }
    }

    displayIntegrityResult(result, type) {
        const container = document.getElementById('integrityResults');
        if (!container) return;

        // Save the report for dashboard display
        this.saveIntegrityReport(result);

        // Clear "no results" message
        if (container.querySelector('.text-muted')) {
            container.innerHTML = '';
        }

        const timestamp = new Date(result.timestamp).toLocaleString();
        const record = result.integrity_record;

        const resultHTML = `
            <div class="integrity-result-item border rounded p-3 mb-3" data-filename="${result.filename}">
                <div class="d-flex justify-content-between align-items-start mb-2">
                    <h6 class="mb-0">
                        <i class="fas fa-file-alt"></i> ${result.filename}
                        <span class="badge bg-primary ms-2">${this.formatFileSize(result.file_size)}</span>
                    </h6>
                    <div class="text-end">
                        <small class="text-muted">${timestamp}</small>
                        <div>
                            <button class="btn btn-sm btn-outline-primary me-1" onclick="integrityManager.copyHashRecord('${result.filename}')">
                                <i class="fas fa-copy"></i> Copy JSON
                            </button>
                            <button class="btn btn-sm btn-outline-success" onclick="integrityManager.saveHashRecord('${result.filename}')">
                                <i class="fas fa-save"></i> Save
                            </button>
                        </div>
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-md-8">
                        <strong>Hash Values:</strong>
                        <div class="hash-values mt-2">
                            ${this.formatHashValues(record.hashes)}
                        </div>
                    </div>
                    <div class="col-md-4">
                        <strong>Details:</strong>
                        <ul class="list-unstyled mt-2 small">
                            <li><strong>Context:</strong> ${record.context}</li>
                            <li><strong>Calculation Time:</strong> ${record.calculation_time_ms}ms</li>
                            <li><strong>File Size:</strong> ${record.file_size} bytes</li>
                            <li><strong>Hash Count:</strong> ${Object.keys(record.hashes).length}</li>
                        </ul>
                    </div>
                </div>
                
                <div class="mt-2">
                    <small class="text-muted">
                        <i class="fas fa-info-circle"></i>
                        Created: ${new Date(record.created_at).toLocaleString()}
                    </small>
                </div>
            </div>
        `;

        container.insertAdjacentHTML('afterbegin', resultHTML);
    }

    displayBatchIntegrityResults(result) {
        const container = document.getElementById('integrityResults');
        if (!container) return;

        // Save batch reports for dashboard display
        this.saveBatchIntegrityReports(result);

        // Clear "no results" message
        if (container.querySelector('.text-muted')) {
            container.innerHTML = '';
        }

        const timestamp = new Date(result.timestamp).toLocaleString();

        const batchHTML = `
            <div class="batch-result-container border rounded p-3 mb-3">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h6 class="mb-0">
                        <i class="fas fa-layer-group"></i> Batch Hash Calculation
                        <span class="badge bg-info ms-2">${result.file_count} files</span>
                    </h6>
                    <div class="text-end">
                        <small class="text-muted">${timestamp}</small>
                        <div>
                            <button class="btn btn-sm btn-outline-primary" onclick="integrityManager.exportBatchResults()">
                                <i class="fas fa-download"></i> Export All
                            </button>
                        </div>
                    </div>
                </div>
                
                <div class="batch-files">
                    ${Object.entries(result.results).map(([filename, fileResult]) => `
                        <div class="file-result border-start border-3 border-primary ps-3 pb-2 mb-2">
                            <div class="d-flex justify-content-between align-items-start">
                                <strong>${filename}</strong>
                                <span class="badge bg-secondary">${this.formatFileSize(fileResult.file_size)}</span>
                            </div>
                            <div class="hash-values-compact mt-1">
                                ${this.formatHashValuesCompact(fileResult.hashes)}
                            </div>
                            <div class="small text-muted mt-1">
                                Time: ${fileResult.calculation_time_ms}ms | 
                                Context: ${fileResult.context}
                            </div>
                        </div>
                    `).join('')}
                </div>
                
                ${result.errors.length > 0 ? `
                    <div class="alert alert-warning mt-3">
                        <strong>Errors encountered:</strong>
                        <ul class="mb-0 mt-1">
                            ${result.errors.map(error => `<li>${error}</li>`).join('')}
                        </ul>
                    </div>
                ` : ''}
            </div>
        `;

        container.insertAdjacentHTML('afterbegin', batchHTML);
    }

    displayVerificationResult(verificationResult) {
        const container = document.getElementById('verificationResults');
        if (!container) return;

        const statusIcon = verificationResult.overall_integrity ?
            '<i class="fas fa-check-circle text-success"></i>' :
            '<i class="fas fa-times-circle text-danger"></i>';

        const statusText = verificationResult.overall_integrity ? 'VERIFIED' : 'VERIFICATION FAILED';
        const statusClass = verificationResult.overall_integrity ? 'success' : 'danger';

        const resultHTML = `
            <div class="alert alert-${statusClass} mb-3">
                <h6>${statusIcon} File Integrity ${statusText}</h6>
                <div class="mt-2">
                    <strong>Status:</strong> ${verificationResult.verification_status}<br>
                    <strong>Matched Hashes:</strong> ${verificationResult.matched_hashes} / ${verificationResult.total_hashes}<br>
                    <strong>Verification Time:</strong> ${verificationResult.verification_time_ms}ms
                </div>
            </div>
            
            <div class="verification-details">
                <h6>Hash Comparison Results:</h6>
                <div class="table-responsive">
                    <table class="table table-sm">
                        <thead>
                            <tr>
                                <th>Algorithm</th>
                                <th>Original Hash</th>
                                <th>Current Hash</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${Object.entries(verificationResult.hash_comparisons).map(([algorithm, comparison]) => `
                                <tr>
                                    <td><code>${algorithm.toUpperCase()}</code></td>
                                    <td><code class="small">${comparison.original_hash}</code></td>
                                    <td><code class="small">${comparison.current_hash}</code></td>
                                    <td>
                                        ${comparison.matches ?
                '<span class="badge bg-success"><i class="fas fa-check"></i> Match</span>' :
                '<span class="badge bg-danger"><i class="fas fa-times"></i> Mismatch</span>'
            }
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        `;

        container.innerHTML = resultHTML;
    }

    formatHashValues(hashes) {
        return Object.entries(hashes).map(([algorithm, hash]) => `
            <div class="hash-entry mb-2">
                <div class="d-flex justify-content-between align-items-center">
                    <strong class="text-uppercase">${algorithm}:</strong>
                    <button class="btn btn-sm btn-outline-secondary" onclick="integrityManager.copyToClipboard('${hash}')">
                        <i class="fas fa-copy"></i>
                    </button>
                </div>
                <code class="d-block small text-break">${hash}</code>
            </div>
        `).join('');
    }

    formatHashValuesCompact(hashes) {
        return Object.entries(hashes).map(([algorithm, hash]) => `
            <div class="d-flex justify-content-between align-items-center small">
                <span class="text-uppercase fw-bold">${algorithm}:</span>
                <code class="text-break ms-2">${hash.substring(0, 16)}...</code>
            </div>
        `).join('');
    }

    formatFileSize(bytes) {
        const sizes = ['B', 'KB', 'MB', 'GB'];
        if (bytes === 0) return '0 B';
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
    }

    getSelectedAlgorithms() {
        const checkboxes = document.querySelectorAll('#algorithmCheckboxes input[type="checkbox"]:checked');
        return Array.from(checkboxes).map(cb => cb.value);
    }

    showIntegrityLoading(fileCount) {
        const container = document.getElementById('integrityResults');
        if (!container) return;

        const loadingHTML = `
            <div id="integrityLoading" class="text-center py-4">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <div class="mt-2">
                    <strong>Calculating hashes for ${fileCount} file${fileCount > 1 ? 's' : ''}...</strong>
                    <div class="small text-muted">Please wait while we process your files</div>
                </div>
            </div>
        `;

        // Remove any existing loading indicators
        const existing = document.getElementById('integrityLoading');
        if (existing) existing.remove();

        container.insertAdjacentHTML('afterbegin', loadingHTML);
    }

    clearIntegrityResults() {
        const container = document.getElementById('integrityResults');
        if (!container) return;

        container.innerHTML = `
            <div class="text-muted text-center py-4">
                <i class="fas fa-info-circle"></i>
                No integrity checks performed yet. Upload files to calculate hash values.
            </div>
        `;
    }

    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            this.showAlert('Hash copied to clipboard!', 'success');
        } catch (error) {
            console.error('Failed to copy to clipboard:', error);
            this.showAlert('Failed to copy to clipboard', 'warning');
        }
    }

    copyHashRecord(filename) {
        const resultItem = document.querySelector(`[data-filename="${filename}"]`);
        if (!resultItem) return;

        // Extract the full integrity record (this would need to be stored)
        // For now, we'll create a simplified version
        const record = {
            filename: filename,
            timestamp: new Date().toISOString(),
            note: 'Full integrity record would be stored and retrieved here'
        };

        this.copyToClipboard(JSON.stringify(record, null, 2));
    }

    exportIntegrityResults() {
        // Implementation for exporting all integrity results
        const results = document.querySelectorAll('.integrity-result-item, .batch-result-container');
        if (results.length === 0) {
            this.showAlert('No results to export', 'warning');
            return;
        }

        // Create export data
        const exportData = {
            exported_at: new Date().toISOString(),
            total_results: results.length,
            note: 'Integrity check results export'
        };

        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `integrity_results_${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);

        this.showAlert('Results exported successfully!', 'success');
    }

    saveIntegrityReport(result) {
        // Save integrity report to localStorage for dashboard display
        try {
            const reports = JSON.parse(localStorage.getItem('integrity_reports') || '[]');

            const report = {
                filename: result.filename,
                timestamp: result.timestamp,
                size: result.file_size,
                type: result.file_type || 'Unknown',
                hashes: result.integrity_record.hashes,
                context: result.integrity_record.context,
                processing_time: result.integrity_record.calculation_time_ms
            };

            // Check if report already exists (avoid duplicates)
            const existingIndex = reports.findIndex(r =>
                r.filename === report.filename &&
                r.timestamp === report.timestamp
            );

            const isNewReport = existingIndex < 0;
            if (isNewReport) {
                reports.push(report); // Add new
            } else {
                reports[existingIndex] = report; // Update existing
            }

            // Keep only last 100 reports to avoid localStorage bloat
            if (reports.length > 100) {
                reports.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
                reports.splice(100);
            }

            localStorage.setItem('integrity_reports', JSON.stringify(reports));
            console.log('Integrity report saved:', report.filename);

            // Update dashboard statistics for new reports only
            if (isNewReport) {
                this.updateDashboardStatistics(1, 1);
            }
        } catch (error) {
            console.error('Error saving integrity report:', error);
        }
    } saveBatchIntegrityReports(batchResult) {
        // Save batch integrity reports to localStorage for dashboard display
        try {
            const reports = JSON.parse(localStorage.getItem('integrity_reports') || '[]');
            let newReportsCount = 0;

            // Process each file in the batch
            Object.entries(batchResult.results).forEach(([filename, fileResult]) => {
                const report = {
                    filename: filename,
                    timestamp: batchResult.timestamp,
                    size: fileResult.file_size,
                    type: fileResult.file_type || 'Unknown',
                    hashes: fileResult.hashes,
                    context: batchResult.context || 'batch_processing',
                    processing_time: fileResult.calculation_time_ms || 0
                };

                // Check if report already exists (avoid duplicates)
                const existingIndex = reports.findIndex(r =>
                    r.filename === report.filename &&
                    r.timestamp === report.timestamp
                );

                if (existingIndex >= 0) {
                    reports[existingIndex] = report; // Update existing
                } else {
                    reports.push(report); // Add new
                    newReportsCount++;
                }
            });

            // Keep only last 100 reports to avoid localStorage bloat
            if (reports.length > 100) {
                reports.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
                reports.splice(100);
            }

            localStorage.setItem('integrity_reports', JSON.stringify(reports));
            console.log('Batch integrity reports saved:', Object.keys(batchResult.results).length, 'files');

            // Update dashboard statistics for new reports only
            if (newReportsCount > 0) {
                this.updateDashboardStatistics(newReportsCount, 1); // 1 integrity check for the batch
            }
        } catch (error) {
            console.error('Error saving batch integrity reports:', error);
        }
    }

    updateDashboardStatistics(filesAnalyzed = 0, integrityChecks = 0) {
        // Update dashboard statistics when integrity operations are performed
        try {
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

            console.log('Dashboard statistics updated:', { filesAnalyzed, integrityChecks, newTotals: newStats });
        } catch (error) {
            console.error('Error updating dashboard statistics:', error);
        }
    }

    generateOperationId() {
        return 'op_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now();
    }

    showAlert(message, type = 'info') {
        // Create alert element
        const alertHTML = `
            <div class="alert alert-${type} alert-dismissible fade show" role="alert">
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `;

        // Find or create alert container
        let alertContainer = document.getElementById('integrityAlerts');
        if (!alertContainer) {
            alertContainer = document.createElement('div');
            alertContainer.id = 'integrityAlerts';
            alertContainer.className = 'position-fixed top-0 end-0 p-3';
            alertContainer.style.zIndex = '1050';
            document.body.appendChild(alertContainer);
        }

        // Add alert
        alertContainer.insertAdjacentHTML('beforeend', alertHTML);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            const alerts = alertContainer.querySelectorAll('.alert');
            alerts.forEach((alert, index) => {
                if (index === 0) { // Remove oldest alert
                    alert.remove();
                }
            });
        }, 5000);
    }
}

// Initialize integrity manager when DOM is ready
document.addEventListener('DOMContentLoaded', function () {
    window.integrityManager = new IntegrityManager();
});

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = IntegrityManager;
}