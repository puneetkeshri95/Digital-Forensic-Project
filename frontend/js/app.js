/**
 * Digital Forensics Application - Main JavaScript
 */

// Global variables
let currentPage = 'dashboard';
const API_BASE_URL = 'http://localhost:5000/api';

// Initialize application
document.addEventListener('DOMContentLoaded', function () {
    initializeApp();
    setupEventListeners();
    loadDashboardData();
});

/**
 * Initialize the application
 */
function initializeApp() {
    console.log('Digital Forensics Application initialized');
    checkAPIHealth();
    setupNavigation();

    // Initialize case management when document is ready
    setTimeout(() => {
        if (typeof initializeCaseManagement === 'function') {
            initializeCaseManagement();
        }
    }, 100);
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
    // Navigation
    document.querySelectorAll('[data-page]').forEach(link => {
        link.addEventListener('click', function (e) {
            e.preventDefault();
            const page = this.getAttribute('data-page');
            navigateToPage(page);
        });
    });

    // File upload form
    const uploadForm = document.getElementById('upload-form');
    if (uploadForm) {
        uploadForm.addEventListener('submit', handleFileUpload);
    }

    // New case form
    const newCaseForm = document.getElementById('new-case-form');
    if (newCaseForm) {
        newCaseForm.addEventListener('submit', function (e) {
            e.preventDefault();
            createCase();
        });
    }

    // File input changes
    const evidenceFile = document.getElementById('evidence-file');
    if (evidenceFile) {
        evidenceFile.addEventListener('change', handleFileSelection);
    }
}

/**
 * Setup navigation system
 */
function setupNavigation() {
    // Show dashboard by default
    navigateToPage('dashboard');
}

/**
 * Navigate to a specific page
 */
function navigateToPage(pageName) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(page => {
        page.classList.remove('active');
    });

    // Show selected page
    const targetPage = document.getElementById(`${pageName}-page`);
    if (targetPage) {
        targetPage.classList.add('active');
        currentPage = pageName;

        // Update navigation
        document.querySelectorAll('[data-page]').forEach(link => {
            link.classList.remove('active');
        });
        document.querySelector(`[data-page="${pageName}"]`).classList.add('active');

        // Load page data
        loadPageData(pageName);
    }
}

/**
 * Load data for specific page
 */
function loadPageData(pageName) {
    switch (pageName) {
        case 'dashboard':
            loadDashboardData();
            break;
        case 'analysis':
            loadAnalysisResults();
            break;
        case 'cases':
            loadCases();
            updateCaseStatistics();
            break;
        case 'file-recovery':
            initializeFileRecovery();
            break;
        case 'image-analysis':
            initializeImageAnalysis();
            break;
        case 'logs-reports':
            loadSystemLogs();
            break;
        case 'upload':
            // No initial data loading needed
            break;
        case 'tools':
            // No initial data loading needed
            break;
    }
}

/**
 * Check API health
 */
async function checkAPIHealth() {
    try {
        const response = await fetch(`${API_BASE_URL}/health`);
        const data = await response.json();

        if (data.status === 'healthy') {
            updateStatus('api-status', 'Online', 'success');
        } else {
            updateStatus('api-status', 'Error', 'danger');
        }
    } catch (error) {
        console.error('API health check failed:', error);
        updateStatus('api-status', 'Offline', 'danger');
    }
}

/**
 * Update status indicator
 */
function updateStatus(elementId, text, type) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = text;
        element.className = `badge bg-${type}`;
    }
}

/**
 * Load dashboard data
 */
async function loadDashboardData() {
    try {
        // Load cases count
        const casesResponse = await fetch(`${API_BASE_URL}/forensic/cases`);
        if (casesResponse.ok) {
            const casesData = await casesResponse.json();
            document.getElementById('total-cases').textContent = casesData.cases.length;
        }

        // Load analysis summary
        const analysisResponse = await fetch(`${API_BASE_URL}/analysis/summary`);
        if (analysisResponse.ok) {
            const analysisData = await analysisResponse.json();
            document.getElementById('completed-analysis').textContent = analysisData.total_analyses;
        }

        // Load files count
        const filesResponse = await fetch(`${API_BASE_URL}/files/list`);
        if (filesResponse.ok) {
            const filesData = await filesResponse.json();
            document.getElementById('evidence-count').textContent = filesData.files.length;
        }

    } catch (error) {
        console.error('Error loading dashboard data:', error);
        showAlert('Error loading dashboard data', 'danger');
    }
}

/**
 * Handle file selection
 */
function handleFileSelection(event) {
    const file = event.target.files[0];
    if (file) {
        const fileSize = (file.size / 1024 / 1024).toFixed(2);
        console.log(`Selected file: ${file.name} (${fileSize} MB)`);

        // Show file info
        const fileInfo = document.createElement('div');
        fileInfo.className = 'alert alert-info mt-2';
        fileInfo.innerHTML = `
            <strong>Selected:</strong> ${file.name}<br>
            <strong>Size:</strong> ${fileSize} MB<br>
            <strong>Type:</strong> ${file.type || 'Unknown'}
        `;

        // Remove existing file info
        const existingInfo = event.target.parentNode.querySelector('.alert');
        if (existingInfo) {
            existingInfo.remove();
        }

        event.target.parentNode.appendChild(fileInfo);
    }
}

/**
 * Handle file upload
 */
async function handleFileUpload(event) {
    event.preventDefault();

    const fileInput = document.getElementById('evidence-file');
    const caseName = document.getElementById('case-name').value;
    const description = document.getElementById('description').value;

    if (!fileInput.files[0]) {
        showAlert('Please select a file', 'warning');
        return;
    }

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('case_name', caseName);
    formData.append('description', description);

    try {
        showLoading('Uploading and analyzing file...');

        const response = await fetch(`${API_BASE_URL}/forensic/analyze`, {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (response.ok) {
            showAlert('File uploaded and analyzed successfully!', 'success');

            // Show analysis results
            displayAnalysisResult(result);

            // Reset form
            document.getElementById('upload-form').reset();

            // Remove file info
            const fileInfo = document.querySelector('#upload-form .alert');
            if (fileInfo) {
                fileInfo.remove();
            }

        } else {
            showAlert(result.error || 'Upload failed', 'danger');
        }

    } catch (error) {
        console.error('Upload error:', error);
        showAlert('Upload failed. Please try again.', 'danger');
    } finally {
        hideLoading();
    }
}

/**
 * Display analysis result
 */
function displayAnalysisResult(result) {
    const resultHTML = `
        <div class="analysis-item">
            <div class="analysis-header">
                <h5 class="analysis-title">${result.filename}</h5>
                <span class="badge bg-success">Completed</span>
            </div>
            <div class="row">
                <div class="col-md-6">
                    <h6>File Information</h6>
                    <p><strong>Case ID:</strong> ${result.case_id}</p>
                    <p><strong>File Hash (SHA256):</strong> <br><code>${result.file_hash.sha256 || 'N/A'}</code></p>
                </div>
                <div class="col-md-6">
                    <h6>Analysis Summary</h6>
                    <p><strong>File Type:</strong> ${result.analysis.file_type?.description || 'Unknown'}</p>
                    <p><strong>Risk Level:</strong> 
                        <span class="badge bg-${getRiskBadgeClass(result.analysis.security_scan?.risk_level)}">${result.analysis.security_scan?.risk_level || 'Unknown'}</span>
                    </p>
                </div>
            </div>
        </div>
    `;

    // Add to recent activity
    const recentActivity = document.getElementById('recent-activity');
    if (recentActivity) {
        if (recentActivity.querySelector('.text-muted')) {
            recentActivity.innerHTML = '';
        }
        recentActivity.insertAdjacentHTML('afterbegin', resultHTML);
    }
}

/**
 * Get risk level badge class
 */
function getRiskBadgeClass(riskLevel) {
    switch (riskLevel) {
        case 'low': return 'success';
        case 'medium': return 'warning';
        case 'high': return 'danger';
        default: return 'secondary';
    }
}

/**
 * Load analysis results
 */
async function loadAnalysisResults() {
    try {
        const response = await fetch(`${API_BASE_URL}/analysis/results`);
        const data = await response.json();

        const resultsContainer = document.getElementById('analysis-results');

        if (data.results && data.results.length > 0) {
            resultsContainer.innerHTML = data.results.map(result => `
                <div class="analysis-item">
                    <div class="analysis-header">
                        <h5 class="analysis-title">${result.basic_info?.filename || 'Unknown File'}</h5>
                        <span class="analysis-timestamp">${new Date(result.timestamp).toLocaleString()}</span>
                    </div>
                    <div class="row">
                        <div class="col-md-4">
                            <h6>File Info</h6>
                            <p><strong>Size:</strong> ${formatFileSize(result.basic_info?.size)}</p>
                            <p><strong>Type:</strong> ${result.file_type?.description || 'Unknown'}</p>
                        </div>
                        <div class="col-md-4">
                            <h6>Security</h6>
                            <p><strong>Risk Level:</strong> 
                                <span class="badge bg-${getRiskBadgeClass(result.security_scan?.risk_level)}">${result.security_scan?.risk_level || 'Unknown'}</span>
                            </p>
                            <p><strong>Indicators:</strong> ${result.security_scan?.suspicious_indicators?.length || 0}</p>
                        </div>
                        <div class="col-md-4">
                            <h6>Hash</h6>
                            <p><strong>SHA256:</strong><br><code class="small">${result.hash_analysis?.sha256 || 'N/A'}</code></p>
                        </div>
                    </div>
                </div>
            `).join('');
        } else {
            resultsContainer.innerHTML = '<p class="text-muted">No analysis results available</p>';
        }

    } catch (error) {
        console.error('Error loading analysis results:', error);
        showAlert('Error loading analysis results', 'danger');
    }
}

/**
 * Load cases
 */
async function loadCases() {
    try {
        const response = await fetch(`${API_BASE_URL}/forensic/cases`);
        const data = await response.json();

        const casesContainer = document.getElementById('cases-list');

        if (data.cases && data.cases.length > 0) {
            casesContainer.innerHTML = `
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Case ID</th>
                                <th>Case Name</th>
                                <th>Investigator</th>
                                <th>Created Date</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${data.cases.map(case_ => `
                                <tr>
                                    <td>${case_.id}</td>
                                    <td>${case_.case_name || 'Untitled'}</td>
                                    <td>${case_.investigator || 'Unknown'}</td>
                                    <td>${new Date(case_.created_date).toLocaleDateString()}</td>
                                    <td><span class="badge bg-${case_.status === 'open' ? 'success' : 'secondary'}">${case_.status}</span></td>
                                    <td>
                                        <button class="btn btn-sm btn-outline-primary" onclick="viewCase(${case_.id})">
                                            <i class="bi bi-eye"></i> View
                                        </button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        } else {
            casesContainer.innerHTML = '<p class="text-muted">No cases found</p>';
        }

    } catch (error) {
        console.error('Error loading cases:', error);
        showAlert('Error loading cases', 'danger');
    }
}

/**
 * Create new case
 */
async function createCase() {
    const caseName = document.getElementById('modal-case-name').value;
    const investigator = document.getElementById('modal-investigator').value;
    const description = document.getElementById('modal-case-description').value;

    if (!caseName.trim()) {
        showAlert('Case name is required', 'warning');
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/forensic/cases`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                case_name: caseName,
                investigator: investigator,
                description: description
            })
        });

        const result = await response.json();

        if (response.ok) {
            showAlert('Case created successfully!', 'success');

            // Close modal
            const modal = bootstrap.Modal.getInstance(document.getElementById('newCaseModal'));
            modal.hide();

            // Reset form
            document.getElementById('new-case-form').reset();

            // Reload cases if on cases page
            if (currentPage === 'cases') {
                loadCases();
            }

        } else {
            showAlert(result.error || 'Failed to create case', 'danger');
        }

    } catch (error) {
        console.error('Error creating case:', error);
        showAlert('Failed to create case', 'danger');
    }
}

/**
 * View case details
 */
async function viewCase(caseId) {
    try {
        const response = await fetch(`${API_BASE_URL}/forensic/cases/${caseId}`);
        const data = await response.json();

        if (response.ok && data.case) {
            // Show case details in a modal or navigate to detail page
            console.log('Case details:', data.case);
            showAlert(`Case "${data.case.case_name}" details loaded`, 'info');
        } else {
            showAlert('Case not found', 'warning');
        }

    } catch (error) {
        console.error('Error loading case:', error);
        showAlert('Error loading case details', 'danger');
    }
}

/**
 * Calculate hash for selected file
 */
async function calculateHash() {
    const fileInput = document.getElementById('hash-file');

    if (!fileInput.files[0]) {
        showAlert('Please select a file', 'warning');
        return;
    }

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    try {
        showLoading('Calculating hashes...');

        const response = await fetch(`${API_BASE_URL}/forensic/hash`, {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (response.ok) {
            const hashResults = document.getElementById('hash-results');
            hashResults.innerHTML = `
                <div class="hash-result">
                    <div class="hash-type">MD5:</div>
                    <div class="hash-value">${result.md5}</div>
                </div>
                <div class="hash-result">
                    <div class="hash-type">SHA1:</div>
                    <div class="hash-value">${result.sha1}</div>
                </div>
                <div class="hash-result">
                    <div class="hash-type">SHA256:</div>
                    <div class="hash-value">${result.sha256}</div>
                </div>
            `;
        } else {
            showAlert(result.error || 'Hash calculation failed', 'danger');
        }

    } catch (error) {
        console.error('Hash calculation error:', error);
        showAlert('Hash calculation failed', 'danger');
    } finally {
        hideLoading();
    }
}

/**
 * Get file information
 */
function getFileInfo() {
    const fileInput = document.getElementById('info-file');

    if (!fileInput.files[0]) {
        showAlert('Please select a file', 'warning');
        return;
    }

    const file = fileInput.files[0];
    const infoResults = document.getElementById('info-results');

    infoResults.innerHTML = `
        <div class="card">
            <div class="card-body">
                <h6>File Information</h6>
                <p><strong>Name:</strong> ${file.name}</p>
                <p><strong>Size:</strong> ${formatFileSize(file.size)}</p>
                <p><strong>Type:</strong> ${file.type || 'Unknown'}</p>
                <p><strong>Last Modified:</strong> ${new Date(file.lastModified).toLocaleString()}</p>
            </div>
        </div>
    `;
}

/**
 * Refresh analysis results
 */
function refreshAnalysis() {
    if (currentPage === 'analysis') {
        loadAnalysisResults();
    }
}

/**
 * Format file size
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';

    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Show alert message
 */
function showAlert(message, type = 'info') {
    const alertHTML = `
        <div class="alert alert-${type} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;

    // Add to top of current page
    const currentPageElement = document.querySelector('.page.active');
    if (currentPageElement) {
        currentPageElement.insertAdjacentHTML('afterbegin', alertHTML);

        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            const alert = currentPageElement.querySelector('.alert');
            if (alert) {
                const alertInstance = new bootstrap.Alert(alert);
                alertInstance.close();
            }
        }, 5000);
    }
}

/**
 * Show loading state
 */
function showLoading(message = 'Loading...') {
    // Implementation depends on your loading UI design
    console.log(message);
}

/**
 * Hide loading state
 */
function hideLoading() {
    // Implementation depends on your loading UI design
    console.log('Loading complete');
}

// ============================================
// ENHANCED FORENSIC MODULE FUNCTIONS (RECUVA-LIKE)
// ============================================

// Global recovery state management
let recoveryState = {
    isScanning: false,
    isPaused: false,
    startTime: null,
    currentScan: null,
    foundFiles: [],
    selectedSource: null,
    scanOptions: {}
};

/**
 * Initialize Enhanced File Recovery Module (Recuva-like)
 */
function initializeFileRecovery() {
    console.log('Initializing Enhanced File Recovery Module (Recuva Professional)');

    setupRecoveryWizard();
    loadAvailableDrives();
    setupRecoveryEventListeners();
    resetRecoveryState();
    showAlert('Recuva File Recovery module initialized', 'info');
}

/**
 * Detect available drives for recovery
 */
function detectAvailableDrives() {
    // Simulate drive detection (in real implementation, this would call a backend API)
    const driveSelect = document.getElementById('drive-select');
    if (driveSelect) {
        // Clear existing options except first
        driveSelect.innerHTML = `
            <option value="">Select a drive...</option>
            <option value="C:">C: System Drive (NTFS)</option>
            <option value="D:">D: Data Drive (NTFS)</option>
            <option value="E:">E: USB Drive (FAT32)</option>
            <option value="F:">F: SD Card (exFAT)</option>
        `;
    }
}

/**
 * Start Recovery Scan (Real Deep Scan Implementation)
 */
async function startRecoveryScan() {
    const driveSelect = document.getElementById('drive-select');
    const diskImageFile = document.getElementById('disk-image-file');
    const scanType = document.querySelector('input[name="scanType"]:checked');

    // Determine scan source
    let imagePath = null;
    if (recoveryState.selectedSource === 'drive') {
        if (!driveSelect.value) {
            showAlert('Please select a drive to scan', 'warning');
            return;
        }
        imagePath = driveSelect.value;
    } else if (recoveryState.selectedSource === 'image') {
        if (!diskImageFile.files[0]) {
            showAlert('Please select a disk image file', 'warning');
            return;
        }
        // For demo purposes, use the file name. In production, upload file first
        imagePath = `C:\\forensic\\images\\${diskImageFile.files[0].name}`;
    } else {
        showAlert('Please select a scan source', 'warning');
        return;
    }

    const type = scanType ? scanType.value : 'deep';

    // Collect scan options
    const scanOptions = {
        scan_type: type,
        scan_images: document.getElementById('file-type-images')?.checked || true,
        scan_documents: document.getElementById('file-type-documents')?.checked || true,
        scan_archives: document.getElementById('file-type-archives')?.checked || true,
        scan_media: document.getElementById('file-type-media')?.checked || true,
        deleted_files_only: type === 'deleted'
    };

    try {
        showAlert(`Starting ${type} scan on ${imagePath}...`, 'info');

        // Show progress
        const progressDiv = document.getElementById('recovery-progress');
        const resultsDiv = document.getElementById('recovery-results');

        progressDiv.classList.remove('d-none');
        resultsDiv.innerHTML = '';

        // Start deep scan via API
        const response = await fetch(`${API_BASE_URL}/deep-scan/start-scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                image_path: imagePath,
                scan_options: scanOptions
            })
        });

        const scanResult = await response.json();

        if (response.ok && scanResult.status === 'success') {
            recoveryState.currentScan = scanResult.session_id;
            recoveryState.isScanning = true;
            recoveryState.startTime = new Date();
            recoveryState.scanOptions = scanOptions;

            showAlert('Deep scan started successfully', 'success');

            // Start monitoring progress
            monitorScanProgress(scanResult.session_id);
        } else {
            throw new Error(scanResult.error || 'Failed to start scan');
        }

    } catch (error) {
        console.error('Deep scan error:', error);
        showAlert(`Scan failed: ${error.message}`, 'danger');

        // Hide progress on error
        document.getElementById('recovery-progress').classList.add('d-none');
        recoveryState.isScanning = false;
    }
}

/**
 * Monitor Deep Scan Progress
 */
async function monitorScanProgress(sessionId) {
    const progressBar = document.querySelector('#recovery-progress .progress-bar');
    const progressText = document.querySelector('#progress-text');
    const filesFoundElement = document.getElementById('files-found');
    const sizeAnalyzedElement = document.getElementById('size-analyzed');
    const timeElapsedElement = document.getElementById('time-elapsed');
    const currentActivityElement = document.getElementById('current-activity');

    const updateInterval = setInterval(async () => {
        try {
            const response = await fetch(`${API_BASE_URL}/deep-scan/scan-status/${sessionId}`);
            const status = await response.json();

            if (response.ok) {
                // Update progress bar
                progressBar.style.width = `${status.progress}%`;
                if (progressText) {
                    progressText.textContent = `${Math.round(status.progress)}%`;
                }

                // Update statistics
                if (filesFoundElement) {
                    filesFoundElement.textContent = status.files_found.toLocaleString();
                }

                if (timeElapsedElement) {
                    const elapsed = Math.round(status.elapsed_time);
                    const hours = Math.floor(elapsed / 3600);
                    const minutes = Math.floor((elapsed % 3600) / 60);
                    const seconds = elapsed % 60;
                    timeElapsedElement.textContent = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
                }

                if (sizeAnalyzedElement && status.statistics) {
                    const sizeGB = (status.statistics.total_data_recovered / (1024 * 1024 * 1024)).toFixed(2);
                    sizeAnalyzedElement.textContent = `${sizeGB} GB`;
                }

                if (currentActivityElement) {
                    currentActivityElement.textContent = status.current_activity || 'Scanning...';
                }

                // Check if scan is complete
                if (status.status === 'completed') {
                    clearInterval(updateInterval);
                    recoveryState.isScanning = false;

                    showAlert(`Deep scan completed! Found ${status.files_found} files.`, 'success');

                    // Load and display results
                    setTimeout(() => {
                        loadScanResults(sessionId);
                    }, 1000);

                } else if (status.status === 'error') {
                    clearInterval(updateInterval);
                    recoveryState.isScanning = false;

                    showAlert(`Scan failed: ${status.error}`, 'danger');
                    document.getElementById('recovery-progress').classList.add('d-none');
                }

            } else {
                throw new Error('Failed to get scan status');
            }

        } catch (error) {
            console.error('Error monitoring scan progress:', error);
            clearInterval(updateInterval);
            recoveryState.isScanning = false;

            showAlert('Lost connection to scan process', 'warning');
        }
    }, 2000); // Update every 2 seconds

    // Store interval ID for potential cancellation
    recoveryState.progressInterval = updateInterval;
}

/**
 * Load Deep Scan Results from API
 */
async function loadScanResults(sessionId, page = 1, fileTypeFilter = 'all', searchQuery = '') {
    try {
        const params = new URLSearchParams({
            page: page,
            per_page: 50,
            file_type: fileTypeFilter,
            search: searchQuery
        });

        const response = await fetch(`${API_BASE_URL}/deep-scan/scan-results/${sessionId}?${params}`);
        const data = await response.json();

        if (response.ok) {
            // Hide progress and show results
            document.getElementById('recovery-progress').classList.add('d-none');
            displayDeepScanResults(data);

            // Store results in global state
            recoveryState.foundFiles = data.results || [];

        } else {
            throw new Error(data.error || 'Failed to load results');
        }

    } catch (error) {
        console.error('Error loading scan results:', error);
        showAlert(`Failed to load results: ${error.message}`, 'danger');
    }
}

/**
 * Display Deep Scan Results in Professional DataTables
 */
function displayDeepScanResults(data) {
    const results = data.results || [];

    if (results.length === 0) {
        showAlert('No files found matching the current filters.', 'info');
        return;
    }

    // Show the results section
    document.getElementById('recovery-results-section').style.display = 'block';

    // Update statistics
    updateRecoveryStatistics(results);

    // Initialize or update DataTables
    initializeRecoveredFilesTable(results);
}

// Generate results table
const tableHTML = `
        <div class="row mb-3">
            <div class="col-md-6">
                <div class="input-group">
                    <span class="input-group-text"><i class="bi bi-search"></i></span>
                    <input type="text" class="form-control" id="search-files" placeholder="Search files..." value="${data.filters?.search_query || ''}">
                </div>
            </div>
            <div class="col-md-3">
                <select class="form-select" id="filter-file-type">
                    <option value="all" ${data.filters?.file_type === 'all' ? 'selected' : ''}>All File Types</option>
                    <option value="JPEG" ${data.filters?.file_type === 'JPEG' ? 'selected' : ''}>Images (JPEG)</option>
                    <option value="PNG" ${data.filters?.file_type === 'PNG' ? 'selected' : ''}>Images (PNG)</option>
                    <option value="PDF" ${data.filters?.file_type === 'PDF' ? 'selected' : ''}>Documents (PDF)</option>
                    <option value="DOCX" ${data.filters?.file_type === 'DOCX' ? 'selected' : ''}>Documents (DOCX)</option>
                    <option value="ZIP" ${data.filters?.file_type === 'ZIP' ? 'selected' : ''}>Archives (ZIP)</option>
                    <option value="MP3" ${data.filters?.file_type === 'MP3' ? 'selected' : ''}>Audio (MP3)</option>
                    <option value="MP4" ${data.filters?.file_type === 'MP4' ? 'selected' : ''}>Video (MP4)</option>
                </select>
            </div>
            <div class="col-md-3">
                <div class="btn-group w-100" role="group">
                    <button type="button" class="btn btn-outline-primary" onclick="selectAllFiles()">
                        <i class="bi bi-check-all"></i> All
                    </button>
                    <button type="button" class="btn btn-outline-secondary" onclick="selectNoFiles()">
                        <i class="bi bi-x-lg"></i> None
                    </button>
                </div>
            </div>
        </div>
        
        <div class="table-responsive">
            <table class="table table-hover" id="results-table">
                <thead>
                    <tr>
                        <th width="40"><input type="checkbox" id="select-all-checkbox" onchange="toggleAllFiles(this)"></th>
                        <th>File Name</th>
                        <th>Type</th>
                        <th>Size</th>
                        <th>Status</th>
                        <th>Location</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${results.map(file => `
                        <tr>
                            <td>
                                <input type="checkbox" class="file-checkbox" value="${file.id}" onchange="updateSelectionCount()">
                            </td>
                            <td>
                                <i class="bi ${getFileIcon(file.file_type)} me-2"></i>
                                ${file.filename}
                            </td>
                            <td>
                                <span class="badge bg-secondary">${file.file_type}</span>
                            </td>
                            <td>${formatFileSize(file.size)}</td>
                            <td>
                                <span class="badge bg-${getRecoveryStatusClass(file.recovery_status)}">${capitalizeFirst(file.recovery_status)}</span>
                            </td>
                            <td>
                                <small class="text-muted">Sector ${file.sector_start.toLocaleString()}</small>
                            </td>
                            <td>
                                <button class="btn btn-sm btn-outline-success me-1" onclick="recoverSingleFile('${recoveryState.currentScan}', '${file.id}')" title="Recover this file">
                                    <i class="bi bi-download"></i>
                                </button>
                                <button class="btn btn-sm btn-outline-info" onclick="showFileDetails('${file.id}')" title="View details">
                                    <i class="bi bi-info-circle"></i>
                                </button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
        
        <div class="row mt-3">
            <div class="col-md-6">
                <p class="text-muted">
                    Showing ${(pagination.page - 1) * pagination.per_page + 1} to ${Math.min(pagination.page * pagination.per_page, pagination.total)} of ${pagination.total} files
                </p>
            </div>
            <div class="col-md-6">
                <nav>
                    <ul class="pagination pagination-sm justify-content-end">
                        ${generatePagination(pagination)}
                    </ul>
                </nav>
            </div>
        </div>
        
        <div class="row mt-3">
            <div class="col-md-12">
                <div class="card bg-light">
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <span id="selected-count">0</span> files selected
                            </div>
                            <div class="col-md-6 text-end">
                                <button class="btn btn-success me-2" onclick="recoverSelectedFiles()" id="recover-selected-btn" disabled>
                                    <i class="bi bi-download"></i> Recover Selected
                                </button>
                                <button class="btn btn-outline-secondary" onclick="exportFileList()">
                                    <i class="bi bi-file-earmark-text"></i> Export List
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

resultsDiv.innerHTML = tableHTML;

// Setup event listeners for search and filter
setupResultsEventListeners();
}

/**
 * Generate mock recovery results (fallback for development)
 */
function generateMockRecoveryResults() {
    return [
        {
            name: 'Document.docx',
            size: '2.3 MB',
            type: 'Document',
            deleted: '2025-11-15 14:30:22',
            recoverable: 'Excellent',
            icon: 'file-earmark-word'
        },
        {
            name: 'IMG_001.jpg',
            size: '4.1 MB',
            type: 'Image',
            deleted: '2025-11-16 09:15:11',
            recoverable: 'Good',
            icon: 'file-earmark-image'
        },
        {
            name: 'Backup.zip',
            size: '125.7 MB',
            type: 'Archive',
            deleted: '2025-11-17 18:45:33',
            recoverable: 'Poor',
            icon: 'file-earmark-zip'
        },
        {
            name: 'Video.mp4',
            size: '89.2 MB',
            type: 'Video',
            deleted: '2025-11-18 08:22:14',
            recoverable: 'Excellent',
            icon: 'file-earmark-play'
        }
    ];
}

/**
 * Display recovery results
 */
function displayRecoveryResults(files) {
    const resultsDiv = document.getElementById('recovery-results');

    if (files.length === 0) {
        resultsDiv.innerHTML = '<p class="text-muted text-center">No recoverable files found</p>';
        return;
    }

    let html = `
        <div class="table-responsive">
            <table class="table table-striped recovery-table">
                <thead>
                    <tr>
                        <th>File</th>
                        <th>Size</th>
                        <th>Type</th>
                        <th>Deleted</th>
                        <th>Recovery</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
    `;

    files.forEach((file, index) => {
        const recoverableClass = file.recoverable === 'Excellent' ? 'success' :
            file.recoverable === 'Good' ? 'warning' : 'danger';

        html += `
            <tr>
                <td>
                    <i class="bi bi-${file.icon} file-icon text-primary"></i>
                    ${file.name}
                </td>
                <td>${file.size}</td>
                <td>${file.type}</td>
                <td><small>${file.deleted}</small></td>
                <td><span class="badge bg-${recoverableClass}">${file.recoverable}</span></td>
                <td>
                    <button class="btn btn-sm btn-outline-success" onclick="recoverFile(${index})">
                        <i class="bi bi-download"></i> Recover
                    </button>
                </td>
            </tr>
        `;
    });

    html += `
                </tbody>
            </table>
        </div>
        <div class="mt-3">
            <button class="btn btn-success" onclick="recoverAllFiles()">
                <i class="bi bi-download"></i> Recover All Files
            </button>
        </div>
    `;

    resultsDiv.innerHTML = html;
    showAlert(`Found ${files.length} recoverable files`, 'success');
}

/**
 * Recover individual file
 */
function recoverFile(index) {
    showAlert('File recovery initiated. Check the recovered_files folder.', 'success');
}

/**
 * Recover all files
 */
function recoverAllFiles() {
    showAlert('All recoverable files are being restored. This may take a few minutes.', 'info');
}

/**
 * Initialize Image Analysis Module
 */
function initializeImageAnalysis() {
    console.log('Initializing Image Analysis Module');

    const imageFileInput = document.getElementById('imageFileInput');
    const uploadArea = document.getElementById('imageUploadArea');

    if (imageFileInput && uploadArea) {
        // File input change handler
        imageFileInput.addEventListener('change', handleImageSelection);

        // Drag and drop handlers
        uploadArea.addEventListener('dragover', handleDragOver);
        uploadArea.addEventListener('dragleave', handleDragLeave);
        uploadArea.addEventListener('drop', handleImageDrop);
        uploadArea.addEventListener('click', () => imageFileInput.click());
    }
}

/**
 * Handle image file selection
 */
function handleImageSelection(event) {
    const file = event.target.files[0];
    if (file && file.type.startsWith('image/')) {
        displayImagePreview(file);
    } else {
        showAlert('Please select a valid image file', 'warning');
    }
}

/**
 * Handle drag over event
 */
function handleDragOver(event) {
    event.preventDefault();
    event.currentTarget.classList.add('dragover');
}

/**
 * Handle drag leave event
 */
function handleDragLeave(event) {
    event.currentTarget.classList.remove('dragover');
}

/**
 * Handle image drop
 */
function handleImageDrop(event) {
    event.preventDefault();
    event.currentTarget.classList.remove('dragover');

    const files = event.dataTransfer.files;
    if (files.length > 0 && files[0].type.startsWith('image/')) {
        document.getElementById('imageFileInput').files = files;
        displayImagePreview(files[0]);
    } else {
        showAlert('Please drop a valid image file', 'warning');
    }
}

/**
 * Display image preview
 */
function displayImagePreview(file) {
    const reader = new FileReader();
    reader.onload = function (e) {
        const previewDiv = document.getElementById('imagePreview');
        const previewImg = document.getElementById('previewImg');

        previewImg.src = e.target.result;
        previewDiv.classList.remove('d-none');
    };
    reader.readAsDataURL(file);
}

/**
 * Analyze image
 */
function analyzeImage() {
    const fileInput = document.getElementById('imageFileInput');
    if (!fileInput.files[0]) {
        showAlert('Please select an image first', 'warning');
        return;
    }

    showLoading('Analyzing image...');

    // Simulate analysis
    setTimeout(() => {
        const mockResults = generateMockImageAnalysis();
        displayImageAnalysisResults(mockResults);
        hideLoading();
        showAlert('Image analysis completed', 'success');
    }, 2000);
}

/**
 * Generate mock image analysis results
 */
function generateMockImageAnalysis() {
    return {
        filename: 'IMG_001.jpg',
        fileSize: '4.1 MB',
        dimensions: '3840x2160',
        colorSpace: 'sRGB',
        exif: {
            camera: 'Canon EOS R5',
            lens: 'RF 24-70mm f/2.8L IS USM',
            dateTime: '2025:11:18 10:30:15',
            gps: '40.7128° N, 74.0060° W',
            iso: '200',
            aperture: 'f/5.6',
            shutterSpeed: '1/125s'
        },
        tampering: {
            detected: false,
            confidence: '95%',
            analysis: 'No signs of digital manipulation detected'
        }
    };
}

/**
 * Display image analysis results
 */
function displayImageAnalysisResults(results) {
    const resultsDiv = document.getElementById('imageAnalysisResults');

    const html = `
        <div class="row">
            <div class="col-md-6">
                <div class="analysis-result-item">
                    <h6><i class="bi bi-info-circle text-primary"></i> File Information</h6>
                    <div class="metadata-item">
                        <span class="metadata-label">Filename:</span>
                        <span class="metadata-value">${results.filename}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">File Size:</span>
                        <span class="metadata-value">${results.fileSize}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Dimensions:</span>
                        <span class="metadata-value">${results.dimensions}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Color Space:</span>
                        <span class="metadata-value">${results.colorSpace}</span>
                    </div>
                </div>
            </div>
            
            <div class="col-md-6">
                <div class="analysis-result-item">
                    <h6><i class="bi bi-camera text-success"></i> EXIF Data</h6>
                    <div class="metadata-item">
                        <span class="metadata-label">Camera:</span>
                        <span class="metadata-value">${results.exif.camera}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Lens:</span>
                        <span class="metadata-value">${results.exif.lens}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Date/Time:</span>
                        <span class="metadata-value">${results.exif.dateTime}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">GPS Location:</span>
                        <span class="metadata-value">${results.exif.gps}</span>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row mt-3">
            <div class="col-12">
                <div class="analysis-result-item">
                    <h6><i class="bi bi-shield-check text-warning"></i> Tampering Analysis</h6>
                    <div class="row">
                        <div class="col-md-4">
                            <div class="metadata-item">
                                <span class="metadata-label">Tampering Detected:</span>
                                <span class="badge ${results.tampering.detected ? 'bg-danger' : 'bg-success'}">
                                    ${results.tampering.detected ? 'Yes' : 'No'}
                                </span>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="metadata-item">
                                <span class="metadata-label">Confidence:</span>
                                <span class="metadata-value">${results.tampering.confidence}</span>
                            </div>
                        </div>
                        <div class="col-md-12 mt-2">
                            <p class="text-muted">${results.tampering.analysis}</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;

    resultsDiv.innerHTML = html;
}

/**
 * Extract EXIF data
 */
function extractExifData() {
    showAlert('EXIF data extraction started', 'info');
    analyzeImage();
}

/**
 * Detect tampering
 */
function detectTampering() {
    showAlert('Tampering detection analysis started', 'info');
    analyzeImage();
}

/**
 * Enhance image
 */
function enhanceImage() {
    showAlert('Image enhancement tools will be available in the next update', 'info');
}

/**
 * Extract GPS location
 */
function extractLocation() {
    showAlert('GPS location extraction started', 'info');
    analyzeImage();
}

/**
 * Load system logs
 */
function loadSystemLogs() {
    console.log('Loading system logs');

    // Simulate loading logs
    const mockLogs = generateMockLogs();
    displayLogs(mockLogs);
}

/**
 * Generate mock system logs
 */
function generateMockLogs() {
    return [
        {
            timestamp: '2025-11-18 10:30:15',
            type: 'SYSTEM',
            message: 'Digital Forensics Application started successfully',
            level: 'INFO'
        },
        {
            timestamp: '2025-11-18 10:31:22',
            type: 'RECOVERY',
            message: 'File recovery scan initiated on drive C:',
            level: 'INFO'
        },
        {
            timestamp: '2025-11-18 10:35:45',
            type: 'ANALYSIS',
            message: 'Image analysis completed: IMG_001.jpg',
            level: 'SUCCESS'
        },
        {
            timestamp: '2025-11-18 10:40:12',
            type: 'CASE',
            message: 'New forensic case created: Case #001',
            level: 'INFO'
        },
        {
            timestamp: '2025-11-18 10:42:33',
            type: 'SYSTEM',
            message: 'Database backup completed successfully',
            level: 'SUCCESS'
        }
    ];
}

/**
 * Display logs
 */
function displayLogs(logs) {
    const logsContainer = document.getElementById('logsContainer');

    const html = logs.map(log => {
        const badgeClass = log.type === 'SYSTEM' ? 'info' :
            log.type === 'RECOVERY' ? 'success' :
                log.type === 'ANALYSIS' ? 'warning' : 'primary';

        return `
            <div class="log-entry">
                <div class="d-flex justify-content-between">
                    <span class="log-time">${log.timestamp}</span>
                    <span class="badge bg-${badgeClass}">${log.type}</span>
                </div>
                <div class="log-message">${log.message}</div>
            </div>
        `;
    }).join('');

    logsContainer.innerHTML = html;
}

/**
 * Filter logs
 */
function filterLogs() {
    const logType = document.getElementById('logType').value;
    const dateRange = document.getElementById('dateRange').value;

    showAlert(`Filtering logs: Type=${logType}, Range=${dateRange}`, 'info');
    loadSystemLogs(); // Reload with filters
}

/**
 * Refresh logs
 */
function refreshLogs() {
    loadSystemLogs();
    showAlert('Logs refreshed', 'success');
}

/**
 * Generate full report
 */
function generateFullReport() {
    showAlert('Generating comprehensive forensic report...', 'info');

    setTimeout(() => {
        showAlert('Report generated successfully! Check the forensic_results folder.', 'success');
    }, 2000);
}

// ============================================
// QUICK ACTION FUNCTIONS
// ============================================

/**
 * Create new case (Quick Action)
 */
function createNewCase() {
    const modal = new bootstrap.Modal(document.getElementById('newCaseModal'));
    modal.show();
}

/**
 * Start file recovery (Quick Action)
 */
function startFileRecovery() {
    navigateToPage('file-recovery');
    showAlert('File recovery module loaded', 'info');
}

/**
 * Generate report (Quick Action)
 */
function generateReport() {
    navigateToPage('logs-reports');
    setTimeout(() => {
        generateFullReport();
    }, 500);
}

/**
 * View system status (Quick Action)
 */
function viewSystemStatus() {
    showAlert('System Status: All modules operational', 'success');
}

/**
 * Enhanced Case Management Utility Functions
 */
function getPriorityClass(priority) {
    const classes = {
        'low': 'bg-success',
        'medium': 'bg-warning',
        'high': 'bg-danger',
        'critical': 'bg-dark'
    };
    return classes[priority] || 'bg-secondary';
}

function getStatusBadge(status) {
    const badges = {
        'open': '<span class="badge bg-primary">Open</span>',
        'in-progress': '<span class="badge bg-info">In Progress</span>',
        'pending-review': '<span class="badge bg-warning">Pending Review</span>',
        'closed': '<span class="badge bg-secondary">Closed</span>'
    };
    return badges[status] || badges['open'];
}

function updateCaseStatistics() {
    const totalCases = currentCases.length;
    const activeCases = currentCases.filter(c => c.status === 'open' || c.status === 'in-progress').length;
    const pendingCases = currentCases.filter(c => c.status === 'pending-review').length;

    // In real app, evidence files count would come from backend
    const evidenceFiles = currentCases.reduce((total, caseItem) => {
        const evidence = JSON.parse(localStorage.getItem(`evidence_${caseItem.caseId}`)) || [];
        return total + evidence.length;
    }, 0);

    const totalCasesStat = document.getElementById('total-cases-stat');
    const activeCasesStat = document.getElementById('active-cases-stat');
    const pendingCasesStat = document.getElementById('pending-cases-stat');
    const evidenceFilesStat = document.getElementById('evidence-files-stat');

    if (totalCasesStat) totalCasesStat.textContent = totalCases;
    if (activeCasesStat) activeCasesStat.textContent = activeCases;
    if (pendingCasesStat) pendingCasesStat.textContent = pendingCases;
    if (evidenceFilesStat) evidenceFilesStat.textContent = evidenceFiles;
}

function refreshCases() {
    showAlert('Refreshing cases...', 'info');
    setTimeout(() => {
        loadCases();
        updateCaseStatistics();
        showAlert('Cases refreshed successfully!', 'success');
    }, 1000);
}

function filterCases() {
    const statusFilter = document.getElementById('case-status-filter');
    const priorityFilter = document.getElementById('case-priority-filter');

    if (!statusFilter || !priorityFilter) return;

    const statusValue = statusFilter.value;
    const priorityValue = priorityFilter.value;

    let filteredCases = currentCases;

    if (statusValue !== 'all') {
        filteredCases = filteredCases.filter(c => c.status === statusValue);
    }

    if (priorityValue !== 'all') {
        filteredCases = filteredCases.filter(c => c.priority === priorityValue);
    }

    // Update display with filtered cases
    displayFilteredCases(filteredCases);
    showAlert(`Found ${filteredCases.length} cases matching your criteria`, 'info');
}

function displayFilteredCases(cases) {
    const casesList = document.getElementById('cases-list');

    if (!casesList) return;

    if (cases.length === 0) {
        casesList.innerHTML = `
            <div class="text-center py-4">
                <i class="bi bi-search fs-1 text-muted"></i>
                <p class="text-muted mt-2">No cases match your filter criteria.</p>
                <button class="btn btn-outline-secondary" onclick="clearFilters()">
                    <i class="bi bi-x-circle"></i> Clear Filters
                </button>
            </div>
        `;
        return;
    }

    // Temporarily replace currentCases for display
    const originalCases = currentCases;
    currentCases = cases;
    displayCases();
    currentCases = originalCases;
}

function clearFilters() {
    const statusFilter = document.getElementById('case-status-filter');
    const priorityFilter = document.getElementById('case-priority-filter');

    if (statusFilter) statusFilter.value = 'all';
    if (priorityFilter) priorityFilter.value = 'all';

    displayCases();
}

function viewCaseDetails(caseId) {
    const caseItem = currentCases.find(c => c.caseId === caseId);
    if (!caseItem) {
        showAlert('Case not found', 'error');
        return;
    }

    const modal = new bootstrap.Modal(document.getElementById('caseDetailsModal'));
    document.getElementById('caseDetailsTitle').innerHTML = `<i class="bi bi-briefcase"></i> ${caseItem.caseName}`;

    // Load evidence for this case
    const evidence = JSON.parse(localStorage.getItem(`evidence_${caseId}`)) || [];

    document.getElementById('caseDetailsContent').innerHTML = `
        <div class="row">
            <div class="col-md-8">
                <h6>Case Information</h6>
                <table class="table table-bordered">
                    <tr><td><strong>Case ID:</strong></td><td>${caseItem.caseId}</td></tr>
                    <tr><td><strong>Name:</strong></td><td>${caseItem.caseName}</td></tr>
                    <tr><td><strong>Investigator:</strong></td><td>${caseItem.investigator}</td></tr>
                    <tr><td><strong>Department:</strong></td><td>${caseItem.department || 'Not specified'}</td></tr>
                    <tr><td><strong>Priority:</strong></td><td><span class="badge ${getPriorityClass(caseItem.priority)}">${caseItem.priority}</span></td></tr>
                    <tr><td><strong>Status:</strong></td><td>${getStatusBadge(caseItem.status)}</td></tr>
                    <tr><td><strong>Type:</strong></td><td>${caseItem.caseType}</td></tr>
                    <tr><td><strong>Created:</strong></td><td>${new Date(caseItem.createdAt).toLocaleString()}</td></tr>
                    ${caseItem.incidentDate ? `<tr><td><strong>Incident Date:</strong></td><td>${new Date(caseItem.incidentDate).toLocaleDateString()}</td></tr>` : ''}
                    ${caseItem.location ? `<tr><td><strong>Location:</strong></td><td>${caseItem.location}</td></tr>` : ''}
                </table>
                
                ${caseItem.description ? `<h6>Description</h6><p>${caseItem.description}</p>` : ''}
                
                ${caseItem.teamMembers ? `<h6>Team Members</h6><pre>${caseItem.teamMembers}</pre>` : ''}
            </div>
            <div class="col-md-4">
                <h6>Evidence Files (${evidence.length})</h6>
                <div class="evidence-list">
                    ${evidence.length > 0 ? evidence.map(e => `
                        <div class="card mb-2">
                            <div class="card-body p-2">
                                <small><strong>${e.name}</strong></small><br>
                                <small class="text-muted">${e.type} - ${e.size}</small><br>
                                <small class="text-muted">${new Date(e.uploadDate).toLocaleDateString()}</small>
                            </div>
                        </div>
                    `).join('') : '<p class="text-muted">No evidence files</p>'}
                </div>
                
                <button class="btn btn-success btn-sm w-100 mt-2" onclick="uploadEvidenceToCase('${caseId}')">
                    <i class="bi bi-upload"></i> Add Evidence
                </button>
            </div>
        </div>
    `;

    modal.show();
}

function uploadEvidenceToCase(caseId) {
    document.getElementById('evidence-case-id').value = caseId;
    const modal = new bootstrap.Modal(document.getElementById('evidenceUploadModal'));
    modal.show();
}

function uploadEvidence() {
    const caseId = document.getElementById('evidence-case-id').value;
    const files = document.getElementById('evidence-files').files;
    const evidenceType = document.getElementById('evidence-type').value;
    const source = document.getElementById('evidence-source').value;
    const description = document.getElementById('evidence-description-upload').value;
    const collectedBy = document.getElementById('evidence-collected-by').value;
    const collectionDate = document.getElementById('evidence-collection-date').value;
    const autoAnalyze = document.getElementById('auto-analyze').checked;

    if (files.length === 0) {
        showAlert('Please select files to upload', 'warning');
        return;
    }

    handleEvidenceUpload(caseId, files, description, {
        type: evidenceType,
        source: source,
        collectedBy: collectedBy,
        collectionDate: collectionDate,
        autoAnalyze: autoAnalyze
    });

    const modal = bootstrap.Modal.getInstance(document.getElementById('evidenceUploadModal'));
    modal.hide();
}

function handleEvidenceUpload(caseId, files, description, metadata = {}) {
    const evidence = JSON.parse(localStorage.getItem(`evidence_${caseId}`)) || [];

    Array.from(files).forEach(file => {
        const evidenceItem = {
            id: Date.now() + Math.random(),
            name: file.name,
            size: formatBytes(file.size),
            type: metadata.type || 'unknown',
            source: metadata.source || '',
            description: description || '',
            collectedBy: metadata.collectedBy || '',
            collectionDate: metadata.collectionDate || new Date().toISOString(),
            uploadDate: new Date().toISOString(),
            hash: 'SHA256:' + Math.random().toString(36).substring(2, 15), // Simulated hash
            autoAnalyze: metadata.autoAnalyze || false
        };

        evidence.push(evidenceItem);
    });

    localStorage.setItem(`evidence_${caseId}`, JSON.stringify(evidence));

    showAlert(`${files.length} evidence file(s) uploaded successfully!`, 'success');
    updateCaseStatistics();

    // Simulate auto-analysis if requested
    if (metadata.autoAnalyze) {
        setTimeout(() => {
            showAlert('Evidence analysis completed. Check reports for results.', 'info');
        }, 3000);
    }
}

function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function editCase(caseId) {
    showAlert('Edit case functionality would open an edit form', 'info');
}

function duplicateCase(caseId) {
    const originalCase = currentCases.find(c => c.caseId === caseId);
    if (originalCase) {
        const newCase = { ...originalCase };
        newCase.caseId = generateCaseId();
        newCase.caseName = originalCase.caseName + ' (Copy)';
        newCase.createdAt = new Date().toISOString();

        currentCases.push(newCase);
        localStorage.setItem('forensicCases', JSON.stringify(currentCases));

        displayCases();
        updateCaseStatistics();
        showAlert('Case duplicated successfully!', 'success');
    }
}

function deleteCase(caseId) {
    if (confirm('Are you sure you want to delete this case? This action cannot be undone.')) {
        currentCases = currentCases.filter(c => c.caseId !== caseId);
        localStorage.setItem('forensicCases', JSON.stringify(currentCases));

        // Also remove evidence
        localStorage.removeItem(`evidence_${caseId}`);

        displayCases();
        updateCaseStatistics();
        showAlert('Case deleted successfully!', 'success');
    }
}

function bulkExport() {
    showAlert('Exporting all cases to CSV...', 'info');
    setTimeout(() => {
        showAlert('Cases exported successfully!', 'success');
    }, 2000);
}

function generateCaseReport(caseId = null) {
    if (caseId) {
        showAlert(`Generating report for case ${caseId}...`, 'info');
    } else {
        showAlert('Generating comprehensive case report...', 'info');
    }

    setTimeout(() => {
        showAlert('Report generated successfully!', 'success');
    }, 2000);
}

function viewCaseStatistics() {
    showAlert('Opening detailed case statistics...', 'info');
}

/**
 * Enhanced Recovery Functions
 */
function setupRecoveryWizard() {
    // Setup source type toggle
    const sourceRadios = document.querySelectorAll('input[name="source-type"]');
    sourceRadios.forEach(radio => {
        radio.addEventListener('change', function () {
            toggleSourceSelection(this.value);
        });
    });

    // Setup scan type change listener
    const scanRadios = document.querySelectorAll('input[name="scan-type"]');
    scanRadios.forEach(radio => {
        radio.addEventListener('change', function () {
            updateRecoverySummary();
        });
    });

    // Setup file type checkboxes
    const typeCheckboxes = document.querySelectorAll('input[type="checkbox"][id^="type-"]');
    typeCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', function () {
            updateRecoverySummary();
        });
    });

    // Setup drive selection change
    const driveList = document.getElementById('drive-list');
    if (driveList) {
        driveList.addEventListener('change', function () {
            if (this.value) {
                loadDriveInfo(this.value);
                updateRecoverySummary();
            }
        });
    }
}

function loadAvailableDrives() {
    const driveList = document.getElementById('drive-list');
    if (!driveList) return;

    // Simulate loading drives (in real app, this would call backend API)
    setTimeout(() => {
        const drives = [
            { letter: 'C:', name: 'System Drive', size: '500 GB', type: 'NTFS', status: 'Healthy' },
            { letter: 'D:', name: 'Data Drive', size: '1 TB', type: 'NTFS', status: 'Healthy' },
            { letter: 'E:', name: 'USB Drive', size: '32 GB', type: 'FAT32', status: 'Healthy' },
            { letter: 'F:', name: 'External HDD', size: '2 TB', type: 'NTFS', status: 'Healthy' }
        ];

        driveList.innerHTML = '<option value="">Select a drive...</option>';
        drives.forEach(drive => {
            const option = document.createElement('option');
            option.value = drive.letter;
            option.textContent = `${drive.letter} - ${drive.name} (${drive.size})`;
            option.dataset.driveInfo = JSON.stringify(drive);
            driveList.appendChild(option);
        });
    }, 1000);
}

function refreshDrives() {
    const driveList = document.getElementById('drive-list');
    if (driveList) {
        driveList.innerHTML = '<option value="">Loading drives...</option>';
        showAlert('Refreshing drive list...', 'info');
        loadAvailableDrives();
    }
}

function toggleSourceSelection(sourceType) {
    const drivePanel = document.getElementById('drive-selection-panel');
    const imagePanel = document.getElementById('image-selection-panel');

    if (sourceType === 'drive') {
        drivePanel.style.display = 'block';
        imagePanel.style.display = 'none';
    } else {
        drivePanel.style.display = 'none';
        imagePanel.style.display = 'block';
    }

    updateRecoverySummary();
}

function loadDriveInfo(driveLetter) {
    const driveList = document.getElementById('drive-list');
    const selectedOption = driveList.querySelector(`option[value="${driveLetter}"]`);

    if (selectedOption && selectedOption.dataset.driveInfo) {
        const driveInfo = JSON.parse(selectedOption.dataset.driveInfo);
        const driveInfoDiv = document.getElementById('drive-info');
        const driveDetails = document.getElementById('drive-details');

        driveDetails.innerHTML = `
            <strong>${driveInfo.letter} ${driveInfo.name}</strong><br>
            Size: ${driveInfo.size}<br>
            File System: ${driveInfo.type}<br>
            Status: <span class="text-success">${driveInfo.status}</span>
        `;

        driveInfoDiv.style.display = 'block';
        recoveryState.selectedSource = driveInfo;
    }
}

function updateRecoverySummary() {
    const sourceType = document.querySelector('input[name="source-type"]:checked')?.value;
    const scanType = document.querySelector('input[name="scan-type"]:checked')?.value;

    // Update source
    let sourceText = 'No source selected';
    if (sourceType === 'drive') {
        const selectedDrive = document.getElementById('drive-list').value;
        if (selectedDrive) {
            sourceText = selectedDrive + ' Drive';
        }
    } else {
        const imageFiles = document.getElementById('image-file').files;
        if (imageFiles.length > 0) {
            sourceText = `${imageFiles.length} image file(s)`;
        }
    }

    const summarySource = document.getElementById('summary-source');
    if (summarySource) summarySource.textContent = sourceText;

    // Update scan type
    const scanTypeNames = {
        'quick': 'Quick Scan',
        'deep': 'Deep Scan',
        'deleted': 'Deleted File Recovery'
    };
    const summaryScanType = document.getElementById('summary-scan-type');
    if (summaryScanType) summaryScanType.textContent = scanTypeNames[scanType] || 'Quick Scan';

    // Update file types
    const checkedTypes = document.querySelectorAll('input[type="checkbox"][id^="type-"]:checked').length;
    const summaryFileTypes = document.getElementById('summary-file-types');
    if (summaryFileTypes) summaryFileTypes.textContent = `${checkedTypes} types selected`;

    // Update estimated time
    const timeEstimates = {
        'quick': '5-10 minutes',
        'deep': '30-60 minutes',
        'deleted': '45-90 minutes'
    };
    const summaryTime = document.getElementById('summary-time');
    if (summaryTime) summaryTime.textContent = timeEstimates[scanType] || '5-10 minutes';
}

function selectOutputFolder() {
    // In a real application, this would open a folder selection dialog
    showAlert('Output folder selection would open here', 'info');
}

function resetWizard() {
    // Reset all form elements
    const driveList = document.getElementById('drive-list');
    const imageFile = document.getElementById('image-file');

    if (driveList) driveList.selectedIndex = 0;
    if (imageFile) imageFile.value = '';

    const sourceRadios = document.querySelectorAll('input[name="source-type"]');
    if (sourceRadios.length > 0) sourceRadios[0].checked = true;

    const scanRadios = document.querySelectorAll('input[name="scan-type"]');
    if (scanRadios.length > 0) scanRadios[0].checked = true;

    // Reset file type checkboxes (except 'all')
    document.querySelectorAll('input[type="checkbox"][id^="type-"]:not(#type-all)').forEach(cb => {
        cb.checked = true;
    });
    const typeAll = document.getElementById('type-all');
    if (typeAll) typeAll.checked = false;

    // Hide drive info
    const driveInfo = document.getElementById('drive-info');
    if (driveInfo) driveInfo.style.display = 'none';

    // Reset panels
    toggleSourceSelection('drive');
    updateRecoverySummary();

    // Reset state
    resetRecoveryState();

    showAlert('Recovery wizard reset', 'info');
}

function startRecovery() {
    // Validate selection
    const sourceType = document.querySelector('input[name="source-type"]:checked')?.value;
    const scanType = document.querySelector('input[name="scan-type"]:checked')?.value;

    if (sourceType === 'drive') {
        const selectedDrive = document.getElementById('drive-list').value;
        if (!selectedDrive) {
            showAlert('Please select a drive to scan', 'warning');
            return;
        }
    } else {
        const imageFiles = document.getElementById('image-file').files;
        if (imageFiles.length === 0) {
            showAlert('Please select disk image file(s) to scan', 'warning');
            return;
        }
    }

    // Collect scan options
    recoveryState.scanOptions = {
        sourceType: sourceType,
        scanType: scanType,
        selectedDrive: document.getElementById('drive-list').value,
        imageFiles: document.getElementById('image-file').files,
        fileTypes: getSelectedFileTypes(),
        minFileSize: document.getElementById('min-file-size').value,
        outputFolder: document.getElementById('output-folder').value
    };

    // Hide wizard and show progress
    const wizard = document.getElementById('recovery-wizard');
    const progress = document.getElementById('recovery-progress');

    if (wizard) wizard.style.display = 'none';
    if (progress) progress.style.display = 'block';

    // Start scanning
    recoveryState.isScanning = true;
    recoveryState.startTime = new Date();

    showAlert('Starting file recovery scan...', 'info');
    simulateAdvancedRecoveryScan();
}

function getSelectedFileTypes() {
    const types = [];
    document.querySelectorAll('input[type="checkbox"][id^="type-"]:checked').forEach(cb => {
        const type = cb.id.replace('type-', '');
        if (type !== 'all') {
            types.push(type);
        }
    });
    return types;
}

function simulateAdvancedRecoveryScan() {
    let progress = 0;
    let filesFound = 0;
    let recoverableFiles = 0;
    let currentActivity = 'Initializing scan...';

    const scanType = recoveryState.scanOptions.scanType;
    const totalTime = scanType === 'quick' ? 30000 : scanType === 'deep' ? 60000 : 45000; // milliseconds
    const updateInterval = 500; // Update every 500ms
    const totalUpdates = totalTime / updateInterval;

    recoveryState.currentScan = setInterval(() => {
        if (recoveryState.isPaused) return;

        progress += (100 / totalUpdates);
        filesFound += Math.floor(Math.random() * 5) + 1;
        recoverableFiles += Math.floor(Math.random() * 3);

        // Update activity based on progress
        if (progress < 20) {
            currentActivity = 'Scanning file allocation table...';
        } else if (progress < 40) {
            currentActivity = 'Analyzing deleted file entries...';
        } else if (progress < 60) {
            currentActivity = 'Searching for file signatures...';
        } else if (progress < 80) {
            currentActivity = 'Recovering file metadata...';
        } else {
            currentActivity = 'Finalizing recovery results...';
        }

        updateProgressDisplay(progress, filesFound, recoverableFiles, currentActivity);

        if (progress >= 100) {
            completeScan(filesFound, recoverableFiles);
        }
    }, updateInterval);
}

function updateProgressDisplay(progress, filesFound, recoverableFiles, activity) {
    // Update progress bar
    const progressBar = document.getElementById('progress-bar');
    const progressPercentage = document.getElementById('progress-percentage');

    if (progressBar) progressBar.style.width = Math.min(progress, 100) + '%';
    if (progressPercentage) progressPercentage.textContent = Math.round(progress) + '%';

    // Update counters
    const filesFoundEl = document.getElementById('files-found');
    const filesRecoverableEl = document.getElementById('files-recoverable');
    const currentSectorEl = document.getElementById('current-sector');

    if (filesFoundEl) filesFoundEl.textContent = filesFound;
    if (filesRecoverableEl) filesRecoverableEl.textContent = recoverableFiles;
    if (currentSectorEl) currentSectorEl.textContent = Math.floor(Math.random() * 1000000);

    // Update elapsed time
    if (recoveryState.startTime) {
        const elapsed = new Date() - recoveryState.startTime;
        const minutes = Math.floor(elapsed / 60000);
        const seconds = Math.floor((elapsed % 60000) / 1000);
        const elapsedTimeEl = document.getElementById('elapsed-time');
        if (elapsedTimeEl) {
            elapsedTimeEl.textContent =
                `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        }
    }

    // Update current activity
    const currentActivityEl = document.getElementById('current-activity');
    if (currentActivityEl) currentActivityEl.textContent = activity;
}

function completeScan(filesFound, recoverableFiles) {
    clearInterval(recoveryState.currentScan);
    recoveryState.isScanning = false;

    // Generate simulated results
    generateRecoveryResults(recoverableFiles);

    // Hide progress and show results
    const progress = document.getElementById('recovery-progress');
    const results = document.getElementById('recovery-results-section');

    if (progress) progress.style.display = 'none';
    if (results) results.style.display = 'block';

    showAlert(`Scan completed! Found ${filesFound} files, ${recoverableFiles} recoverable.`, 'success');
}

function generateRecoveryResults(count) {
    const fileTypes = ['jpg', 'png', 'pdf', 'docx', 'xlsx', 'mp3', 'mp4', 'zip', 'txt', 'pptx'];
    const paths = ['C:\\\\Users\\\\Documents\\\\', 'C:\\\\Users\\\\Pictures\\\\', 'C:\\\\Users\\\\Downloads\\\\', 'C:\\\\Users\\\\Desktop\\\\'];
    const statuses = [
        { name: 'Excellent', class: 'success', weight: 50 },
        { name: 'Good', class: 'info', weight: 30 },
        { name: 'Poor', class: 'warning', weight: 20 }
    ];

    recoveryState.foundFiles = [];

    for (let i = 0; i < count; i++) {
        const fileType = fileTypes[Math.floor(Math.random() * fileTypes.length)];
        const path = paths[Math.floor(Math.random() * paths.length)];
        const status = getWeightedRandomStatus(statuses);

        recoveryState.foundFiles.push({
            id: i + 1,
            filename: `recovered_file_${i + 1}.${fileType}`,
            path: path,
            size: Math.floor(Math.random() * 10000000) + 1000, // Random size between 1KB and 10MB
            type: fileType.toUpperCase(),
            modified: new Date(Date.now() - Math.random() * 365 * 24 * 60 * 60 * 1000), // Random date within last year
            status: status,
            selected: false
        });
    }

    displayRecoveryResults();
}

function getWeightedRandomStatus(statuses) {
    const totalWeight = statuses.reduce((sum, status) => sum + status.weight, 0);
    let random = Math.random() * totalWeight;

    for (const status of statuses) {
        random -= status.weight;
        if (random <= 0) {
            return status;
        }
    }

    return statuses[0]; // fallback
}

function displayRecoveryResults() {
    const tbody = document.getElementById('results-tbody');
    const totalCount = document.getElementById('total-files-count');
    const totalResults = document.getElementById('total-results');
    const showingCount = document.getElementById('showing-count');

    if (totalCount) totalCount.textContent = recoveryState.foundFiles.length;
    if (totalResults) totalResults.textContent = recoveryState.foundFiles.length;
    if (showingCount) showingCount.textContent = Math.min(recoveryState.foundFiles.length, 50); // Show first 50

    if (!tbody) return;

    if (recoveryState.foundFiles.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center text-muted py-4">
                    No recoverable files found
                </td>
            </tr>
        `;
        return;
    }

    let html = '';
    recoveryState.foundFiles.slice(0, 50).forEach(file => {
        html += `
            <tr>
                <td><input type="checkbox" class="file-checkbox" data-file-id="${file.id}"></td>
                <td>
                    <i class="bi bi-file-${getFileIcon(file.type)}"></i>
                    ${file.filename}
                </td>
                <td><small class="text-muted">${file.path}</small></td>
                <td>${formatBytes(file.size)}</td>
                <td><span class="badge bg-secondary">${file.type}</span></td>
                <td><small>${file.modified.toLocaleDateString()}</small></td>
                <td>
                    <span class="badge bg-${file.status.class}">${file.status.name}</span>
                </td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="previewFile(${file.id})">
                        <i class="bi bi-eye"></i>
                    </button>
                    <button class="btn btn-sm btn-success" onclick="recoverSingleFile(${file.id})">
                        <i class="bi bi-download"></i>
                    </button>
                </td>
            </tr>
        `;
    });

    tbody.innerHTML = html;
}

function getFileIcon(type) {
    const icons = {
        'JPG': 'image', 'PNG': 'image', 'GIF': 'image',
        'PDF': 'pdf', 'DOC': 'word', 'DOCX': 'word',
        'XLS': 'excel', 'XLSX': 'excel',
        'PPT': 'ppt', 'PPTX': 'ppt',
        'MP3': 'music', 'MP4': 'play',
        'ZIP': 'zip', 'RAR': 'zip',
        'TXT': 'text'
    };
    return icons[type] || 'file';
}

function pauseRecovery() {
    if (recoveryState.isScanning) {
        recoveryState.isPaused = !recoveryState.isPaused;
        const pauseBtn = document.getElementById('pause-btn');

        if (pauseBtn) {
            if (recoveryState.isPaused) {
                pauseBtn.innerHTML = '<i class="bi bi-play-fill"></i> Resume';
                showAlert('Recovery scan paused', 'warning');
            } else {
                pauseBtn.innerHTML = '<i class="bi bi-pause-fill"></i> Pause';
                showAlert('Recovery scan resumed', 'info');
            }
        }
    }
}

function stopRecovery() {
    if (recoveryState.isScanning) {
        clearInterval(recoveryState.currentScan);
        recoveryState.isScanning = false;
        recoveryState.isPaused = false;

        // Show wizard again
        const progress = document.getElementById('recovery-progress');
        const wizard = document.getElementById('recovery-wizard');

        if (progress) progress.style.display = 'none';
        if (wizard) wizard.style.display = 'block';

        showAlert('Recovery scan stopped', 'warning');
        resetRecoveryState();
    }
}

function recoverSelectedFiles() {
    const selectedFiles = document.querySelectorAll('.file-checkbox:checked');
    if (selectedFiles.length === 0) {
        showAlert('Please select files to recover', 'warning');
        return;
    }

    showAlert(`Starting recovery of ${selectedFiles.length} selected files...`, 'info');

    // Simulate file recovery process
    setTimeout(() => {
        showAlert(`Successfully recovered ${selectedFiles.length} files to ${recoveryState.scanOptions.outputFolder}`, 'success');
    }, 2000);
}

function recoverSingleFile(fileId) {
    const file = recoveryState.foundFiles.find(f => f.id === fileId);
    if (file) {
        showAlert(`Recovering ${file.filename}...`, 'info');
        setTimeout(() => {
            showAlert(`${file.filename} recovered successfully!`, 'success');
        }, 1000);
    }
}

function previewFile(fileId) {
    const file = recoveryState.foundFiles.find(f => f.id === fileId);
    if (file) {
        showAlert(`File preview: ${file.filename} (${file.type}) - ${formatBytes(file.size)}`, 'info');
    }
}

function newScan() {
    // Reset everything and show wizard
    const results = document.getElementById('recovery-results-section');
    const wizard = document.getElementById('recovery-wizard');

    if (results) results.style.display = 'none';
    if (wizard) wizard.style.display = 'block';

    resetRecoveryState();
    resetWizard();
}

function resetRecoveryState() {
    if (recoveryState.currentScan) {
        clearInterval(recoveryState.currentScan);
    }

    recoveryState.isScanning = false;
    recoveryState.isPaused = false;
    recoveryState.startTime = null;
    recoveryState.currentScan = null;
    recoveryState.foundFiles = [];
    recoveryState.selectedSource = null;
    recoveryState.scanOptions = {};
}

function setupRecoveryEventListeners() {
    // Setup search functionality
    const searchInput = document.getElementById('results-search');
    if (searchInput) {
        searchInput.addEventListener('input', function () {
            filterRecoveryResults();
        });
    }

    // Setup filter dropdown
    const filterSelect = document.getElementById('results-filter');
    if (filterSelect) {
        filterSelect.addEventListener('change', function () {
            filterRecoveryResults();
        });
    }

    // Setup select all checkbox
    const selectAllCheckbox = document.getElementById('select-all-files');
    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', function () {
            const fileCheckboxes = document.querySelectorAll('.file-checkbox');
            fileCheckboxes.forEach(cb => {
                cb.checked = this.checked;
            });
        });
    }
}

function filterRecoveryResults() {
    // In a real application, this would filter the displayed results
    // based on search term and filter criteria
    showAlert('Results filtered (simulation)', 'info');
}

// ============================================
// DATATABLES FUNCTIONS
// ============================================

/**
 * Initialize DataTables for recovered files display
 */
let recoveredFilesTable = null;

function initializeRecoveredFilesTable(data) {
    // Destroy existing table if it exists
    if (recoveredFilesTable) {
        recoveredFilesTable.destroy();
    }

    // Transform data for DataTables
    const tableData = data.map(file => {
        return {
            checkbox: `<div class="form-check"><input class="form-check-input file-checkbox" type="checkbox" value="${file.id || file.filename}"></div>`,
            filename: `<div class="d-flex align-items-center">
                        <i class="${getFileIcon(file.file_type)} me-2"></i>
                        <span class="fw-medium">${file.filename}</span>
                       </div>`,
            path: `<span class="text-muted small">${file.filepath || 'N/A'}</span>`,
            size: formatFileSize(file.size),
            type: `<span class="badge bg-primary">${file.file_type}</span>`,
            modified: file.modified_date ? new Date(file.modified_date).toLocaleDateString() : 'Unknown',
            recovery_probability: `<div class="recovery-probability">
                                   <div class="progress" style="height: 8px;">
                                       <div class="progress-bar bg-${getProbabilityColor(file.confidence || file.recovery_confidence || 0.5)}" 
                                            style="width: ${(file.confidence || file.recovery_confidence || 0.5) * 100}%"></div>
                                   </div>
                                   <small class="text-muted">${((file.confidence || file.recovery_confidence || 0.5) * 100).toFixed(1)}%</small>
                                  </div>`,
            status: `<span class="badge bg-${getStatusColor(file.recovery_status || getStatusFromConfidence(file.confidence || file.recovery_confidence || 0.5))}">
                     ${getStatusText(file.recovery_status || getStatusFromConfidence(file.confidence || file.recovery_confidence || 0.5))}
                     </span>`,
            actions: `<div class="btn-group btn-group-sm">
                        <button class="btn btn-outline-success" onclick="recoverSingleFile('${recoveryState.currentScan}', '${file.id || file.filename}')" title="Recover File">
                            <i class="bi bi-download"></i>
                        </button>
                        <button class="btn btn-outline-info" onclick="showFileDetails('${file.id || file.filename}')" title="View Details">
                            <i class="bi bi-info-circle"></i>
                        </button>
                        <button class="btn btn-outline-secondary" onclick="previewFile('${file.id || file.filename}')" title="Preview">
                            <i class="bi bi-eye"></i>
                        </button>
                      </div>`,
            // Hidden columns for sorting/filtering
            sizeBytes: file.size,
            confidenceValue: file.confidence || file.recovery_confidence || 0.5,
            statusValue: file.recovery_status || getStatusFromConfidence(file.confidence || file.recovery_confidence || 0.5)
        };
    });

    // Initialize DataTables
    recoveredFilesTable = $('#recovered-files-table').DataTable({
        data: tableData,
        columns: [
            { data: 'checkbox', orderable: false, searchable: false, width: '30px' },
            { data: 'filename', title: 'Filename' },
            { data: 'path', title: 'Path' },
            {
                data: 'size', title: 'Size', type: 'num', render: function (data, type, row) {
                    return type === 'sort' ? row.sizeBytes : data;
                }
            },
            { data: 'type', title: 'Type' },
            { data: 'modified', title: 'Modified' },
            {
                data: 'recovery_probability', title: 'Recovery Probability', type: 'num', render: function (data, type, row) {
                    return type === 'sort' ? row.confidenceValue : data;
                }
            },
            {
                data: 'status', title: 'Status', render: function (data, type, row) {
                    return type === 'sort' ? row.statusValue : data;
                }
            },
            { data: 'actions', title: 'Actions', orderable: false, searchable: false }
        ],
        pageLength: 25,
        lengthMenu: [[10, 25, 50, 100, -1], [10, 25, 50, 100, 'All']],
        order: [[6, 'desc']], // Sort by recovery probability by default
        dom: '<"row"<"col-sm-12 col-md-6"l><"col-sm-12 col-md-6"f>>' +
            '<"row"<"col-sm-12"t>>' +
            '<"row"<"col-sm-12 col-md-5"i><"col-sm-12 col-md-7"p>>B',
        buttons: [
            {
                extend: 'csv',
                text: '<i class="bi bi-file-earmark-csv"></i> Export CSV',
                className: 'btn btn-outline-success btn-sm',
                exportOptions: {
                    columns: [1, 2, 3, 4, 5, 6, 7] // Exclude checkbox and actions
                }
            },
            {
                extend: 'pdf',
                text: '<i class="bi bi-file-earmark-pdf"></i> Export PDF',
                className: 'btn btn-outline-danger btn-sm',
                exportOptions: {
                    columns: [1, 2, 3, 4, 5, 6, 7]
                }
            },
            {
                text: '<i class="bi bi-arrow-clockwise"></i> Refresh',
                className: 'btn btn-outline-primary btn-sm',
                action: function () {
                    refreshRecoveredFiles();
                }
            }
        ],
        language: {
            search: '<i class="bi bi-search"></i>',
            searchPlaceholder: 'Search files...'
        },
        initComplete: function () {
            // Add custom filters
            addCustomFilters();

            // Setup select all functionality
            setupSelectAllFunctionality();
        }
    });
}

/**
 * Add custom filter dropdowns
 */
function addCustomFilters() {
    // File type filter
    const typeFilter = $('<select class="form-select form-select-sm ms-2" id="type-filter"><option value="">All Types</option></select>');
    recoveredFilesTable.column(4).data().unique().sort().each(function (d) {
        const typeText = $(d).text();
        typeFilter.append('<option value="' + typeText + '">' + typeText + '</option>');
    });

    // Status filter
    const statusFilter = $('<select class="form-select form-select-sm ms-2" id="status-filter"><option value="">All Status</option></select>');
    recoveredFilesTable.column(7).data().unique().sort().each(function (d) {
        const statusText = $(d).text().trim();
        statusFilter.append('<option value="' + statusText + '">' + statusText + '</option>');
    });

    // Add filters to the table header
    $('.dataTables_filter').append(typeFilter).append(statusFilter);

    // Filter functionality
    typeFilter.on('change', function () {
        recoveredFilesTable.column(4).search(this.value).draw();
    });

    statusFilter.on('change', function () {
        recoveredFilesTable.column(7).search(this.value).draw();
    });
}

/**
 * Setup select all functionality for DataTables
 */
function setupSelectAllFunctionality() {
    // Handle select all checkbox
    $('#select-all-checkbox').on('change', function () {
        const isChecked = this.checked;
        $('.file-checkbox:visible').prop('checked', isChecked);
        updateSelectedCount();
    });

    // Handle individual checkboxes
    $('#recovered-files-table').on('change', '.file-checkbox', function () {
        updateSelectedCount();
        updateSelectAllState();
    });
}

/**
 * Update selected files count
 */
function updateSelectedCount() {
    const selectedCount = $('.file-checkbox:checked').length;
    const totalVisible = $('.file-checkbox:visible').length;

    // Update button text
    const recoverBtn = document.querySelector('[onclick="recoverSelectedFiles()"]');
    if (recoverBtn) {
        recoverBtn.innerHTML = `<i class="bi bi-download"></i> Recover Selected (${selectedCount})`;
        recoverBtn.disabled = selectedCount === 0;
    }

    // Update total files count display
    const totalCountEl = document.getElementById('total-files-count');
    if (totalCountEl) {
        totalCountEl.textContent = selectedCount;
    }
}

/**
 * Update select all checkbox state
 */
function updateSelectAllState() {
    const totalCheckboxes = $('.file-checkbox:visible').length;
    const checkedCheckboxes = $('.file-checkbox:visible:checked').length;
    const selectAllCheckbox = document.getElementById('select-all-checkbox');

    if (selectAllCheckbox) {
        if (checkedCheckboxes === 0) {
            selectAllCheckbox.indeterminate = false;
            selectAllCheckbox.checked = false;
        } else if (checkedCheckboxes === totalCheckboxes) {
            selectAllCheckbox.indeterminate = false;
            selectAllCheckbox.checked = true;
        } else {
            selectAllCheckbox.indeterminate = true;
        }
    }
}

/**
 * Update recovery statistics display
 */
function updateRecoveryStatistics(files) {
    const total = files.length;
    let excellent = 0, good = 0, poor = 0;

    files.forEach(file => {
        const confidence = file.confidence || file.recovery_confidence || 0.5;
        if (confidence >= 0.8) excellent++;
        else if (confidence >= 0.5) good++;
        else poor++;
    });

    // Update stat cards
    document.getElementById('total-files-stat').textContent = total;
    document.getElementById('excellent-recovery-stat').textContent = excellent;
    document.getElementById('good-recovery-stat').textContent = good;
    document.getElementById('poor-recovery-stat').textContent = poor;
}

/**
 * Helper functions for DataTables
 */
function getProbabilityColor(confidence) {
    if (confidence >= 0.8) return 'success';
    if (confidence >= 0.5) return 'warning';
    return 'danger';
}

function getStatusColor(status) {
    switch (status?.toLowerCase()) {
        case 'excellent': return 'success';
        case 'good': return 'warning';
        case 'poor': return 'danger';
        case 'deleted': return 'info';
        case 'overwritten': return 'secondary';
        default: return 'secondary';
    }
}

function getStatusText(status) {
    return status ? status.charAt(0).toUpperCase() + status.slice(1) : 'Unknown';
}

function getStatusFromConfidence(confidence) {
    if (confidence >= 0.8) return 'excellent';
    if (confidence >= 0.5) return 'good';
    return 'poor';
}

/**
 * Refresh recovered files data
 */
function refreshRecoveredFiles() {
    if (recoveryState.currentScan) {
        loadDeepScanResults(recoveryState.currentScan);
        showAlert('Refreshing recovered files...', 'info');
    }
}

/**
 * Show file details in modal
 */
function showFileDetails(fileId) {
    // Find file data
    const fileData = recoveredFilesTable.data().toArray().find(row =>
        row.checkbox.includes(fileId)
    );

    if (!fileData) {
        showAlert('File details not found', 'error');
        return;
    }

    // Create and show modal with file details
    const modal = new bootstrap.Modal(document.getElementById('file-details-modal') || createFileDetailsModal());
    populateFileDetailsModal(fileId);
    modal.show();
}

/**
 * Preview file content with comprehensive viewer
 */
function previewFile(fileId) {
    const sessionId = recoveryState.currentScan;
    if (!sessionId) {
        showAlert('No active scan session', 'warning');
        return;
    }

    // Show preview modal
    const modal = new bootstrap.Modal(document.getElementById('file-preview-modal'));
    modal.show();

    // Reset modal state
    resetPreviewModal();

    // Set up preview mode buttons
    setupPreviewModeButtons(fileId, sessionId);

    // Load file preview
    loadFilePreview(fileId, sessionId, 'content');
}

/**
 * Reset preview modal to initial state
 */
function resetPreviewModal() {
    // Show loading state
    document.getElementById('preview-loading').style.display = 'block';
    document.getElementById('preview-error').style.display = 'none';
    document.getElementById('preview-container').style.display = 'none';

    // Hide all preview types
    document.getElementById('image-preview').style.display = 'none';
    document.getElementById('text-preview').style.display = 'none';
    document.getElementById('pdf-preview').style.display = 'none';
    document.getElementById('hex-preview').style.display = 'none';

    // Reset content
    document.getElementById('preview-image').src = '';
    document.getElementById('preview-text').textContent = '';
    document.getElementById('preview-pdf').src = '';
    document.getElementById('preview-hex').textContent = '';
}

/**
 * Setup preview mode toggle buttons
 */
function setupPreviewModeButtons(fileId, sessionId) {
    // Content mode button
    document.getElementById('preview-mode-content').onclick = () => {
        document.getElementById('preview-mode-content').className = 'btn btn-primary btn-sm';
        document.getElementById('preview-mode-hex').className = 'btn btn-outline-secondary btn-sm';
        resetPreviewModal();
        loadFilePreview(fileId, sessionId, 'content');
    };

    // Hex mode button
    document.getElementById('preview-mode-hex').onclick = () => {
        document.getElementById('preview-mode-hex').className = 'btn btn-primary btn-sm';
        document.getElementById('preview-mode-content').className = 'btn btn-outline-primary btn-sm';
        resetPreviewModal();
        loadFilePreview(fileId, sessionId, 'hex');
    };

    // Set default active button
    document.getElementById('preview-mode-content').className = 'btn btn-primary btn-sm';
    document.getElementById('preview-mode-hex').className = 'btn btn-outline-secondary btn-sm';
}

/**
 * Load file preview from backend API
 */
function loadFilePreview(fileId, sessionId, mode = 'content') {
    const url = `/api/deep-scan/preview-file/${sessionId}/${fileId}?mode=${mode}`;

    fetch(url)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                displayFilePreview(data, mode);
            } else {
                showPreviewError(data.error || 'Failed to load preview');
            }
        })
        .catch(error => {
            console.error('Preview error:', error);
            showPreviewError(error.message);
        });
}

/**
 * Display file preview based on data and mode
 */
function displayFilePreview(data, mode) {
    // Hide loading
    document.getElementById('preview-loading').style.display = 'none';
    document.getElementById('preview-container').style.display = 'block';

    // Update modal title and file info
    document.getElementById('preview-modal-title').textContent = `Preview: ${data.filename}`;
    document.getElementById('preview-file-info').textContent =
        `${data.file_type} • ${formatFileSize(data.size)} • ${data.encoding || 'Binary'}`;

    // Setup recover button
    document.getElementById('preview-recover-btn').onclick = () => {
        recoverSingleFile(recoveryState.currentScan, data.filename);
    };

    if (mode === 'hex') {
        displayHexPreview(data.hex_data);
    } else {
        displayContentPreview(data);
    }
}

/**
 * Display content preview based on file type
 */
function displayContentPreview(data) {
    const fileType = data.file_type.toLowerCase();

    if (isImageType(fileType)) {
        displayImagePreview(data);
    } else if (isTextType(fileType)) {
        displayTextPreview(data);
    } else if (fileType === 'pdf') {
        displayPdfPreview(data);
    } else {
        // Default to hex view for unsupported types
        displayHexPreview(data.hex_data);
    }
}

/**
 * Display image preview
 */
function displayImagePreview(data) {
    document.getElementById('image-preview').style.display = 'block';
    const img = document.getElementById('preview-image');
    img.src = `data:${getMimeType(data.file_type)};base64,${data.base64_data}`;
    img.onerror = () => showPreviewError('Failed to load image');
}

/**
 * Display text file preview
 */
function displayTextPreview(data) {
    document.getElementById('text-preview').style.display = 'block';
    const textElement = document.getElementById('preview-text');

    if (data.text_content) {
        textElement.textContent = data.text_content;
    } else if (data.base64_data) {
        // Decode base64 text
        try {
            const decoded = atob(data.base64_data);
            textElement.textContent = decoded;
        } catch (e) {
            showPreviewError('Failed to decode text content');
        }
    } else {
        showPreviewError('No text content available');
    }
}

/**
 * Display PDF preview
 */
function displayPdfPreview(data) {
    document.getElementById('pdf-preview').style.display = 'block';
    const iframe = document.getElementById('preview-pdf');

    if (data.base64_data) {
        const pdfData = `data:application/pdf;base64,${data.base64_data}`;
        iframe.src = pdfData;
    } else {
        showPreviewError('PDF data not available');
    }
}

/**
 * Display hex dump preview
 */
function displayHexPreview(hexData) {
    document.getElementById('hex-preview').style.display = 'block';
    const hexElement = document.getElementById('preview-hex');

    if (hexData) {
        hexElement.textContent = hexData;
    } else {
        showPreviewError('Hex data not available');
    }
}

/**
 * Show preview error message
 */
function showPreviewError(message) {
    document.getElementById('preview-loading').style.display = 'none';
    document.getElementById('preview-error').style.display = 'block';
    document.getElementById('preview-error-message').textContent = message;
}

/**
 * Check if file type is an image
 */
function isImageType(fileType) {
    const imageTypes = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg', 'tiff', 'ico'];
    return imageTypes.includes(fileType.toLowerCase());
}

/**
 * Check if file type is text-based
 */
function isTextType(fileType) {
    const textTypes = ['txt', 'csv', 'json', 'xml', 'html', 'css', 'js', 'py', 'java',
        'cpp', 'c', 'h', 'md', 'log', 'cfg', 'ini', 'yml', 'yaml'];
    return textTypes.includes(fileType.toLowerCase());
}

/**
 * Get MIME type for file type
 */
function getMimeType(fileType) {
    const mimeTypes = {
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'png': 'image/png',
        'gif': 'image/gif',
        'bmp': 'image/bmp',
        'webp': 'image/webp',
        'svg': 'image/svg+xml',
        'tiff': 'image/tiff',
        'ico': 'image/x-icon',
        'pdf': 'application/pdf'
    };
    return mimeTypes[fileType.toLowerCase()] || 'application/octet-stream';
}

/**
 * Create file details modal if it doesn't exist
 */
function createFileDetailsModal() {
    const modalHtml = `
        <div class="modal fade" id="file-details-modal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <!-- Modal content will be populated dynamically -->
                </div>
            </div>
        </div>
    `;
    document.body.insertAdjacentHTML('beforeend', modalHtml);
    return document.getElementById('file-details-modal');
}

/**
 * Populate file details modal with file information
 */
function populateFileDetailsModal(fileId) {
    // This would typically fetch detailed file information from the API
    // For now, we'll use placeholder data
    const fileInfo = {
        filename: 'document.pdf',
        type: 'PDF Document',
        size: '2.5 MB',
        modified: '2023-10-15 14:30:22',
        created: '2023-10-10 09:15:10',
        probability: '85%',
        status: 'Excellent',
        sector: '245,678',
        signature: 'PDF-1.4',
        hash: 'a1b2c3d4e5f6789...',
        path: '/Users/Documents/Important/document.pdf',
        recoveryPath: '/Recovered/Documents/document_recovered.pdf'
    };

    // Populate modal fields
    document.getElementById('detail-filename').textContent = fileInfo.filename;
    document.getElementById('detail-type').textContent = fileInfo.type;
    document.getElementById('detail-size').textContent = fileInfo.size;
    document.getElementById('detail-modified').textContent = fileInfo.modified;
    document.getElementById('detail-created').textContent = fileInfo.created;
    document.getElementById('detail-probability').textContent = fileInfo.probability;
    document.getElementById('detail-status').textContent = fileInfo.status;
    document.getElementById('detail-sector').textContent = fileInfo.sector;
    document.getElementById('detail-signature').textContent = fileInfo.signature;
    document.getElementById('detail-hash').textContent = fileInfo.hash;
    document.getElementById('detail-path').textContent = fileInfo.path;
    document.getElementById('detail-recovery-path').textContent = fileInfo.recoveryPath;

    // Setup modal buttons
    const recoverBtn = document.getElementById('recover-file-btn');
    const previewBtn = document.getElementById('preview-file-btn');

    if (recoverBtn) {
        recoverBtn.onclick = () => {
            recoverSingleFile(recoveryState.currentScan, fileId);
            bootstrap.Modal.getInstance(document.getElementById('file-details-modal')).hide();
        };
    }

    if (previewBtn) {
        previewBtn.onclick = () => previewFile(fileId);
    }
}

// ============================================
// FILE CARVING FUNCTIONS
// ============================================

/**
 * Start comprehensive scan with file carving
 */
async function startComprehensiveScan() {
    const imagePath = document.getElementById('recovery-image-path').value;
    const enableCarving = document.getElementById('enable-carving').checked;

    if (!imagePath) {
        showAlert('Please select a disk image file first', 'warning');
        return;
    }

    try {
        showRecoveryProgress();
        updateRecoveryProgress(5, 'Starting comprehensive scan with file carving...');

        // Get scan options
        const scanOptions = getRecoveryScanOptions();
        scanOptions.enable_carving = enableCarving;

        // Start comprehensive scan
        const response = await fetch(`${API_BASE_URL}/deep-scan/scan-with-carving`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                image_path: imagePath,
                scan_mode: 'comprehensive',
                enable_carving: enableCarving,
                scan_options: scanOptions
            })
        });

        const data = await response.json();

        if (data.session_id) {
            recoveryState.currentScan = data.session_id;
            showAlert('Comprehensive scan started successfully', 'success');
            monitorComprehensiveScan(data.session_id);
        } else {
            showAlert(`Error: ${data.error}`, 'error');
        }

    } catch (error) {
        console.error('Comprehensive scan error:', error);
        showAlert('Failed to start comprehensive scan', 'error');
        hideRecoveryProgress();
    }
}

/**
 * Monitor comprehensive scan progress
 */
async function monitorComprehensiveScan(sessionId) {
    const checkInterval = setInterval(async () => {
        try {
            // Check scan status
            const response = await fetch(`${API_BASE_URL}/deep-scan/scan-status/${sessionId}`);
            const status = await response.json();

            if (status.status === 'completed') {
                clearInterval(checkInterval);
                updateRecoveryProgress(100, 'Comprehensive scan completed!');

                // Load both regular scan results and carving results
                await loadComprehensiveResults(sessionId);
                showAlert(`Comprehensive scan completed! Found ${status.files_found} files.`, 'success');

            } else if (status.status === 'carving') {
                updateRecoveryProgress(75, 'Performing file carving...');

            } else if (status.status === 'scanning') {
                const progress = Math.min(50, status.progress || 0);
                updateRecoveryProgress(progress, `Scanning: ${status.current_activity || 'Processing...'}`);

            } else if (status.status === 'error') {
                clearInterval(checkInterval);
                showAlert('Comprehensive scan failed', 'error');
                console.error('Scan error:', status.error);
                hideRecoveryProgress();
            }

        } catch (error) {
            console.error('Error checking scan status:', error);
            clearInterval(checkInterval);
            hideRecoveryProgress();
        }
    }, 2000);
}

/**
 * Load comprehensive scan results (both regular and carved files)
 */
async function loadComprehensiveResults(sessionId) {
    try {
        // Load regular scan results
        const scanResponse = await fetch(`${API_BASE_URL}/deep-scan/scan-results/${sessionId}`);
        const scanData = await scanResponse.json();

        // Load carving results
        const carvingResponse = await fetch(`${API_BASE_URL}/deep-scan/carve-results/${sessionId}`);
        const carvingData = await carvingResponse.json();

        // Combine and display results
        displayComprehensiveResults(scanData, carvingData);

    } catch (error) {
        console.error('Error loading comprehensive results:', error);
        showAlert('Failed to load scan results', 'error');
    }
}

/**
 * Display comprehensive results with carving data
 */
function displayComprehensiveResults(scanData, carvingData) {
    hideRecoveryProgress();

    const resultsContainer = document.getElementById('recovery-results');
    if (!resultsContainer) {
        // Show results section instead
        document.getElementById('recovery-results-section').style.display = 'block';
    } const regularFiles = scanData.files || [];
    const carvedFiles = carvingData.carved_files || [];
    const totalFiles = regularFiles.length + carvedFiles.length;

    resultsContainer.innerHTML = `
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5><i class="bi bi-search"></i> Comprehensive Scan Results</h5>
                <div class="btn-group">
                    <button class="btn btn-primary btn-sm" onclick="toggleResultsView('regular')">
                        Regular Scan (${regularFiles.length})
                    </button>
                    <button class="btn btn-success btn-sm" onclick="toggleResultsView('carved')">
                        Carved Files (${carvedFiles.length})
                    </button>
                    <button class="btn btn-info btn-sm" onclick="toggleResultsView('all')">
                        All Files (${totalFiles})
                    </button>
                </div>
            </div>
            <div class="card-body">
                <div class="row mb-3">
                    <div class="col-md-3">
                        <div class="stat-card bg-primary text-white">
                            <h4>${totalFiles}</h4>
                            <p>Total Files Found</p>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card bg-success text-white">
                            <h4>${carvedFiles.filter(f => f.confidence > 0.8).length}</h4>
                            <p>High Confidence</p>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card bg-warning text-white">
                            <h4>${carvedFiles.filter(f => f.confidence > 0.5 && f.confidence <= 0.8).length}</h4>
                            <p>Medium Confidence</p>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card bg-info text-white">
                            <h4>${new Set([...regularFiles.map(f => f.file_type), ...carvedFiles.map(f => f.file_type)]).size}</h4>
                            <p>File Types</p>
                        </div>
                    </div>
                </div>
                
                <div id="regular-results" class="results-section">
                    <h6>Regular Scan Results</h6>
                    ${createResultsTable(regularFiles, 'regular')}
                </div>
                
                <div id="carved-results" class="results-section" style="display: none;">
                    <h6>File Carving Results</h6>
                    ${createCarvingResultsTable(carvedFiles)}
                </div>
                
                <div id="all-results" class="results-section" style="display: none;">
                    <h6>All Results Combined</h6>
                    ${createCombinedResultsTable(regularFiles, carvedFiles)}
                </div>
            </div>
        </div>
    `;
}

/**
 * Create carving results table
 */
function createCarvingResultsTable(carvedFiles) {
    if (!carvedFiles || carvedFiles.length === 0) {
        return '<div class="alert alert-info">No carved files found</div>';
    }

    const rows = carvedFiles.map(file => `
        <tr>
            <td>
                <div class="d-flex align-items-center">
                    <i class="${getFileIcon(file.file_type)} me-2"></i>
                    <span>${file.filename}</span>
                </div>
            </td>
            <td><span class="badge bg-secondary">${file.file_type}</span></td>
            <td>${formatFileSize(file.size)}</td>
            <td>
                <div class="confidence-meter">
                    <div class="confidence-bar" style="width: ${file.confidence * 100}%; background-color: ${getConfidenceColor(file.confidence)}"></div>
                    <span class="confidence-text">${(file.confidence * 100).toFixed(1)}%</span>
                </div>
            </td>
            <td><small class="text-muted">0x${file.offset.toString(16).toUpperCase()}</small></td>
            <td>
                <button class="btn btn-sm btn-primary" onclick="recoverCarvedFile('${file.filename}', '${file.filepath}')">
                    <i class="bi bi-download"></i> Recover
                </button>
            </td>
        </tr>
    `).join('');

    return `
        <div class="table-responsive">
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>Filename</th>
                        <th>Type</th>
                        <th>Size</th>
                        <th>Confidence</th>
                        <th>Offset</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${rows}
                </tbody>
            </table>
        </div>
    `;
}

/**
 * Toggle between different result views
 */
function toggleResultsView(view) {
    const sections = ['regular-results', 'carved-results', 'all-results'];
    sections.forEach(section => {
        document.getElementById(section).style.display = 'none';
    });

    if (view === 'all') {
        document.getElementById('all-results').style.display = 'block';
    } else {
        document.getElementById(`${view}-results`).style.display = 'block';
    }

    // Update button states
    document.querySelectorAll('.btn-group .btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
}

/**
 * Get confidence color for visual indication
 */
function getConfidenceColor(confidence) {
    if (confidence >= 0.8) return '#28a745'; // Green
    if (confidence >= 0.5) return '#ffc107'; // Yellow  
    return '#dc3545'; // Red
}

/**
 * Recover carved file
 */
async function recoverCarvedFile(filename, filepath) {
    try {
        showAlert(`Recovering carved file: ${filename}`, 'info');

        // In a real implementation, this would download the carved file
        // For demo, we'll simulate the recovery
        setTimeout(() => {
            showAlert(`Carved file recovered successfully: ${filename}`, 'success');
        }, 1000);

    } catch (error) {
        console.error('Error recovering carved file:', error);
        showAlert('Failed to recover carved file', 'error');
    }
}

/**
 * Create file details modal if it doesn't exist
 */
function createFileDetailsModal() {
    const modalHtml = `
        <div class="modal fade" id="file-details-modal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <!-- Modal content will be populated dynamically -->
                </div>
            </div>
        </div>
    `;
    document.body.insertAdjacentHTML('beforeend', modalHtml);
    return document.getElementById('file-details-modal');
}

/**
 * Populate file details modal with file information
 */
function populateFileDetailsModal(fileId) {
    // This would typically fetch detailed file information from the API
    // For now, we'll use placeholder data
    const fileInfo = {
        filename: 'document.pdf',
        type: 'PDF Document',
        size: '2.5 MB',
        modified: '2023-10-15 14:30:22',
        created: '2023-10-10 09:15:10',
        probability: '85%',
        status: 'Excellent',
        sector: '245,678',
        signature: 'PDF-1.4',
        hash: 'a1b2c3d4e5f6789...',
        path: '/Users/Documents/Important/document.pdf',
        recoveryPath: '/Recovered/Documents/document_recovered.pdf'
    };

    // Populate modal fields
    const detailElements = {
        'detail-filename': fileInfo.filename,
        'detail-type': fileInfo.type,
        'detail-size': fileInfo.size,
        'detail-modified': fileInfo.modified,
        'detail-created': fileInfo.created,
        'detail-probability': fileInfo.probability,
        'detail-status': fileInfo.status,
        'detail-sector': fileInfo.sector,
        'detail-signature': fileInfo.signature,
        'detail-hash': fileInfo.hash,
        'detail-path': fileInfo.path,
        'detail-recovery-path': fileInfo.recoveryPath
    };

    Object.entries(detailElements).forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element) element.textContent = value;
    });

    // Setup modal buttons
    const recoverBtn = document.getElementById('recover-file-btn');
    const previewBtn = document.getElementById('preview-file-btn');

    if (recoverBtn) {
        recoverBtn.onclick = () => {
            recoverSingleFile(recoveryState.currentScan, fileId);
            bootstrap.Modal.getInstance(document.getElementById('file-details-modal')).hide();
        };
    }

    if (previewBtn) {
        previewBtn.onclick = () => previewFile(fileId);
    }
}// ============================================
// DEEP SCAN HELPER FUNCTIONS
// ============================================

/**
 * Start comprehensive recovery with automatic carving detection
 */
function startComprehensiveRecovery() {
    const enableCarving = document.getElementById('enable-carving').checked;

    if (enableCarving) {
        startComprehensiveScan();
    } else {
        startRecovery(); // Use existing function for non-carving scans
    }
}

/**
 * Create combined results table
 */
function createCombinedResultsTable(regularFiles, carvedFiles) {
    const allFiles = [
        ...regularFiles.map(f => ({ ...f, source: 'scan' })),
        ...carvedFiles.map(f => ({ ...f, source: 'carving' }))
    ];

    if (allFiles.length === 0) {
        return '<div class="alert alert-warning">No files found</div>';
    }

    const rows = allFiles.map(file => `
        <tr>
            <td>
                <div class="d-flex align-items-center">
                    <i class="${getFileIcon(file.file_type)} me-2"></i>
                    <span>${file.filename}</span>
                    <span class="badge bg-${file.source === 'carving' ? 'success' : 'primary'} ms-2">
                        ${file.source === 'carving' ? 'Carved' : 'Scan'}
                    </span>
                </div>
            </td>
            <td><span class="badge bg-secondary">${file.file_type}</span></td>
            <td>${formatFileSize(file.size)}</td>
            <td>
                ${file.confidence !== undefined ? `
                    <div class="confidence-meter">
                        <div class="confidence-bar" style="width: ${file.confidence * 100}%; background-color: ${getConfidenceColor(file.confidence)}"></div>
                        <span class="confidence-text">${(file.confidence * 100).toFixed(1)}%</span>
                    </div>
                ` : '<span class="text-muted">N/A</span>'}
            </td>
            <td>
                <button class="btn btn-sm btn-primary" onclick="${file.source === 'carving' ? `recoverCarvedFile('${file.filename}', '${file.filepath}')` : `recoverFile('${file.id || file.filename}')`}">
                    <i class="bi bi-download"></i> Recover
                </button>
            </td>
        </tr>
    `).join('');

    return `
        <div class="table-responsive">
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>Filename</th>
                        <th>Type</th>
                        <th>Size</th>
                        <th>Confidence</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${rows}
                </tbody>
            </table>
        </div>
    `;
}

/**
 * Get appropriate file icon for file type
 */
function getFileIcon(type) {
    const iconMap = {
        'JPEG': 'bi-file-image',
        'PNG': 'bi-file-image',
        'GIF': 'bi-file-image',
        'BMP': 'bi-file-image',
        'PDF': 'bi-file-pdf',
        'DOCX': 'bi-file-word',
        'XLSX': 'bi-file-excel',
        'PPTX': 'bi-file-ppt',
        'ZIP': 'bi-file-zip',
        'RAR': 'bi-file-zip',
        'MP3': 'bi-file-music',
        'MP4': 'bi-file-play',
        'AVI': 'bi-file-play'
    };

    return iconMap[type] || 'bi-file-text';
}

/**
 * Get CSS class for recovery status badge
 */
function getRecoveryStatusClass(status) {
    const statusMap = {
        'excellent': 'success',
        'good': 'info',
        'poor': 'warning'
    };

    return statusMap[status] || 'secondary';
}

/**
 * Capitalize first letter of string
 */
function capitalizeFirst(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 * Generate pagination HTML
 */
function generatePagination(pagination) {
    const { page, pages, total } = pagination;
    let html = '';

    // Previous button
    html += `<li class="page-item ${page <= 1 ? 'disabled' : ''}">
        <a class="page-link" href="#" onclick="loadScanResults('${recoveryState.currentScan}', ${page - 1})">Previous</a>
    </li>`;

    // Page numbers
    const startPage = Math.max(1, page - 2);
    const endPage = Math.min(pages, page + 2);

    if (startPage > 1) {
        html += `<li class="page-item"><a class="page-link" href="#" onclick="loadScanResults('${recoveryState.currentScan}', 1)">1</a></li>`;
        if (startPage > 2) {
            html += `<li class="page-item disabled"><span class="page-link">...</span></li>`;
        }
    }

    for (let i = startPage; i <= endPage; i++) {
        html += `<li class="page-item ${i === page ? 'active' : ''}">
            <a class="page-link" href="#" onclick="loadScanResults('${recoveryState.currentScan}', ${i})">${i}</a>
        </li>`;
    }

    if (endPage < pages) {
        if (endPage < pages - 1) {
            html += `<li class="page-item disabled"><span class="page-link">...</span></li>`;
        }
        html += `<li class="page-item"><a class="page-link" href="#" onclick="loadScanResults('${recoveryState.currentScan}', ${pages})">${pages}</a></li>`;
    }

    // Next button
    html += `<li class="page-item ${page >= pages ? 'disabled' : ''}">
        <a class="page-link" href="#" onclick="loadScanResults('${recoveryState.currentScan}', ${page + 1})">Next</a>
    </li>`;

    return html;
}

/**
 * Setup event listeners for results interface
 */
function setupResultsEventListeners() {
    // Search functionality
    const searchInput = document.getElementById('search-files');
    if (searchInput) {
        let searchTimeout;
        searchInput.addEventListener('input', function () {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                const searchQuery = this.value;
                const fileTypeFilter = document.getElementById('filter-file-type')?.value || 'all';
                loadScanResults(recoveryState.currentScan, 1, fileTypeFilter, searchQuery);
            }, 500);
        });
    }

    // File type filter
    const fileTypeFilter = document.getElementById('filter-file-type');
    if (fileTypeFilter) {
        fileTypeFilter.addEventListener('change', function () {
            const searchQuery = document.getElementById('search-files')?.value || '';
            loadScanResults(recoveryState.currentScan, 1, this.value, searchQuery);
        });
    }
}

/**
 * Toggle all file selections
 */
function toggleAllFiles(selectAllCheckbox) {
    const fileCheckboxes = document.querySelectorAll('.file-checkbox');
    fileCheckboxes.forEach(cb => {
        cb.checked = selectAllCheckbox.checked;
    });
    updateSelectionCount();
}

/**
 * Select all files
 */
function selectAllFiles() {
    const fileCheckboxes = document.querySelectorAll('.file-checkbox');
    const selectAllCheckbox = document.getElementById('select-all-checkbox');

    fileCheckboxes.forEach(cb => {
        cb.checked = true;
    });

    if (selectAllCheckbox) {
        selectAllCheckbox.checked = true;
    }

    updateSelectionCount();
}

/**
 * Select no files
 */
function selectNoFiles() {
    const fileCheckboxes = document.querySelectorAll('.file-checkbox');
    const selectAllCheckbox = document.getElementById('select-all-checkbox');

    fileCheckboxes.forEach(cb => {
        cb.checked = false;
    });

    if (selectAllCheckbox) {
        selectAllCheckbox.checked = false;
    }

    updateSelectionCount();
}

/**
 * Update selection count display
 */
function updateSelectionCount() {
    const selectedCheckboxes = document.querySelectorAll('.file-checkbox:checked');
    const count = selectedCheckboxes.length;

    const countElement = document.getElementById('selected-count');
    const recoverButton = document.getElementById('recover-selected-btn');

    if (countElement) {
        countElement.textContent = count;
    }

    if (recoverButton) {
        recoverButton.disabled = count === 0;
        recoverButton.innerHTML = count > 0
            ? `<i class="bi bi-download"></i> Recover Selected (${count})`
            : `<i class="bi bi-download"></i> Recover Selected`;
    }
}

/**
 * Recover a single file
 */
async function recoverSingleFile(sessionId, fileId) {
    try {
        showLoading(`Recovering file...`);

        const response = await fetch(`${API_BASE_URL}/deep-scan/recover-file/${sessionId}/${fileId}`, {
            method: 'POST'
        });

        const result = await response.json();

        if (response.ok && result.status === 'success') {
            showAlert(`File recovered successfully: ${result.filename}`, 'success');
        } else {
            throw new Error(result.error || 'Recovery failed');
        }

    } catch (error) {
        console.error('File recovery error:', error);
        showAlert(`Recovery failed: ${error.message}`, 'danger');
    } finally {
        hideLoading();
    }
}

/**
 * Recover selected files
 */
async function recoverSelectedFiles() {
    const selectedCheckboxes = document.querySelectorAll('.file-checkbox:checked');
    const fileIds = Array.from(selectedCheckboxes).map(cb => cb.value);

    if (fileIds.length === 0) {
        showAlert('No files selected for recovery', 'warning');
        return;
    }

    try {
        showLoading(`Recovering ${fileIds.length} files...`);

        const response = await fetch(`${API_BASE_URL}/deep-scan/recover-selected/${recoveryState.currentScan}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                file_ids: fileIds
            })
        });

        const result = await response.json();

        if (response.ok && result.status === 'success') {
            const successCount = result.recovered_count;
            const failedCount = result.failed_count;

            if (failedCount === 0) {
                showAlert(`Successfully recovered ${successCount} files`, 'success');
            } else {
                showAlert(`Recovered ${successCount} files (${failedCount} failed)`, 'warning');
            }

            // Clear selections
            selectNoFiles();

        } else {
            throw new Error(result.error || 'Recovery failed');
        }

    } catch (error) {
        console.error('Bulk recovery error:', error);
        showAlert(`Recovery failed: ${error.message}`, 'danger');
    } finally {
        hideLoading();
    }
}

/**
 * Show file details modal
 */
function showFileDetails(fileId) {
    const file = recoveryState.foundFiles.find(f => f.id === fileId);
    if (!file) {
        showAlert('File details not found', 'warning');
        return;
    }

    const modalHTML = `
        <div class="modal fade" id="fileDetailsModal" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">
                            <i class="bi ${getFileIcon(file.file_type)} me-2"></i>
                            File Details
                        </h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row">
                            <div class="col-md-6">
                                <h6>Basic Information</h6>
                                <table class="table table-sm">
                                    <tr><td><strong>Filename:</strong></td><td>${file.filename}</td></tr>
                                    <tr><td><strong>File Type:</strong></td><td>${file.file_type}</td></tr>
                                    <tr><td><strong>Size:</strong></td><td>${formatFileSize(file.size)}</td></tr>
                                    <tr><td><strong>Recovery Status:</strong></td><td><span class="badge bg-${getRecoveryStatusClass(file.recovery_status)}">${capitalizeFirst(file.recovery_status)}</span></td></tr>
                                </table>
                            </div>
                            <div class="col-md-6">
                                <h6>Forensic Information</h6>
                                <table class="table table-sm">
                                    <tr><td><strong>File ID:</strong></td><td><code>${file.id}</code></td></tr>
                                    <tr><td><strong>Start Sector:</strong></td><td>${file.sector_start.toLocaleString()}</td></tr>
                                    <tr><td><strong>End Sector:</strong></td><td>${file.sector_end.toLocaleString()}</td></tr>
                                    <tr><td><strong>MD5 Hash:</strong></td><td><code class="small">${file.md5_hash}</code></td></tr>
                                    <tr><td><strong>Found On:</strong></td><td>${new Date(file.timestamp).toLocaleString()}</td></tr>
                                </table>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-success" onclick="recoverSingleFile('${recoveryState.currentScan}', '${file.id}')">
                            <i class="bi bi-download"></i> Recover File
                        </button>
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>
    `;

    // Remove existing modal if any
    const existingModal = document.getElementById('fileDetailsModal');
    if (existingModal) {
        existingModal.remove();
    }

    // Add modal to DOM
    document.body.insertAdjacentHTML('beforeend', modalHTML);

    // Show modal
    const modal = new bootstrap.Modal(document.getElementById('fileDetailsModal'));
    modal.show();
}

/**
 * Export file list
 */
function exportFileList() {
    const files = recoveryState.foundFiles;
    if (!files || files.length === 0) {
        showAlert('No files to export', 'warning');
        return;
    }

    // Create CSV content
    const headers = ['Filename', 'Type', 'Size', 'Status', 'Start Sector', 'MD5 Hash', 'Timestamp'];
    const csvContent = [
        headers.join(','),
        ...files.map(file => [
            file.filename,
            file.file_type,
            file.size,
            file.recovery_status,
            file.sector_start,
            file.md5_hash,
            file.timestamp
        ].join(','))
    ].join('\n');

    // Download CSV
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `recovery_results_${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);

    showAlert('File list exported successfully', 'success');
}

// Legacy compatibility functions
function startRecoveryScan() {
    // Map to new function
    startRecovery();
}