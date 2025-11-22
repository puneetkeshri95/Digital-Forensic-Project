/**
 * Auto-Integrity Dashboard JavaScript
 * Handles real-time integrity status updates and automatic verification displays
 */

class AutoIntegrityDashboard {
  constructor() {
    this.activeOperations = new Map();
    this.refreshInterval = null;
    this.initialize();
  }

  initialize() {
    console.log('Initializing Auto-Integrity Dashboard');
    this.refreshDashboard();
    this.startAutoRefresh();
    this.setupEventListeners();
  }

  setupEventListeners() {
    // File drag and drop
    const widget = document.getElementById('quickIntegrityWidget');
    if (widget) {
      widget.addEventListener('click', () => {
        document.getElementById('quickFileInput').click();
      });
    }
  }

  startAutoRefresh() {
    // Refresh every 10 seconds
    this.refreshInterval = setInterval(() => {
      this.refreshDashboard();
    }, 10000);
  }

  stopAutoRefresh() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
    }
  }

  async refreshDashboard() {
    try {
      await Promise.all([
        this.loadActiveOperations(),
        this.loadStatusCards(),
        this.loadOperationHistory()
      ]);
    } catch (error) {
      console.error('Error refreshing dashboard:', error);
      this.showError('Failed to refresh dashboard data');
    }
  }

  async loadStatusCards() {
    try {
      const response = await fetch('/api/auto-integrity/active-operations');
      const data = await response.json();

      if (!data.success) {
        throw new Error(data.error || 'Failed to load status');
      }

      const statusCards = document.getElementById('statusCards');
      const operations = data.active_operations || [];

      // Create status summary cards
      const totalOperations = operations.length;
      const verifiedCount = operations.filter(op => op.status === 'verified').length;
      const pendingCount = operations.filter(op => op.status === 'pre_analysis_complete').length;

      statusCards.innerHTML = `
                <div class="col-md-4">
                    <div class="card text-center border-primary">
                        <div class="card-body">
                            <h3 class="text-primary">${totalOperations}</h3>
                            <p class="mb-0">Active Operations</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card text-center border-success">
                        <div class="card-body">
                            <h3 class="text-success">${verifiedCount}</h3>
                            <p class="mb-0">Verified Files</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card text-center border-warning">
                        <div class="card-body">
                            <h3 class="text-warning">${pendingCount}</h3>
                            <p class="mb-0">Pending Verification</p>
                        </div>
                    </div>
                </div>
            `;

    } catch (error) {
      console.error('Error loading status cards:', error);
    }
  }

  async loadActiveOperations() {
    try {
      const response = await fetch('/api/auto-integrity/active-operations');
      const data = await response.json();

      if (!data.success) {
        throw new Error(data.error || 'Failed to load operations');
      }

      const container = document.getElementById('activeOperations');
      const operations = data.active_operations || [];

      if (operations.length === 0) {
        container.innerHTML = `
                    <div class="text-center text-muted">
                        <i class="fas fa-hourglass-half fa-2x mb-2"></i>
                        <p>No active operations</p>
                    </div>
                `;
        return;
      }

      const operationsHtml = operations.map(op => `
                <div class="card mb-2 integrity-status-card integrity-pending">
                    <div class="card-body py-2">
                        <div class="d-flex justify-content-between align-items-center">
                            <div>
                                <span class="badge bg-warning analysis-badge me-2">
                                    ${op.analysis_type.toUpperCase()}
                                </span>
                                <small class="text-muted">${this.getFileName(op.file_path)}</small>
                            </div>
                            <div class="text-end">
                                <div class="live-status">
                                    <i class="fas fa-clock text-warning me-1"></i>
                                    <small>In Progress</small>
                                </div>
                                <div class="mt-1">
                                    <small class="text-muted">${this.formatTime(op.start_time)}</small>
                                </div>
                            </div>
                        </div>
                        <div class="mt-2">
                            <small class="text-muted">Operation ID: ${op.operation_id}</small>
                        </div>
                    </div>
                </div>
            `).join('');

      container.innerHTML = operationsHtml;

    } catch (error) {
      console.error('Error loading active operations:', error);
    }
  }

  async loadOperationHistory() {
    try {
      // This would typically load from a logging API
      // For now, we'll simulate some history data
      const timeline = document.getElementById('operationTimeline');

      // In a real implementation, this would fetch from your logging system
      const mockHistory = [
        {
          id: 'op_001',
          type: 'ELA Analysis',
          file: 'evidence_photo.jpg',
          status: 'verified',
          timestamp: new Date(Date.now() - 300000).toISOString(),
          hashes: {
            sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            md5: 'd41d8cd98f00b204e9800998ecf8427e'
          }
        },
        {
          id: 'op_002',
          type: 'EXIF Analysis',
          file: 'metadata_sample.tiff',
          status: 'compromised',
          timestamp: new Date(Date.now() - 600000).toISOString(),
          hashes: {
            sha256: 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
            md5: '098f6bcd4621d373cade4e832627b4f6'
          }
        }
      ];

      const historyHtml = mockHistory.map(item => `
                <div class="timeline-item ${item.status === 'verified' ? 'success' : 'danger'}">
                    <div class="card integrity-status-card ${item.status === 'verified' ? 'integrity-verified' : 'integrity-compromised'}">
                        <div class="card-body py-2">
                            <div class="d-flex justify-content-between align-items-center">
                                <div>
                                    <span class="badge ${item.status === 'verified' ? 'bg-success' : 'bg-danger'} analysis-badge me-2">
                                        ${item.type}
                                    </span>
                                    <strong>${item.file}</strong>
                                </div>
                                <div class="text-end">
                                    <span class="badge ${item.status === 'verified' ? 'bg-success' : 'bg-danger'}">
                                        <i class="fas ${item.status === 'verified' ? 'fa-check-circle' : 'fa-exclamation-triangle'} me-1"></i>
                                        ${item.status === 'verified' ? 'VERIFIED' : 'COMPROMISED'}
                                    </span>
                                </div>
                            </div>
                            <div class="mt-2">
                                <small class="text-muted">${this.formatTime(item.timestamp)}</small>
                                <button class="btn btn-link btn-sm p-0 ms-2" onclick="dashboard.showIntegrityDetails('${item.id}')">
                                    <i class="fas fa-info-circle"></i> Details
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            `).join('');

      timeline.innerHTML = historyHtml || '<p class="text-muted">No operation history available</p>';

    } catch (error) {
      console.error('Error loading operation history:', error);
    }
  }

  async performQuickIntegrityCheck(file) {
    const resultDiv = document.getElementById('quickHashResult');

    try {
      // Show loading state
      resultDiv.style.display = 'block';
      resultDiv.innerHTML = `
                <div class="text-center">
                    <div class="spinner-border spinner-border-sm me-2" role="status"></div>
                    <span>Calculating hashes...</span>
                </div>
            `;

      const formData = new FormData();
      formData.append('file_path', file.name); // In real app, you'd handle file path differently

      // Simulate API call - in real implementation, you'd upload the file and get its path
      // For demonstration, we'll simulate hash calculation
      await new Promise(resolve => setTimeout(resolve, 2000)); // Simulate processing time

      const mockHashes = {
        sha256: this.generateMockHash('sha256'),
        md5: this.generateMockHash('md5')
      };

      resultDiv.innerHTML = `
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h6 class="mb-0">
                        <i class="fas fa-file me-2"></i>
                        ${file.name}
                    </h6>
                    <span class="badge bg-success">
                        <i class="fas fa-check-circle me-1"></i>
                        Calculated
                    </span>
                </div>
                <div class="row">
                    <div class="col-12 mb-2">
                        <label class="form-label fw-bold">SHA256:</label>
                        <div class="hash-display hash-verified">
                            ${mockHashes.sha256}
                        </div>
                    </div>
                    <div class="col-12 mb-2">
                        <label class="form-label fw-bold">MD5:</label>
                        <div class="hash-display hash-verified">
                            ${mockHashes.md5}
                        </div>
                    </div>
                </div>
                <div class="text-center mt-3">
                    <button class="btn btn-outline-primary btn-sm me-2" onclick="dashboard.copyToClipboard('${mockHashes.sha256}')">
                        <i class="fas fa-copy me-1"></i>Copy SHA256
                    </button>
                    <button class="btn btn-outline-secondary btn-sm" onclick="dashboard.copyToClipboard('${mockHashes.md5}')">
                        <i class="fas fa-copy me-1"></i>Copy MD5
                    </button>
                </div>
            `;

    } catch (error) {
      console.error('Error performing quick integrity check:', error);
      resultDiv.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle me-2"></i>
                    Error calculating hashes: ${error.message}
                </div>
            `;
    }
  }

  showIntegrityDetails(operationId) {
    // Mock detailed integrity information
    const mockDetails = {
      operation_id: operationId,
      file_path: '/evidence/sample_file.jpg',
      analysis_type: 'ELA Analysis',
      status: 'verified',
      pre_analysis: {
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        md5: 'd41d8cd98f00b204e9800998ecf8427e'
      },
      post_analysis: {
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        md5: 'd41d8cd98f00b204e9800998ecf8427e'
      }
    };

    const modalBody = document.getElementById('integrityModalBody');
    const isVerified = mockDetails.status === 'verified';

    modalBody.innerHTML = `
            <div class="integrity-status-card ${isVerified ? 'integrity-verified' : 'integrity-compromised'} p-3 mb-3">
                <div class="d-flex align-items-center mb-2">
                    <i class="fas ${isVerified ? 'fa-check-circle' : 'fa-exclamation-triangle'} 
                       text-${isVerified ? 'success' : 'danger'} fa-2x me-3"></i>
                    <div>
                        <h5 class="mb-1">
                            ${isVerified ? 'File Integrity Verified' : 'File Integrity Compromised'}
                        </h5>
                        <p class="mb-0 text-muted">Operation ID: ${mockDetails.operation_id}</p>
                    </div>
                </div>
            </div>

            <div class="row">
                <div class="col-md-6">
                    <h6>File Information</h6>
                    <table class="table table-sm">
                        <tr>
                            <td><strong>File Path:</strong></td>
                            <td><code>${mockDetails.file_path}</code></td>
                        </tr>
                        <tr>
                            <td><strong>Analysis Type:</strong></td>
                            <td><span class="badge bg-primary">${mockDetails.analysis_type}</span></td>
                        </tr>
                    </table>
                </div>
                <div class="col-md-6">
                    <h6>Verification Status</h6>
                    <table class="table table-sm">
                        <tr>
                            <td><strong>SHA256:</strong></td>
                            <td><i class="fas fa-check text-success"></i> Match</td>
                        </tr>
                        <tr>
                            <td><strong>MD5:</strong></td>
                            <td><i class="fas fa-check text-success"></i> Match</td>
                        </tr>
                    </table>
                </div>
            </div>

            <div class="mt-4">
                <h6>Hash Comparison</h6>
                <div class="row">
                    <div class="col-12 mb-3">
                        <label class="form-label fw-bold">SHA256 (Pre-Analysis):</label>
                        <div class="hash-display hash-verified">
                            ${mockDetails.pre_analysis.sha256}
                        </div>
                        <label class="form-label fw-bold mt-2">SHA256 (Post-Analysis):</label>
                        <div class="hash-display hash-verified">
                            ${mockDetails.post_analysis.sha256}
                        </div>
                    </div>
                    <div class="col-12">
                        <label class="form-label fw-bold">MD5 (Pre-Analysis):</label>
                        <div class="hash-display hash-verified">
                            ${mockDetails.pre_analysis.md5}
                        </div>
                        <label class="form-label fw-bold mt-2">MD5 (Post-Analysis):</label>
                        <div class="hash-display hash-verified">
                            ${mockDetails.post_analysis.md5}
                        </div>
                    </div>
                </div>
            </div>
        `;

    const modal = new bootstrap.Modal(document.getElementById('integrityModal'));
    modal.show();
  }

  async copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      this.showSuccess('Hash copied to clipboard');
    } catch (error) {
      console.error('Error copying to clipboard:', error);
      this.showError('Failed to copy to clipboard');
    }
  }

  generateMockHash(algorithm) {
    const chars = '0123456789abcdef';
    const length = algorithm === 'sha256' ? 64 : 32;
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  getFileName(filePath) {
    return filePath.split(/[\\/]/).pop() || filePath;
  }

  formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
  }

  showSuccess(message) {
    this.showAlert(message, 'success');
  }

  showError(message) {
    this.showAlert(message, 'danger');
  }

  showAlert(message, type) {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
    alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999;';
    alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

    document.body.appendChild(alertDiv);

    // Auto-remove after 5 seconds
    setTimeout(() => {
      if (alertDiv.parentNode) {
        alertDiv.parentNode.removeChild(alertDiv);
      }
    }, 5000);
  }
}

// File drag and drop handlers
function handleDragOver(event) {
  event.preventDefault();
  event.currentTarget.classList.add('drag-over');
}

function handleDragLeave(event) {
  event.currentTarget.classList.remove('drag-over');
}

function handleFileDrop(event) {
  event.preventDefault();
  event.currentTarget.classList.remove('drag-over');

  const files = event.dataTransfer.files;
  if (files.length > 0) {
    dashboard.performQuickIntegrityCheck(files[0]);
  }
}

function handleFileSelect(event) {
  const files = event.target.files;
  if (files.length > 0) {
    dashboard.performQuickIntegrityCheck(files[0]);
  }
}

function refreshDashboard() {
  dashboard.refreshDashboard();
}

// Initialize dashboard when page loads
let dashboard;
document.addEventListener('DOMContentLoaded', function () {
  dashboard = new AutoIntegrityDashboard();
});

// Cleanup on page unload
window.addEventListener('beforeunload', function () {
  if (dashboard) {
    dashboard.stopAutoRefresh();
  }
});