/**
 * Forensics Logging and Notes Manager
 * ==================================
 * 
 * JavaScript module for managing forensic activity logs and investigator notes.
 * Provides comprehensive functionality for:
 * - Session management and tracking
 * - Activity logging and visualization
 * - Investigator notes CRUD operations
 * - Evidence tracking and chain of custody
 * - Search and filtering capabilities
 * - Data export and reporting
 */

class ForensicsLogger {
    constructor() {
        this.baseUrl = '/api/logging';
        this.currentSession = null;
        this.currentInvestigator = null;
        this.activityCache = new Map();
        this.notesCache = new Map();
        this.refreshInterval = null;

        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadSessionFromStorage();
        this.initializeUI();
    }

    setupEventListeners() {
        // Session management
        document.addEventListener('click', (e) => {
            if (e.target.matches('[data-action="start-session"]')) {
                this.showSessionModal();
            } else if (e.target.matches('[data-action="end-session"]')) {
                this.endCurrentSession();
            } else if (e.target.matches('[data-action="add-note"]')) {
                this.showNoteModal();
            } else if (e.target.matches('[data-action="view-logs"]')) {
                this.showActivityLogs();
            } else if (e.target.matches('[data-action="export-data"]')) {
                this.exportSessionData();
            } else if (e.target.matches('[data-action="search-logs"]')) {
                this.performSearch('logs');
            } else if (e.target.matches('[data-action="search-notes"]')) {
                this.performSearch('notes');
            }
        });

        // Form submissions
        document.addEventListener('submit', (e) => {
            if (e.target.matches('#sessionForm')) {
                e.preventDefault();
                this.createSession();
            } else if (e.target.matches('#noteForm')) {
                e.preventDefault();
                this.saveNote();
            }
        });

        // Auto-refresh functionality
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                this.stopAutoRefresh();
            } else {
                this.startAutoRefresh();
            }
        });
    }

    loadSessionFromStorage() {
        const sessionData = localStorage.getItem('forensics_session');
        if (sessionData) {
            try {
                const session = JSON.parse(sessionData);
                this.currentSession = session.session_id;
                this.currentInvestigator = session.investigator_id;
                this.updateSessionDisplay(session);
            } catch (e) {
                console.error('Failed to load session from storage:', e);
                localStorage.removeItem('forensics_session');
            }
        }
    }

    initializeUI() {
        this.createSessionBar();
        this.createNotesPanel();
        this.createActivityPanel();

        if (this.currentSession) {
            this.refreshData();
            this.startAutoRefresh();
        }
    }

    createSessionBar() {
        const sessionBar = document.createElement('div');
        sessionBar.id = 'forensics-session-bar';
        sessionBar.className = 'forensics-session-bar';
        sessionBar.innerHTML = `
            <div class="container-fluid">
                <div class="row align-items-center">
                    <div class="col-md-6">
                        <div id="session-info" class="session-info">
                            <span class="session-status">No active session</span>
                        </div>
                    </div>
                    <div class="col-md-6 text-end">
                        <div class="session-controls">
                            <button class="btn btn-primary btn-sm" data-action="start-session">
                                <i class="fas fa-play"></i> Start Session
                            </button>
                            <button class="btn btn-success btn-sm" data-action="add-note" style="display: none;">
                                <i class="fas fa-sticky-note"></i> Add Note
                            </button>
                            <button class="btn btn-info btn-sm" data-action="view-logs" style="display: none;">
                                <i class="fas fa-list"></i> View Logs
                            </button>
                            <button class="btn btn-warning btn-sm" data-action="export-data" style="display: none;">
                                <i class="fas fa-download"></i> Export
                            </button>
                            <button class="btn btn-danger btn-sm" data-action="end-session" style="display: none;">
                                <i class="fas fa-stop"></i> End Session
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Insert at the top of the page
        document.body.insertBefore(sessionBar, document.body.firstChild);

        // Add styles
        this.addSessionBarStyles();
    }

    addSessionBarStyles() {
        const style = document.createElement('style');
        style.textContent = `
            .forensics-session-bar {
                background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
                color: white;
                padding: 8px 0;
                position: sticky;
                top: 0;
                z-index: 1000;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                border-bottom: 3px solid #3498db;
            }
            
            .session-info {
                font-weight: 500;
            }
            
            .session-status {
                display: inline-block;
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 0.9em;
            }
            
            .session-status.active {
                background-color: #27ae60;
                color: white;
            }
            
            .session-status.inactive {
                background-color: #e74c3c;
                color: white;
            }
            
            .session-controls .btn {
                margin-left: 5px;
                border-radius: 20px;
            }
            
            .forensics-modal {
                background-color: rgba(0,0,0,0.8);
            }
            
            .activity-log-item {
                border-left: 4px solid #3498db;
                padding: 10px 15px;
                margin: 5px 0;
                background: #f8f9fa;
                border-radius: 5px;
            }
            
            .activity-log-item.error {
                border-left-color: #e74c3c;
            }
            
            .activity-log-item.success {
                border-left-color: #27ae60;
            }
            
            .note-item {
                border: 1px solid #dee2e6;
                border-radius: 8px;
                padding: 15px;
                margin: 10px 0;
                background: white;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            
            .note-item.priority-high {
                border-left: 5px solid #e74c3c;
            }
            
            .note-item.priority-medium {
                border-left: 5px solid #f39c12;
            }
            
            .note-item.priority-low {
                border-left: 5px solid #27ae60;
            }
            
            .note-tags {
                margin-top: 10px;
            }
            
            .note-tag {
                display: inline-block;
                background: #3498db;
                color: white;
                padding: 2px 8px;
                border-radius: 12px;
                font-size: 0.8em;
                margin-right: 5px;
            }
        `;
        document.head.appendChild(style);
    }

    createNotesPanel() {
        // Notes panel will be created dynamically when needed
    }

    createActivityPanel() {
        // Activity panel will be created dynamically when needed
    }

    showSessionModal() {
        const modal = this.createModal('sessionModal', 'Start Investigation Session', `
            <form id="sessionForm">
                <div class="mb-3">
                    <label for="investigatorId" class="form-label">Investigator ID *</label>
                    <input type="text" class="form-control" id="investigatorId" name="investigator_id" required>
                </div>
                <div class="mb-3">
                    <label for="investigatorName" class="form-label">Investigator Name</label>
                    <input type="text" class="form-control" id="investigatorName" name="investigator_name">
                </div>
                <div class="mb-3">
                    <label for="caseNumber" class="form-label">Case Number</label>
                    <input type="text" class="form-control" id="caseNumber" name="case_number">
                </div>
                <div class="mb-3">
                    <label for="caseTitle" class="form-label">Case Title</label>
                    <input type="text" class="form-control" id="caseTitle" name="case_title">
                </div>
                <div class="mb-3">
                    <label for="sessionTitle" class="form-label">Session Title</label>
                    <input type="text" class="form-control" id="sessionTitle" name="session_title">
                </div>
                <div class="mb-3">
                    <label for="sessionNotes" class="form-label">Initial Notes</label>
                    <textarea class="form-control" id="sessionNotes" name="session_notes" rows="3"></textarea>
                </div>
                <div class="text-end">
                    <button type="button" class="btn btn-secondary me-2" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Start Session</button>
                </div>
            </form>
        `);

        modal.show();
    }

    showNoteModal(noteData = null) {
        const isEdit = noteData !== null;
        const title = isEdit ? 'Edit Note' : 'Add Investigation Note';

        const modal = this.createModal('noteModal', title, `
            <form id="noteForm">
                <input type="hidden" id="noteId" value="${noteData?.id || ''}">
                <div class="row">
                    <div class="col-md-8">
                        <div class="mb-3">
                            <label for="noteTitle" class="form-label">Title *</label>
                            <input type="text" class="form-control" id="noteTitle" name="title" 
                                   value="${noteData?.title || ''}" required>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="mb-3">
                            <label for="notePriority" class="form-label">Priority</label>
                            <select class="form-select" id="notePriority" name="priority">
                                <option value="low" ${noteData?.priority === 'low' ? 'selected' : ''}>Low</option>
                                <option value="normal" ${!noteData?.priority || noteData?.priority === 'normal' ? 'selected' : ''}>Normal</option>
                                <option value="high" ${noteData?.priority === 'high' ? 'selected' : ''}>High</option>
                            </select>
                        </div>
                    </div>
                </div>
                <div class="row">
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label for="noteType" class="form-label">Note Type</label>
                            <select class="form-select" id="noteType" name="note_type">
                                <option value="general" ${!noteData?.note_type || noteData?.note_type === 'general' ? 'selected' : ''}>General</option>
                                <option value="evidence" ${noteData?.note_type === 'evidence' ? 'selected' : ''}>Evidence</option>
                                <option value="finding" ${noteData?.note_type === 'finding' ? 'selected' : ''}>Finding</option>
                                <option value="procedure" ${noteData?.note_type === 'procedure' ? 'selected' : ''}>Procedure</option>
                                <option value="observation" ${noteData?.note_type === 'observation' ? 'selected' : ''}>Observation</option>
                            </select>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="mb-3">
                            <label for="evidenceReference" class="form-label">Evidence Reference</label>
                            <input type="text" class="form-control" id="evidenceReference" name="evidence_reference"
                                   value="${noteData?.evidence_reference || ''}">
                        </div>
                    </div>
                </div>
                <div class="mb-3">
                    <label for="noteContent" class="form-label">Content *</label>
                    <textarea class="form-control" id="noteContent" name="content" rows="5" required>${noteData?.content || ''}</textarea>
                </div>
                <div class="mb-3">
                    <label for="noteTags" class="form-label">Tags (comma-separated)</label>
                    <input type="text" class="form-control" id="noteTags" name="tags"
                           value="${noteData?.tags ? noteData.tags.join(', ') : ''}"
                           placeholder="forensics, evidence, analysis">
                </div>
                <div class="mb-3">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="isConfidential" name="is_confidential"
                               ${noteData?.is_confidential ? 'checked' : ''}>
                        <label class="form-check-label" for="isConfidential">
                            Confidential Note
                        </label>
                    </div>
                </div>
                <div class="text-end">
                    <button type="button" class="btn btn-secondary me-2" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">${isEdit ? 'Update' : 'Save'} Note</button>
                </div>
            </form>
        `);

        modal.show();
    }

    showActivityLogs() {
        const modal = this.createModal('logsModal', 'Activity Logs', `
            <div class="mb-3">
                <div class="row">
                    <div class="col-md-6">
                        <input type="text" class="form-control" id="logSearch" placeholder="Search logs...">
                    </div>
                    <div class="col-md-3">
                        <select class="form-select" id="activityTypeFilter">
                            <option value="">All Types</option>
                            <option value="ela_analysis">ELA Analysis</option>
                            <option value="exif_analysis">EXIF Analysis</option>
                            <option value="hex_analysis">Hex Analysis</option>
                            <option value="clone_detection">Clone Detection</option>
                            <option value="file_upload">File Upload</option>
                            <option value="user_action">User Action</option>
                        </select>
                    </div>
                    <div class="col-md-3">
                        <button class="btn btn-primary" data-action="search-logs">
                            <i class="fas fa-search"></i> Search
                        </button>
                        <button class="btn btn-secondary" onclick="this.refreshActivityLogs()">
                            <i class="fas fa-refresh"></i>
                        </button>
                    </div>
                </div>
            </div>
            <div id="activityLogsContainer" style="max-height: 500px; overflow-y: auto;">
                <div class="text-center p-4">
                    <div class="spinner-border" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                </div>
            </div>
            <div class="mt-3 text-end">
                <button class="btn btn-outline-primary" onclick="this.loadMoreLogs()">Load More</button>
            </div>
        `, 'modal-lg');

        modal.show();

        // Load activity logs
        this.loadActivityLogs();
    }

    async createSession() {
        try {
            const form = document.getElementById('sessionForm');
            const formData = new FormData(form);
            const sessionData = Object.fromEntries(formData.entries());

            const response = await fetch(`${this.baseUrl}/sessions`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(sessionData)
            });

            const result = await response.json();

            if (result.success) {
                this.currentSession = result.session_id;
                this.currentInvestigator = sessionData.investigator_id;

                // Save to localStorage
                localStorage.setItem('forensics_session', JSON.stringify({
                    session_id: this.currentSession,
                    investigator_id: this.currentInvestigator,
                    investigator_name: sessionData.investigator_name,
                    case_number: sessionData.case_number,
                    start_time: new Date().toISOString()
                }));

                this.updateSessionDisplay({
                    session_id: this.currentSession,
                    investigator_name: sessionData.investigator_name,
                    case_number: sessionData.case_number
                });

                this.startAutoRefresh();

                // Close modal
                bootstrap.Modal.getInstance(document.getElementById('sessionModal')).hide();

                this.showSuccess('Investigation session started successfully');
            } else {
                this.showError(result.error || 'Failed to create session');
            }
        } catch (error) {
            console.error('Error creating session:', error);
            this.showError('Failed to create session');
        }
    }

    async endCurrentSession() {
        if (!this.currentSession) return;

        try {
            const response = await fetch(`${this.baseUrl}/sessions/${this.currentSession}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    session_notes: 'Session ended by user'
                })
            });

            const result = await response.json();

            if (result.success) {
                this.currentSession = null;
                this.currentInvestigator = null;
                localStorage.removeItem('forensics_session');

                this.updateSessionDisplay(null);
                this.stopAutoRefresh();

                this.showSuccess('Investigation session ended successfully');
            } else {
                this.showError(result.error || 'Failed to end session');
            }
        } catch (error) {
            console.error('Error ending session:', error);
            this.showError('Failed to end session');
        }
    }

    async saveNote() {
        try {
            const form = document.getElementById('noteForm');
            const formData = new FormData(form);
            const noteData = Object.fromEntries(formData.entries());

            // Add session context
            noteData.session_id = this.currentSession;
            noteData.investigator_id = this.currentInvestigator;

            // Process tags
            if (noteData.tags) {
                noteData.tags = noteData.tags.split(',').map(tag => tag.trim()).filter(tag => tag);
            }

            // Convert checkbox
            noteData.is_confidential = formData.has('is_confidential');

            const noteId = document.getElementById('noteId').value;
            const isEdit = noteId !== '';

            const url = isEdit ? `${this.baseUrl}/notes/${noteId}` : `${this.baseUrl}/notes`;
            const method = isEdit ? 'PUT' : 'POST';

            const response = await fetch(url, {
                method: method,
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(noteData)
            });

            const result = await response.json();

            if (result.success) {
                // Close modal
                bootstrap.Modal.getInstance(document.getElementById('noteModal')).hide();

                this.showSuccess(isEdit ? 'Note updated successfully' : 'Note added successfully');

                // Refresh notes if panel is open
                if (document.getElementById('notesPanel')) {
                    this.loadNotes();
                }
            } else {
                this.showError(result.error || 'Failed to save note');
            }
        } catch (error) {
            console.error('Error saving note:', error);
            this.showError('Failed to save note');
        }
    }

    async loadActivityLogs(offset = 0) {
        try {
            const params = new URLSearchParams({
                session_id: this.currentSession || '',
                limit: '50',
                offset: offset.toString()
            });

            const response = await fetch(`${this.baseUrl}/activities?${params}`);
            const result = await response.json();

            if (result.success) {
                this.displayActivityLogs(result.activities, offset === 0);
            } else {
                this.showError(result.error || 'Failed to load activity logs');
            }
        } catch (error) {
            console.error('Error loading activity logs:', error);
            this.showError('Failed to load activity logs');
        }
    }

    displayActivityLogs(activities, clearContainer = true) {
        const container = document.getElementById('activityLogsContainer');

        if (clearContainer) {
            container.innerHTML = '';
        }

        if (activities.length === 0) {
            container.innerHTML = '<div class="text-center p-4 text-muted">No activity logs found</div>';
            return;
        }

        activities.forEach(activity => {
            const logItem = document.createElement('div');
            logItem.className = `activity-log-item ${activity.result_status || 'success'}`;

            logItem.innerHTML = `
                <div class="d-flex justify-content-between align-items-start">
                    <div class="flex-grow-1">
                        <div class="fw-bold">${activity.activity_type} - ${activity.description}</div>
                        ${activity.file_name ? `<div class="text-muted small">File: ${activity.file_name}</div>` : ''}
                        ${activity.error_message ? `<div class="text-danger small">Error: ${activity.error_message}</div>` : ''}
                        ${activity.duration_ms ? `<div class="text-info small">Duration: ${activity.duration_ms}ms</div>` : ''}
                    </div>
                    <div class="text-end">
                        <small class="text-muted">${new Date(activity.timestamp).toLocaleString()}</small>
                        ${activity.result_status ? `<div class="badge bg-${activity.result_status === 'success' ? 'success' : 'danger'}">${activity.result_status}</div>` : ''}
                    </div>
                </div>
            `;

            container.appendChild(logItem);
        });
    }

    async performSearch(type) {
        const searchTerm = document.getElementById(type === 'logs' ? 'logSearch' : 'noteSearch')?.value;
        if (!searchTerm) return;

        try {
            const endpoint = type === 'logs' ? 'activities/search' : 'notes/search';
            const params = new URLSearchParams({
                q: searchTerm,
                session_id: this.currentSession || ''
            });

            const response = await fetch(`${this.baseUrl}/${endpoint}?${params}`);
            const result = await response.json();

            if (result.success) {
                if (type === 'logs') {
                    this.displayActivityLogs(result.results, true);
                } else {
                    this.displayNotes(result.results, true);
                }
            } else {
                this.showError(result.error || 'Search failed');
            }
        } catch (error) {
            console.error('Error performing search:', error);
            this.showError('Search failed');
        }
    }

    async exportSessionData() {
        if (!this.currentSession) {
            this.showError('No active session to export');
            return;
        }

        try {
            const response = await fetch(`${this.baseUrl}/sessions/${this.currentSession}/export`);
            const result = await response.json();

            if (result.success) {
                // Create and download file
                const blob = new Blob([JSON.stringify(result.export_data, null, 2)],
                    { type: 'application/json' });
                const url = URL.createObjectURL(blob);

                const a = document.createElement('a');
                a.href = url;
                a.download = `forensics_session_${this.currentSession}_${new Date().toISOString().slice(0, 19)}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);

                this.showSuccess('Session data exported successfully');
            } else {
                this.showError(result.error || 'Export failed');
            }
        } catch (error) {
            console.error('Error exporting data:', error);
            this.showError('Export failed');
        }
    }

    updateSessionDisplay(sessionData) {
        const sessionInfo = document.getElementById('session-info');
        const controls = document.querySelectorAll('.session-controls button');

        if (sessionData) {
            sessionInfo.innerHTML = `
                <span class="session-status active">Active Session</span>
                <div class="session-details">
                    <strong>ID:</strong> ${sessionData.session_id}<br>
                    ${sessionData.investigator_name ? `<strong>Investigator:</strong> ${sessionData.investigator_name}<br>` : ''}
                    ${sessionData.case_number ? `<strong>Case:</strong> ${sessionData.case_number}` : ''}
                </div>
            `;

            // Show session controls
            controls.forEach(btn => {
                if (btn.dataset.action === 'start-session') {
                    btn.style.display = 'none';
                } else {
                    btn.style.display = 'inline-block';
                }
            });
        } else {
            sessionInfo.innerHTML = '<span class="session-status inactive">No active session</span>';

            // Hide session controls
            controls.forEach(btn => {
                if (btn.dataset.action === 'start-session') {
                    btn.style.display = 'inline-block';
                } else {
                    btn.style.display = 'none';
                }
            });
        }
    }

    startAutoRefresh() {
        if (this.refreshInterval) return;

        this.refreshInterval = setInterval(() => {
            this.refreshData();
        }, 30000); // Refresh every 30 seconds
    }

    stopAutoRefresh() {
        if (this.refreshInterval) {
            clearInterval(this.refreshInterval);
            this.refreshInterval = null;
        }
    }

    async refreshData() {
        // Refresh any open panels
        if (document.getElementById('activityLogsContainer')) {
            this.loadActivityLogs();
        }
    }

    // Utility methods
    createModal(id, title, content, size = 'modal-xl') {
        // Remove existing modal
        const existing = document.getElementById(id);
        if (existing) existing.remove();

        const modal = document.createElement('div');
        modal.className = 'modal fade forensics-modal';
        modal.id = id;
        modal.innerHTML = `
            <div class="modal-dialog ${size}">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">${title}</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        ${content}
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        return new bootstrap.Modal(modal);
    }

    showSuccess(message) {
        this.showToast(message, 'success');
    }

    showError(message) {
        this.showToast(message, 'error');
    }

    showToast(message, type = 'info') {
        // Create toast container if it doesn't exist
        let container = document.getElementById('toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toast-container';
            container.className = 'toast-container position-fixed top-0 end-0 p-3';
            container.style.zIndex = '1060';
            document.body.appendChild(container);
        }

        const toast = document.createElement('div');
        toast.className = `toast align-items-center text-white bg-${type === 'success' ? 'success' : type === 'error' ? 'danger' : 'primary'} border-0`;
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">${message}</div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;

        container.appendChild(toast);

        const bsToast = new bootstrap.Toast(toast, { delay: 5000 });
        bsToast.show();

        toast.addEventListener('hidden.bs.toast', () => {
            toast.remove();
        });
    }

    // Public API for logging activities
    async logActivity(activityType, description, additionalData = {}) {
        try {
            const logData = {
                activity_type: activityType,
                description: description,
                session_id: this.currentSession,
                investigator_id: this.currentInvestigator,
                ...additionalData
            };

            const response = await fetch(`${this.baseUrl}/activities`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(logData)
            });

            const result = await response.json();
            return result.success ? result.activity_id : null;
        } catch (error) {
            console.error('Error logging activity:', error);
            return null;
        }
    }

    // Helper method to log file analysis
    logFileAnalysis(filePath, analysisType, results, duration = null) {
        return this.logActivity(analysisType, `${analysisType} analysis completed`, {
            activity_category: 'file_analysis',
            file_path: filePath,
            file_name: filePath ? filePath.split('/').pop() : null,
            operation_details: results,
            duration_ms: duration
        });
    }
}

// Initialize global instance
window.forensicsLogger = new ForensicsLogger();

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ForensicsLogger;
}