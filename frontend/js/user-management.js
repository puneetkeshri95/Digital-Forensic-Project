/**
 * User Management JavaScript
 * Handles user CRUD operations, role management, and administrative functions
 */

class UserManagement {
    constructor() {
        this.apiBase = '/api/auth';
        this.users = [];
        this.currentUser = null;
        this.editingUserId = null;
        this.initialize();
    }

    async initialize() {
        // Check authentication and permissions
        if (!requireAuth()) return;
        
        const permissions = await authManager.getUserPermissions();
        if (!permissions.includes('manage_users')) {
            this.showAlert('You do not have permission to access user management', 'danger');
            setTimeout(() => window.location.href = '/', 3000);
            return;
        }

        // Load current user info
        this.currentUser = await authManager.getCurrentUser();
        this.updateCurrentUserDisplay();

        // Load users and statistics
        await this.loadUsers();
        await this.loadStatistics();

        // Initialize DataTable
        this.initializeDataTable();
    }

    updateCurrentUserDisplay() {
        const userNameElement = document.getElementById('currentUserName');
        if (userNameElement && this.currentUser) {
            userNameElement.textContent = this.currentUser.full_name || this.currentUser.username;
        }
    }

    async loadUsers() {
        try {
            const response = await authManager.apiCall('/users');
            if (response.ok) {
                const result = await response.json();
                if (result.success) {
                    this.users = result.users;
                    this.renderUsersTable();
                }
            } else {
                throw new Error('Failed to load users');
            }
        } catch (error) {
            console.error('Error loading users:', error);
            this.showAlert('Failed to load users', 'danger');
        }
    }

    async loadStatistics() {
        try {
            const response = await authManager.apiCall('/system-info');
            if (response.ok) {
                const result = await response.json();
                if (result.success) {
                    this.renderStatistics(result.system_info);
                }
            }
        } catch (error) {
            console.error('Error loading statistics:', error);
        }
    }

    renderStatistics(stats) {
        const container = document.getElementById('statsContainer');
        
        const statsHtml = `
            <div class="col-md-3">
                <div class="stats-card">
                    <h3>${stats.total_users}</h3>
                    <p class="mb-0">
                        <i class="fas fa-users me-2"></i>Total Users
                    </p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stats-card">
                    <h3>${stats.role_distribution.admin || 0}</h3>
                    <p class="mb-0">
                        <i class="fas fa-crown me-2"></i>Administrators
                    </p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stats-card">
                    <h3>${stats.role_distribution.forensic_investigator || 0}</h3>
                    <p class="mb-0">
                        <i class="fas fa-search me-2"></i>Investigators
                    </p>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stats-card">
                    <h3>${stats.role_distribution.viewer || 0}</h3>
                    <p class="mb-0">
                        <i class="fas fa-eye me-2"></i>Viewers
                    </p>
                </div>
            </div>
        `;
        
        container.innerHTML = statsHtml;
    }

    renderUsersTable() {
        const tbody = document.getElementById('usersTableBody');
        
        const usersHtml = this.users.map(user => {
            const avatar = this.generateAvatar(user.full_name || user.username);
            const roleClass = `role-${user.role}`;
            const statusClass = `status-${user.status}`;
            const lastLogin = user.last_login ? 
                new Date(user.last_login).toLocaleDateString() : 'Never';
            const created = new Date(user.created_at).toLocaleDateString();
            
            return `
                <tr>
                    <td>
                        <div class="d-flex align-items-center">
                            <div class="user-avatar me-3">${avatar}</div>
                            <div>
                                <div class="fw-bold">${user.full_name || user.username}</div>
                                <small class="text-muted">${user.email}</small>
                                ${user.department ? `<br><small class="text-muted">${user.department}</small>` : ''}
                            </div>
                        </div>
                    </td>
                    <td>
                        <span class="role-badge ${roleClass}">
                            ${this.formatRole(user.role)}
                        </span>
                    </td>
                    <td>
                        <i class="fas fa-circle ${statusClass} me-1"></i>
                        ${user.status.charAt(0).toUpperCase() + user.status.slice(1)}
                    </td>
                    <td>${lastLogin}</td>
                    <td>${created}</td>
                    <td>
                        <button class="btn btn-outline-primary btn-action" onclick="userManager.viewUser(${user.user_id})" title="View Details">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="btn btn-outline-secondary btn-action" onclick="userManager.editUser(${user.user_id})" title="Edit User">
                            <i class="fas fa-edit"></i>
                        </button>
                        ${user.user_id !== this.currentUser.user_id ? `
                            <button class="btn btn-outline-${user.status === 'active' ? 'warning' : 'success'} btn-action" 
                                    onclick="userManager.toggleUserStatus(${user.user_id})" 
                                    title="${user.status === 'active' ? 'Suspend' : 'Activate'} User">
                                <i class="fas fa-${user.status === 'active' ? 'pause' : 'play'}"></i>
                            </button>
                        ` : ''}
                    </td>
                </tr>
            `;
        }).join('');
        
        tbody.innerHTML = usersHtml;
    }

    initializeDataTable() {
        if ($.fn.DataTable.isDataTable('#usersTable')) {
            $('#usersTable').DataTable().destroy();
        }

        $('#usersTable').DataTable({
            responsive: true,
            pageLength: 10,
            order: [[4, 'desc']], // Sort by created date
            columnDefs: [
                { orderable: false, targets: [5] } // Disable sorting for actions column
            ],
            language: {
                search: "Search users:",
                lengthMenu: "Show _MENU_ users per page",
                info: "Showing _START_ to _END_ of _TOTAL_ users",
                paginate: {
                    first: "First",
                    last: "Last",
                    next: "Next",
                    previous: "Previous"
                }
            }
        });
    }

    generateAvatar(name) {
        if (!name) return '?';
        const initials = name.split(' ').map(n => n[0]).join('').toUpperCase();
        return initials.substring(0, 2);
    }

    formatRole(role) {
        const roleMap = {
            'admin': 'Administrator',
            'forensic_investigator': 'Investigator',
            'viewer': 'Viewer'
        };
        return roleMap[role] || role;
    }

    showCreateUser() {
        this.editingUserId = null;
        document.getElementById('userModalTitle').innerHTML = '<i class="fas fa-user-plus me-2"></i>Add New User';
        document.getElementById('userForm').reset();
        document.getElementById('passwordSection').style.display = 'block';
        document.getElementById('password').required = true;
        document.getElementById('confirmPassword').required = true;
        
        const modal = new bootstrap.Modal(document.getElementById('userModal'));
        modal.show();
    }

    async editUser(userId) {
        const user = this.users.find(u => u.user_id === userId);
        if (!user) return;

        this.editingUserId = userId;
        document.getElementById('userModalTitle').innerHTML = '<i class="fas fa-user-edit me-2"></i>Edit User';
        
        // Populate form
        document.getElementById('userId').value = user.user_id;
        document.getElementById('username').value = user.username;
        document.getElementById('email').value = user.email;
        document.getElementById('fullName').value = user.full_name || '';
        document.getElementById('department').value = user.department || '';
        document.getElementById('role').value = user.role;
        document.getElementById('status').value = user.status;
        
        // Hide password section for editing
        document.getElementById('passwordSection').style.display = 'none';
        document.getElementById('password').required = false;
        document.getElementById('confirmPassword').required = false;
        
        const modal = new bootstrap.Modal(document.getElementById('userModal'));
        modal.show();
    }

    async viewUser(userId) {
        const user = this.users.find(u => u.user_id === userId);
        if (!user) return;

        const detailsContent = document.getElementById('userDetailsContent');
        const avatar = this.generateAvatar(user.full_name || user.username);
        const roleClass = `role-${user.role}`;
        
        const permissionsHtml = user.permissions ? 
            user.permissions.map(p => `<span class="permission-badge">${p.replace('_', ' ')}</span>`).join(' ') :
            'No permissions assigned';

        detailsContent.innerHTML = `
            <div class="row">
                <div class="col-md-4">
                    <div class="text-center mb-4">
                        <div class="user-avatar mx-auto mb-3" style="width: 80px; height: 80px; font-size: 2em;">
                            ${avatar}
                        </div>
                        <h4>${user.full_name || user.username}</h4>
                        <span class="role-badge ${roleClass}">
                            ${this.formatRole(user.role)}
                        </span>
                    </div>
                </div>
                <div class="col-md-8">
                    <div class="row">
                        <div class="col-sm-6">
                            <h6>User Information</h6>
                            <table class="table table-sm table-borderless">
                                <tr>
                                    <td><strong>Username:</strong></td>
                                    <td>${user.username}</td>
                                </tr>
                                <tr>
                                    <td><strong>Email:</strong></td>
                                    <td>${user.email}</td>
                                </tr>
                                <tr>
                                    <td><strong>Department:</strong></td>
                                    <td>${user.department || 'Not specified'}</td>
                                </tr>
                                <tr>
                                    <td><strong>Status:</strong></td>
                                    <td>
                                        <i class="fas fa-circle status-${user.status} me-1"></i>
                                        ${user.status.charAt(0).toUpperCase() + user.status.slice(1)}
                                    </td>
                                </tr>
                            </table>
                        </div>
                        <div class="col-sm-6">
                            <h6>Account Details</h6>
                            <table class="table table-sm table-borderless">
                                <tr>
                                    <td><strong>Created:</strong></td>
                                    <td>${new Date(user.created_at).toLocaleString()}</td>
                                </tr>
                                <tr>
                                    <td><strong>Last Login:</strong></td>
                                    <td>${user.last_login ? new Date(user.last_login).toLocaleString() : 'Never'}</td>
                                </tr>
                                <tr>
                                    <td><strong>User ID:</strong></td>
                                    <td>${user.user_id}</td>
                                </tr>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            
            <hr>
            
            <div class="row">
                <div class="col-12">
                    <h6>Permissions</h6>
                    <div class="user-permissions">
                        ${permissionsHtml}
                    </div>
                </div>
            </div>
        `;

        const modal = new bootstrap.Modal(document.getElementById('userDetailsModal'));
        modal.show();
    }

    async saveUser() {
        const form = document.getElementById('userForm');
        const formData = new FormData(form);
        
        const userData = {
            username: formData.get('username'),
            email: formData.get('email'),
            full_name: formData.get('full_name'),
            department: formData.get('department'),
            role: formData.get('role'),
            status: formData.get('status') || 'active'
        };

        // Validate required fields
        if (!userData.username || !userData.email || !userData.role) {
            this.showAlert('Please fill in all required fields', 'warning');
            return;
        }

        // Handle password for new users
        if (!this.editingUserId) {
            const password = formData.get('password');
            const confirmPassword = formData.get('confirm_password');
            
            if (!password || password.length < 8) {
                this.showAlert('Password must be at least 8 characters long', 'warning');
                return;
            }
            
            if (password !== confirmPassword) {
                this.showAlert('Passwords do not match', 'warning');
                return;
            }
            
            userData.password = password;
        }

        try {
            let response;
            if (this.editingUserId) {
                // Update existing user
                response = await authManager.apiCall(`/users/${this.editingUserId}`, {
                    method: 'PUT',
                    body: JSON.stringify(userData)
                });
            } else {
                // Create new user
                response = await authManager.apiCall('/register', {
                    method: 'POST',
                    body: JSON.stringify(userData)
                });
            }

            if (response.ok) {
                const result = await response.json();
                if (result.success) {
                    this.showAlert(
                        this.editingUserId ? 'User updated successfully' : 'User created successfully', 
                        'success'
                    );
                    
                    // Close modal and reload users
                    bootstrap.Modal.getInstance(document.getElementById('userModal')).hide();
                    await this.loadUsers();
                    await this.loadStatistics();
                } else {
                    throw new Error(result.error || 'Operation failed');
                }
            } else {
                throw new Error('Server error');
            }
        } catch (error) {
            console.error('Error saving user:', error);
            this.showAlert(error.message || 'Failed to save user', 'danger');
        }
    }

    async toggleUserStatus(userId) {
        const user = this.users.find(u => u.user_id === userId);
        if (!user) return;

        // Prevent users from disabling themselves
        if (userId === this.currentUser.user_id) {
            this.showAlert('You cannot modify your own account status', 'warning');
            return;
        }

        const newStatus = user.status === 'active' ? 'suspended' : 'active';
        const action = newStatus === 'active' ? 'activate' : 'suspend';
        
        if (!confirm(`Are you sure you want to ${action} this user?`)) {
            return;
        }

        try {
            const response = await authManager.apiCall(`/users/${userId}`, {
                method: 'PUT',
                body: JSON.stringify({ status: newStatus })
            });

            if (response.ok) {
                const result = await response.json();
                if (result.success) {
                    this.showAlert(`User ${action}d successfully`, 'success');
                    await this.loadUsers();
                    await this.loadStatistics();
                } else {
                    throw new Error(result.error || 'Operation failed');
                }
            } else {
                throw new Error('Server error');
            }
        } catch (error) {
            console.error('Error updating user status:', error);
            this.showAlert(error.message || 'Failed to update user status', 'danger');
        }
    }

    async showProfile() {
        if (!this.currentUser) return;

        document.getElementById('profileEmail').value = this.currentUser.email || '';
        document.getElementById('profileFullName').value = this.currentUser.full_name || '';
        document.getElementById('profileDepartment').value = this.currentUser.department || '';

        const modal = new bootstrap.Modal(document.getElementById('profileModal'));
        modal.show();
    }

    async updateProfile() {
        const form = document.getElementById('profileForm');
        const formData = new FormData(form);
        
        const profileData = {
            email: formData.get('email'),
            full_name: formData.get('full_name'),
            department: formData.get('department')
        };

        try {
            const response = await authManager.apiCall('/profile', {
                method: 'PUT',
                body: JSON.stringify(profileData)
            });

            if (response.ok) {
                const result = await response.json();
                if (result.success) {
                    this.currentUser = result.user;
                    this.updateCurrentUserDisplay();
                    this.showAlert('Profile updated successfully', 'success');
                    bootstrap.Modal.getInstance(document.getElementById('profileModal')).hide();
                } else {
                    throw new Error(result.error || 'Update failed');
                }
            } else {
                throw new Error('Server error');
            }
        } catch (error) {
            console.error('Error updating profile:', error);
            this.showAlert(error.message || 'Failed to update profile', 'danger');
        }
    }

    showChangePassword() {
        document.getElementById('changePasswordForm').reset();
        const modal = new bootstrap.Modal(document.getElementById('changePasswordModal'));
        modal.show();
    }

    async changePassword() {
        const form = document.getElementById('changePasswordForm');
        const formData = new FormData(form);
        
        const currentPassword = formData.get('current_password');
        const newPassword = formData.get('new_password');
        const confirmPassword = formData.get('confirm_new_password');

        if (!currentPassword || !newPassword || !confirmPassword) {
            this.showAlert('Please fill in all password fields', 'warning');
            return;
        }

        if (newPassword.length < 8) {
            this.showAlert('New password must be at least 8 characters long', 'warning');
            return;
        }

        if (newPassword !== confirmPassword) {
            this.showAlert('New passwords do not match', 'warning');
            return;
        }

        try {
            const response = await authManager.apiCall('/change-password', {
                method: 'POST',
                body: JSON.stringify({
                    current_password: currentPassword,
                    new_password: newPassword
                })
            });

            if (response.ok) {
                const result = await response.json();
                if (result.success) {
                    this.showAlert('Password changed successfully', 'success');
                    bootstrap.Modal.getInstance(document.getElementById('changePasswordModal')).hide();
                } else {
                    throw new Error(result.error || 'Password change failed');
                }
            } else {
                throw new Error('Server error');
            }
        } catch (error) {
            console.error('Error changing password:', error);
            this.showAlert(error.message || 'Failed to change password', 'danger');
        }
    }

    async refreshUsers() {
        await this.loadUsers();
        await this.loadStatistics();
        this.showAlert('Users refreshed successfully', 'success');
    }

    showAlert(message, type = 'info') {
        const alertContainer = document.getElementById('alertContainer');
        if (!alertContainer) return;

        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        alertContainer.insertBefore(alertDiv, alertContainer.firstChild);

        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    }
}

// Global functions for onclick handlers
function showProfile() {
    userManager.showProfile();
}

function showChangePassword() {
    userManager.showChangePassword();
}

function showCreateUser() {
    userManager.showCreateUser();
}

function saveUser() {
    userManager.saveUser();
}

function updateProfile() {
    userManager.updateProfile();
}

function changePassword() {
    userManager.changePassword();
}

function refreshUsers() {
    userManager.refreshUsers();
}

// Initialize user management
let userManager;
document.addEventListener('DOMContentLoaded', () => {
    userManager = new UserManagement();
});