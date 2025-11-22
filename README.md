# Digital Forensics Application

A comprehensive digital forensics application built with Python Flask backend and modern HTML/CSS/JS frontend. This application provides tools for analyzing digital evidence, managing forensic cases, and generating detailed analysis reports.

![Digital Forensics](https://img.shields.io/badge/Digital-Forensics-blue)
![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Flask](https://img.shields.io/badge/Flask-2.3+-green)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-purple)

## 🚀 Features

- **Evidence Upload & Analysis**: Upload various file types for forensic analysis
- **Hash Calculation**: Generate MD5, SHA1, and SHA256 hashes for file integrity
- **Case Management**: Create and manage forensic investigation cases
- **Security Scanning**: Basic security assessment of uploaded files
- **File Metadata Extraction**: Extract detailed file information and metadata
- **Analysis Results Export**: Export analysis results in various formats
- **Audit Logging**: Complete audit trail of all forensic activities
- **Responsive UI**: Modern, mobile-friendly interface with Bootstrap 5

## 📁 Project Structure

```
Digital Forensic/
├── .github/
│   └── copilot-instructions.md    # GitHub Copilot configuration
├── .vscode/
│   ├── launch.json               # VS Code debug configuration
│   └── settings.json             # VS Code workspace settings
├── backend/                      # Flask API backend
│   ├── api/                      # API endpoints
│   │   ├── __init__.py
│   │   ├── analysis_api.py       # Analysis results API
│   │   ├── file_api.py          # File management API
│   │   └── forensic_api.py      # Main forensic analysis API
│   ├── config/                   # Configuration files
│   │   ├── __init__.py
│   │   └── config.py            # Application configuration
│   ├── models/                   # Database models
│   │   ├── __init__.py
│   │   └── database.py          # SQLite database operations
│   ├── utils/                    # Utility functions
│   │   ├── __init__.py
│   │   ├── file_analyzer.py     # File analysis utilities
│   │   └── hash_calculator.py   # Hash calculation utilities
│   └── app.py                   # Main Flask application
├── frontend/                     # HTML/CSS/JS frontend
│   ├── assets/
│   │   └── images/              # Static images
│   ├── css/
│   │   └── style.css            # Custom styles
│   ├── js/
│   │   └── app.js               # Main application JavaScript
│   └── index.html               # Main HTML file
├── database/                     # SQLite database storage
├── forensic_results/            # Analysis results storage
├── logs/                        # Application logs
├── recovered_files/             # Recovered evidence files
├── uploads/                     # Uploaded evidence files
├── .env.example                 # Environment variables template
├── .gitignore                   # Git ignore rules
├── requirements.txt             # Python dependencies
└── README.md                    # This file
```

## ⚡ Quick Start

### Prerequisites

- Python 3.10 or higher
- Git (for version control)
- VS Code (recommended) with Python extension

### Installation

1. **Clone the repository**

   ```bash
   git clone <your-repo-url>
   cd "Digital Forensic"
   ```

2. **Create virtual environment**

   ```bash
   python -m venv venv

   # On Windows
   venv\Scripts\activate

   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**

   ```bash
   # Copy the example file
   copy .env.example .env

   # Edit .env with your settings
   # At minimum, change the SECRET_KEY for security
   ```

5. **Initialize the database**
   ```bash
   cd backend
   python -c "from models.database import Database; Database().init_database()"
   cd ..
   ```

### Running the Application

#### Option 1: Using VS Code (Recommended)

1. Open the project in VS Code
2. Press `F5` or go to `Run and Debug` panel
3. Select "Python: Flask" configuration
4. The backend will start at `http://localhost:5000`

#### Option 2: Command Line

```bash
# Start the Flask backend
cd backend
python app.py

# The application will be available at http://localhost:5000
```

#### Option 3: Frontend Development

If you want to run the frontend separately for development:

1. Install Live Server extension in VS Code
2. Right-click on `frontend/index.html`
3. Select "Open with Live Server"
4. Frontend will open at `http://localhost:5500`

## 📖 Usage Guide

### 1. Dashboard

- View system statistics and recent activity
- Monitor API health and system status
- Quick overview of cases and evidence

### 2. Upload Evidence

- Select files for forensic analysis
- Supported formats: Images, Documents, Archives, Disk Images
- Automatic hash calculation and analysis
- Case association for organization

### 3. Analysis Results

- View detailed analysis results
- File metadata and security assessment
- Hash verification and integrity checks
- Export results for reporting

### 4. Case Management

- Create new forensic cases
- Associate evidence with cases
- Track investigation progress
- Audit trail for all activities

### 5. Forensic Tools

- **Hash Calculator**: Generate file hashes
- **File Info**: Extract detailed metadata
- **Security Scanner**: Basic threat assessment

## 🔧 Configuration

### Environment Variables

The application uses environment variables for configuration. Copy `.env.example` to `.env` and modify:

```env
# Security - IMPORTANT: Change in production!
SECRET_KEY=your-unique-secret-key-here

# Database
DATABASE_URL=sqlite:///database/forensics.db

# File Upload
MAX_CONTENT_LENGTH=104857600  # 100MB
UPLOAD_FOLDER=uploads

# Logging
LOG_LEVEL=INFO

# Development
FLASK_DEBUG=True
```

### File Types Support

The application supports analysis of various file types:

- **Images**: JPG, PNG, GIF, BMP, TIFF
- **Documents**: PDF, DOC, DOCX, TXT, RTF
- **Archives**: ZIP, RAR, 7Z, TAR, GZ
- **Disk Images**: IMG, DD, RAW, ISO, VHD, VMDK
- **Other**: LOG, CSV, JSON, XML

## 🔒 Security Considerations

- **File Upload Security**: All uploads are validated for type and size
- **Hash Verification**: Files are automatically hashed for integrity
- **Audit Logging**: All activities are logged for forensic purposes
- **Secure Configuration**: Environment variables for sensitive data
- **Input Validation**: All user inputs are validated and sanitized
  
## 🔮 Roadmap

- [ ] Advanced malware detection
- [ ] Network traffic analysis
- [ ] Memory dump analysis
- [ ] Timeline analysis
- [ ] Report generation (PDF/HTML)
- [ ] Multi-user support with authentication
- [ ] Integration with external threat intelligence
- [ ] Advanced visualization tools
- [ ] Mobile application support
- [ ] Cloud storage integration
 analysis and educational purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

