# WebShield - Flask-Based Vulnerability Scanner

WebShield is a **Flask-based vulnerability scanner** designed to help users identify and analyze security issues in web applications. It integrates multiple security tools like **Nmap, OWASP ZAP, and threat intelligence sources** to provide **comprehensive security scanning**.

---

## Features
✅ **User Authentication** - Secure login and registration using Flask-Login & bcrypt.  
✅ **Multiple Scan Modes** - Quick, Full, and Custom scans to suit different security needs.  
✅ **Nmap Integration** - Port scanning and service detection.  
✅ **OWASP ZAP Integration** - Web vulnerability scanning for common threats like **SQL Injection, XSS, and Directory Traversal**.  
✅ **Threat Intelligence** - Fetches **CVE details** and indicators from external sources like **NVD & Abuse.ch**.  
✅ **Real-time Scan Monitoring** - Live scan progress tracking with event updates.  
✅ **Detailed Reporting** - Generates **HTML, JSON, and PDF** reports with vulnerability details.  
✅ **Dark Mode UI** - Sleek Bootstrap-powered dashboard with an intuitive user interface.  

---

## Installation

### **1. Clone the Repository**
```bash
git clone https://github.com/yourusername/WebShield.git
cd WebShield
```

### **2. Create a Virtual Environment & Install Dependencies**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### **3. Set Up Environment Variables**
Create a `.env` file in the root directory and configure the following:
```
FLASK_APP=main.py
FLASK_ENV=production
SESSION_SECRET=your_secret_key
DATABASE_URL=sqlite:///vulnscanner.db
```

### **4. Initialize the Database**
```bash
flask db upgrade
```

### **5. Run the Application**
```bash
python main.py
```
Visit **`http://127.0.0.1:5000/`** in your browser.

---

## Usage
### **1. Register & Login**
Create an account and log in to access the dashboard.

### **2. Start a Security Scan**
- Navigate to the **Dashboard**
- Click **"New Scan"** and enter a **Target URL**
- Choose from **Quick, Full, or Custom Scan**
- Monitor scan progress in real-time

### **3. View & Export Reports**
- Once the scan is complete, view the detailed report
- Export the report in **PDF, HTML, or JSON** format

---

## API Endpoints
| Method | Endpoint | Description |
|--------|-------------|-------------|
| `POST` | `/scan` | Start a new scan |
| `GET`  | `/scan/<scan_id>` | Get scan details |
| `GET`  | `/report/<report_id>` | View scan report |
| `GET`  | `/api/scan/status/<scan_id>` | Get scan status |
| `POST` | `/api/scan/cancel/<scan_id>` | Cancel an ongoing scan |
| `GET`  | `/report/export/<report_id>?format=pdf` | Export report |

---

## Technology Stack
- **Backend:** Flask, SQLAlchemy, Flask-Login
- **Frontend:** Bootstrap, Jinja2, JavaScript
- **Database:** SQLite (default) / MySQL
- **Security Tools:** Nmap, OWASP ZAP, Threat Intelligence APIs

---

## Contributing
We welcome contributions! Please follow these steps:
1. Fork the repository
2. Create a new branch (`feature-branch`)
3. Commit changes and push to GitHub
4. Submit a pull request

---

## Contributers 
