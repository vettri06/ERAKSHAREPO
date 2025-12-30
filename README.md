# IoT Security Scanner (eRaksha) 🛡️

A comprehensive, full-stack IoT security assessment tool designed to discover, analyze, and secure IoT devices on local networks. This application combines traditional network scanning with AI/ML-based anomaly detection to identify vulnerabilities and classify devices in real-time.

## 🚀 Key Features

*   **🔍 Network Discovery**: Automatically scans local subnets to identify connected devices (IP, MAC, Vendor).
*   **🛡️ Vulnerability Assessment**: Integration with the National Vulnerability Database (NVD) to detect known CVEs for running services.
*   **🤖 AI Device Classification**: Uses Machine Learning (Gradient Boosting) to identify device types (e.g., Camera, Router, Smart Speaker) based on traffic behavior.
*   **📉 Anomaly Detection**: Unsupervised learning (Isolation Forest) to flag suspicious network behavior and potential zero-day attacks.
*   **📊 Interactive Dashboard**: Real-time React-based UI to visualize network security posture, active devices, and risk levels.
*   **📄 PDF Reporting**: Generate professional security audit reports with one click.
*   **⚡ Real-time Updates**: WebSocket integration for live scan progress and logging.

## 🛠️ Technology Stack

### Backend
*   **Python 3.10+**
*   **FastAPI**: High-performance API framework.
*   **Nmap**: Core network scanning engine.
*   **Scikit-learn**: ML models for classification and anomaly detection.
*   **Pandas/Numpy**: Data processing.

### Frontend
*   **React 18**: UI Library.
*   **TypeScript**: Type safety.
*   **Vite**: Build tool.
*   **Tailwind CSS & Shadcn/UI**: Styling and components.
*   **Recharts**: Data visualization.

## 📋 Prerequisites

Before running the application, ensure you have the following installed:

1.  **Python 3.10+**: [Download Python](https://www.python.org/downloads/)
2.  **Node.js & npm**: [Download Node.js](https://nodejs.org/)
3.  **Nmap**: [Download Nmap](https://nmap.org/download.html)
    *   *Windows*: Ensure `nmap` is added to your system PATH.
    *   *Linux/Mac*: `sudo apt install nmap` or `brew install nmap`.

## ⚙️ Installation & Setup

### 1. Clone the Repository
```bash
git clone <repository-url>
cd iot-security-scanner
```

### 2. Backend Setup
Navigate to the backend directory and install dependencies:

```bash
cd backend
# Create virtual environment (Optional but recommended)
python -m venv venv
# Windows
.\venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

**Configuration:**
Open `backend/config.py` and add your NVD API Key (optional but recommended for faster scans):
```python
NVD_API_KEY = "your-nvd-api-key-here"
```

### 3. Frontend Setup
Navigate to the frontend directory and install dependencies:

```bash
cd ../frontend
npm install
```

## 🚀 Running the Application

### Start the Backend
From the `backend` directory:
```bash
python api.py
```
* The API will start at `http://localhost:8000`
* Swagger Docs available at `http://localhost:8000/docs`

### Start the Frontend
From the `frontend` directory:
```bash
npm run dev
```
* The application will run at `http://localhost:8080` (or similar, check console output).

## 📖 Usage Guide

1.  **Dashboard**: Open the frontend URL in your browser.
2.  **Select Interface**: Choose the network interface (Wi-Fi/Ethernet) you want to scan.
3.  **Start Scan**: Click "Start Scan" to begin discovery.
    *   *Quick Scan*: Ping scan + Top ports.
    *   *Deep Scan*: Full port scan + Service version detection.
4.  **View Results**:
    *   Click on devices to see detailed vulnerability reports.
    *   Check the "Vulnerabilities" tab for a prioritized list of risks.
5.  **Export**: Click "Export Report" to download a PDF summary.

## 📂 Project Structure

```
iot-security-scanner/
├── backend/                # Python FastAPI Server
│   ├── iot_security/       # Core Security Modules (AI, Nmap, Vuln Check)
│   ├── models/             # Trained ML Models (.pkl)
│   ├── api.py              # API Entry Point
│   ├── iot_scanner.py      # Main Scanner Logic
│   └── requirements.txt    # Python Dependencies
├── frontend/               # React Application
│   ├── src/
│   │   ├── components/     # UI Components
│   │   ├── pages/          # Application Views
│   │   └── services/       # API Integration
│   └── package.json        # Frontend Dependencies
└── README.md               # Project Documentation
```

## 🤝 Contributing

Contributions are welcome! Please fork the repository and submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---
*Built with ❤️ for IoT Security Research*
