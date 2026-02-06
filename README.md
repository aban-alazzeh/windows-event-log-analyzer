# Windows Event Logs AI Analyzer

A hybrid machine learning and heuristic-based system for detecting suspicious activities in Windows Event Logs. This tool analyzes Security, System, and PowerShell logs to identify potential security threats including brute force attacks, privilege escalation, malicious PowerShell execution, and suspicious service installations.

## Requirements

- Python 3.8 or higher
- Windows Event Viewer CSV exports

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/windows-event-analyzer.git
cd windows-event-analyzer
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### 1. Export Event Logs from Windows Event Viewer

Export the following logs as CSV files:
- **Security.evtx** → Save as `security.csv`
- **System.evtx** → Save as `system.csv`
- **Microsoft-Windows-PowerShell/Operational.evtx** → Save as `powershell.csv`

### 2. Run the Application

```bash
streamlit run app.py
```

### 3. Access the Web Interface

The application will automatically open in your browser at:
```
http://localhost:8501
```

### 4. Analyze Logs

1. Upload your three CSV files (Security, System, PowerShell)
2. Click "🚀 Analyze Logs"
3. Review the verdict and detailed detection results

## Project Structure

```
windows-event-analyzer/
├── app.py                              # Streamlit web interface
├── engine/
│   └── analyze.py                      # Core analysis engine
├── models/
│   ├── brute_force_model.pkl
│   ├── powershell_suspicious_model.pkl
│   ├── privilege_escalation_model.pkl
│   └── service_installation_model.pkl
├── requirements.txt
└── README.md
```

## How It Works

1. **Feature Extraction**: Groups events into 5-minute time windows
2. **ML Prediction**: Four trained models analyze event patterns
3. **Heuristic Analysis**: Domain-specific rules reduce false positives
4. **Verdict Generation**: Combines detectors to determine final verdict

## Detection Logic

- **Benign**: Normal Windows operations and routine activities
- **Suspicious**: Detected attack patterns or anomalous behavior


## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Contact

For questions or support, please open an issue on GitHub.
