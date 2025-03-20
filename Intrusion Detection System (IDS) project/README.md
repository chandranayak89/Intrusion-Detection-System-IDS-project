# 🛡️ Intrusion Detection System (IDS)

## Overview
This project implements a network intrusion detection system (IDS) that combines signature-based and anomaly-based detection methods to identify potential security threats and network intrusions. The system is designed to be lightweight and efficient for deployment in railway network environments.

## 🚀 Features
- **Real-time Network Traffic Monitoring** - Analyze network packets in real-time to detect suspicious activities
- **Signature-based Detection** - Detect known attack patterns and signatures
- **Machine Learning-based Anomaly Detection** - Detect unknown attacks by identifying deviations from normal behavior
- **SIEM Integration** - Forward alerts to Security Information and Event Management systems
- **Customizable Alert Rules** - Define rules for different types of attacks
- **Dashboard for Real-time Monitoring** - Visualize IDS activity and alerts

## 📊 Project Structure
```
Intrusion-Detection-System/
│── src/                     # Main source code
│   ├── data_preprocessing/   # Data collection and preprocessing scripts
│   ├── detection/            # ML-based & signature-based detection modules
│   ├── network_monitoring/   # Network traffic analysis tools
│   ├── siem_integration/     # Forwarding alerts to SIEM
│   ├── utils/                # Helper functions
│   └── main.py               # Main script to run IDS
│── config/                   # Configuration files
│── data/                     # Network traffic datasets
│── models/                   # Trained ML models
│── notebooks/                # Exploratory data analysis & model training
│── logs/                     # System logs and alerts
│── tests/                    # Unit tests for each module
│── requirements.txt          # Dependencies
│── README.md                 # Project description and setup guide
```

## 🔧 Installation & Setup
1. Clone the repository:
```bash
git clone https://github.com/yourusername/Intrusion-Detection-System.git
cd Intrusion-Detection-System
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
# For Windows
venv\Scripts\activate
# For Linux/Mac
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Download the required datasets (optional):
```bash
python src/data_preprocessing/download_datasets.py
```

## 🚀 Usage
1. Run the IDS system:
```bash
python src/main.py
```

2. Configure detection rules in `config/detection_rules.yaml`

3. View alerts in the logs directory or in your SIEM system

## 📘 Documentation
- [Data Preprocessing](docs/data_preprocessing.md)
- [Detection Modules](docs/detection.md)
- [Network Monitoring](docs/network_monitoring.md)
- [SIEM Integration](docs/siem_integration.md)
- [Alert Rules Configuration](docs/alert_rules.md)

## 🧪 Testing
Run the tests:
```bash
pytest tests/
```

## 📊 Datasets
The system has been tested with the following datasets:
- [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
- [NSL-KDD](https://www.unb.ca/cic/datasets/nsl.html)
- [UNSW-NB15](https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/)

## 🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/yourusername/Intrusion-Detection-System/issues).

## 📝 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
