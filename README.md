# Log Analyzer

## Overview
The **Log Analyzer** is a powerful tool designed to parse, analyze, and visualize Apache server access logs efficiently. It provides insightful data regarding web traffic, user behavior, and potential security threats by analyzing access logs.

## Features
- **Log Parsing:** Supports Apache server access logs in common formats.
- **Real-Time Analysis:** Processes logs dynamically and provides instant insights.
- **Filtering & Search:** Enables searching and filtering logs based on keywords, timestamps, or status codes.
- **Visualization:** Displays logs in an intuitive UI using charts and tables.
- **Alerts & Notifications:** Detects anomalies and sends alerts based on predefined rules.
- **User Authentication:** Secure access to log data with role-based permissions.
- **IP Geolocation Lookup:** Uses the ipinfo API to fetch geolocation details of IP addresses found in logs.

## Tech Stack
- **Programming Language:** Python
- **Framework:** Flask
- **Libraries & Tools:**
  - Pandas (log processing)
  - Matplotlib/Plotly (data visualization)
  - Requests (API integration with ipinfo.io)

## Installation
### Prerequisites
- Python 3.8+
- Virtual Environment (optional but recommended)
- ipinfo API Key (Sign up at [ipinfo.io](https://ipinfo.io/))

### Setup
1. **Clone the repository:**
   ```bash
   git clone https://github.com/Radheshyam00/Log-Analyser.git
   cd Log-Analyser
   ```

2. **Setup (Flask & Python)**
   ```bash
   python -m venv venv  # Create a virtual environment
   source venv/bin/activate  # Activate (Linux/macOS)
   venv\Scripts\activate  # Activate (Windows)
   pip install -r requirements.txt  # Install dependencies
   export IPINFO_API_KEY="your_api_key_here"  # Set API Key (Linux/macOS)
   set IPINFO_API_KEY="your_api_key_here"  # Set API Key (Windows)
   streamlit run App.py  # Start the server
   ```

## Usage
- Access the API at `http://localhost:5000`.
- Upload Apache access log files for analysis.
- Use filters and search to analyze log data.
- View logs in table format or interactive charts.
- Retrieve geolocation details of IP addresses from logs using ipinfo.

## API Endpoints
| Method | Endpoint | Description |
|--------|---------|-------------|
| GET | `/logs` | Fetch all logs |
| POST | `/upload` | Upload an Apache access log file |
| GET | `/logs?filter=error` | Filter logs by keyword |
| GET | `/logs/:id` | Fetch log details by ID |
| GET | `/ipinfo/:ip` | Fetch geolocation details of an IP address using ipinfo API |

## SARIMA for Traffic Forecasting in Log Analysis
SARIMA is suitable for time-series data with seasonal patterns, which is often the case in log data (e.g., higher traffic during business hours). The model handles:
- Autoregressive and moving average trends
- Differencing for stationarity
- Seasonal effects (e.g., daily, weekly traffic cycles)

Model Notation:
```bash
   SARIMA(p, d, q)(P, D, Q, s)
   ```
Where:
- (p, d, q) are the non-seasonal parameters
- (P, D, Q, s) are the seasonal parameters, with s being the seasonal cycle length (e.g., 24 for hourly data in a day)

**Run SARIMA Model:**
```bash
   streamlit run mTrain.py
   ```


## Contributing
1. Fork the repository.
2. Create a new branch: `git checkout -b feature-branch`
3. Commit changes: `git commit -m "Added a new feature"`
4. Push to the branch: `git push origin feature-branch`
5. Submit a pull request.

## Demo

1. [Log Analyzer](https://log-analyser-c3cjt8wcknel7pecdsjxh3.streamlit.app/)
2. [SARIMA Model](https://sarima-model.streamlit.app/)

## License
This project is licensed under the MIT License. See the `LICENSE` file for more details.

## Contact
For support or inquiries, contact **portfolio-radhe00.vercel.app** or open an issue on GitHub.




