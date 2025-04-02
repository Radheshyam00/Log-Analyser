# Log Analyzer

## Overview
The **Log Analyzer** is a powerful tool designed to parse, analyze, and visualize log files efficiently. It provides insightful data regarding system logs, security logs, and application logs, helping users identify patterns, detect anomalies, and troubleshoot issues.

## Features
- **Log Parsing:** Supports multiple log formats (JSON, CSV, plain text, etc.).
- **Real-Time Analysis:** Processes logs dynamically and provides instant insights.
- **Filtering & Search:** Enables searching and filtering logs based on keywords, timestamps, or severity levels.
- **Visualization:** Displays logs in an intuitive UI using charts and tables.
- **Alerts & Notifications:** Detects anomalies and sends alerts based on predefined rules.
- **User Authentication:** Secure access to log data with role-based permissions.

## Tech Stack
- **Programming Language:** Python
- **Framework:** Flask
- **Libraries & Tools:**
  - Pandas (log processing)
  - Matplotlib/Plotly (data visualization)

## Installation
### Prerequisites
- Python 3.8+
- Virtual Environment (optional but recommended)

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
   streamlit run app.py  # Start the server
   ```

## Usage
- Access the API at `http://localhost:5000`.
- Upload log files or connect to live log sources.
- Use filters and search to analyze log data.
- View logs in table format or interactive charts.

## API Endpoints
| Method | Endpoint | Description |
|--------|---------|-------------|
| GET | `/logs` | Fetch all logs |
| POST | `/upload` | Upload a log file |
| GET | `/logs?filter=error` | Filter logs by keyword |
| GET | `/logs/:id` | Fetch log details by ID |

## Contributing
1. Fork the repository.
2. Create a new branch: `git checkout -b feature-branch`
3. Commit changes: `git commit -m "Added a new feature"`
4. Push to the branch: `git push origin feature-branch`
5. Submit a pull request.

## License
This project is licensed under the MIT License. See the `LICENSE` file for more details.

## Contact
For support or inquiries, contact **portfolio-radhe00.vercel.app** or open an issue on GitHub.

