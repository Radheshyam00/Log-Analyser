import re
import pandas as pd
import streamlit as st
from ipaddress import ip_address, ip_network
from geopy.geocoders import Nominatim
import joblib  # For Machine Learning
import numpy as np
from datetime import datetime

# Default log file path
DEFAULT_LOG_FILE_PATH = "../../access1.log"

# Regex pattern to extract key fields from the log line
log_pattern = r'(?P<ip_address>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d{3}) (?P<size>\S+) "(?P<referrer>[^"]+)" "(?P<user_agent>[^"]+)"'

# Function to parse each log line using regex
def parse_log_line(line):
    match = re.match(log_pattern, line)
    if match:
        return match.groupdict()
    return None

# Function to parse the entire log file
def parse_log_file(log_file_path):
    parsed_logs = []
    line_count = 0
    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                if line_count % 10000 == 0:
                    print("Processing line:", line_count)
                if line_count == 600000:
                    break
                parsed_log = parse_log_line(line)
                if parsed_log:
                    parsed_logs.append(parsed_log)
                line_count += 1
    except FileNotFoundError:
        return {"error": "Log file not found"}

    # Convert parsed logs to a DataFrame
    df = pd.DataFrame(parsed_logs)
    # Clean the 'size' column, converting '-' to 0 and making it numeric
    if 'size' in df.columns:
        df['size'] = pd.to_numeric(df['size'], errors='coerce').fillna(0)
    return df

# Function to detect potential IP spoofing
def detect_ip_spoofing(df):
    private_ip_ranges = [
        ip_network("10.0.0.0/8"),
        ip_network("172.16.0.0/12"),
        ip_network("192.168.0.0/16"),
        ip_network("127.0.0.0/8"),
        ip_network("169.254.0.0/16"),  # Link-local addresses
    ]
    df["is_spoofed"] = df["ip_address"].apply(
        lambda ip: any(ip_address(ip) in network for network in private_ip_ranges) if ip_address(ip) else False
    )
    spoofed_logs = df[df["is_spoofed"]]
    return spoofed_logs

# Function to perform Geo-IP Lookup
def geoip_lookup(ip):
    geolocator = Nominatim(user_agent="geoip_lookup")
    try:
        location = geolocator.geocode(ip)
        if location:
            return location.address
        else:
            return "Location not found"
    except Exception:
        return "Error in Geo-IP lookup"

def detect_ddos_attacks(df, time_window=10, request_threshold=100):
    # Check if 'timestamp' exists
    if "timestamp" not in df.columns:
        raise KeyError('"timestamp" column is missing from the DataFrame')

    # Convert 'timestamp' column to datetime, handling errors gracefully
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors='coerce')

    # Handle if the timestamp conversion results in NaT (Not a Time)
    if df["timestamp"].isna().sum() > 0:
        invalid_timestamps = df[df["timestamp"].isna()]
        print(f"Warning: {len(invalid_timestamps)} invalid timestamps found and removed.")
        df = df.dropna(subset=["timestamp"])  # Drop rows with invalid timestamps

    # Set the 'timestamp' column as the index
    df.set_index("timestamp", inplace=True)

    # Group by 'ip_address' and resample the data by the given time window
    grouped = df.groupby("ip_address").resample(f"{time_window}S").size().reset_index(name="request_count")

    # Filter logs based on request threshold for DDoS detection
    ddos_logs = grouped[grouped["request_count"] > request_threshold]

    if ddos_logs.empty:
        print("No DDoS/DoS attacks detected.")
    else:
        print(f"Detected {len(ddos_logs)} DDoS/DoS attack incidents.")
    
    return ddos_logs



# Function for Machine Learning-based anomaly detection
# def detect_anomalies(df):
#     model_path = "../anomaly_detection_model.pkl"
#     try:
#         model = joblib.load(model_path)
#         if {"status", "size"}.issubset(df.columns):
#             features = df[["status", "size"]].astype(float).values
#             df["anomaly"] = model.predict(features)
#             anomalies = df[df["anomaly"] == -1]
#             return anomalies
#     except FileNotFoundError:
#         return {"error": "Model file not found"}
#     return pd.DataFrame()

def detect_anomalies(df):
    model_path = "../anomaly_detection_model.pkl"
    try:
        model = joblib.load(model_path)

        # Ensure that all the expected features are in the dataframe
        expected_features = ["status", "size", "ip_address", "timestamp", "user_agent", "referrer", "request"]
        
        # Check if all expected features are present
        missing_features = [feature for feature in expected_features if feature not in df.columns]
        if missing_features:
            raise ValueError(f"Missing features: {', '.join(missing_features)}")

        # You may need to preprocess your features (e.g., encode categorical data)
        features = df[expected_features].copy()

        # Convert 'timestamp' to Unix timestamp (float)
        features["timestamp"] = features["timestamp"].astype(np.int64) // 10**9  # Convert to seconds

        # Example: Encoding categorical variables (if needed)
        features["user_agent"] = features["user_agent"].astype('category').cat.codes
        features["referrer"] = features["referrer"].astype('category').cat.codes

        # Ensure the features are numeric
        features = features.astype(float)

        # Predict anomalies
        df["anomaly"] = model.predict(features.values)
        anomalies = df[df["anomaly"] == -1]
        return anomalies
    
    except FileNotFoundError:
        return {"error": "Model file not found"}
    except ValueError as e:
        return {"error": str(e)}

    return pd.DataFrame()



# Streamlit App Initialization
def run_streamlit_app():
    st.title("Advanced Log Analyzer with Regex Parsing")
    
    # Sidebar input
    st.sidebar.header("Settings")
    log_file_path = st.sidebar.text_input("Log File Path", value=DEFAULT_LOG_FILE_PATH)
    
    # Initialize logs in session state
    if 'logs' not in st.session_state:
        st.session_state.logs = None
    
    # Main Streamlit App logic
    feature = st.selectbox("Choose a feature", ["Parse Section", "Analysis Section"])

    if feature == "Parse Section":
        # Load logs only if button is pressed
        if st.sidebar.button("Parse Logs"):
            st.write(f"Parsing logs from: {log_file_path}")
            st.session_state.logs = parse_log_file(log_file_path)
            
            # Check for parsing errors
            if isinstance(st.session_state.logs, dict) and "error" in st.session_state.logs:
                st.error(st.session_state.logs["error"])
            else:
                st.success("Logs parsed successfully!")
                st.write(f"Total log entries parsed: {len(st.session_state.logs)}")
                st.dataframe(st.session_state.logs)

    elif feature == "Analysis Section":
        if st.session_state.logs is not None and isinstance(st.session_state.logs, pd.DataFrame) and not st.session_state.logs.empty:
            st.sidebar.subheader("Analysis Tools")
            analysis_type = st.selectbox("Choose a feature", ["None", "IP Spoofing Detection", "Geo-IP Lookup", "DDoS/DoS Detection", "Anomaly Detection"])

            # IP Spoofing Detection
            if analysis_type == "IP Spoofing Detection":
                if st.sidebar.button("Detect Spoofed IPs"):
                    spoofed_logs = detect_ip_spoofing(st.session_state.logs)
                    if not spoofed_logs.empty:
                        st.write(f"Detected {len(spoofed_logs)} spoofed IPs.")
                        st.dataframe(spoofed_logs)
                    else:
                        st.write("No spoofed IPs detected.")

            # Geo-IP Lookup
            elif analysis_type == "Geo-IP Lookup":
                ip_to_lookup = st.sidebar.text_input("Enter IP Address for Geo-IP Lookup")
                if ip_to_lookup and st.sidebar.button("Perform Geo-IP Lookup"):
                    location = geoip_lookup(ip_to_lookup)
                    st.write(f"Geo-IP location for {ip_to_lookup}: {location}")

            # DDoS/DoS Detection
            elif analysis_type == "DDoS/DoS Detection":
                time_window = st.sidebar.slider("Time Window (seconds)", min_value=1, max_value=60, value=10)
                request_threshold = st.sidebar.number_input("Request Threshold", min_value=10, value=100)
                if st.sidebar.button("Detect DDoS/DoS Attacks"):
                    ddos_logs = detect_ddos_attacks(st.session_state.logs, time_window, request_threshold)
                    if not ddos_logs.empty:
                        st.write(f"DDoS/DoS incidents detected: {len(ddos_logs)}")
                        st.dataframe(ddos_logs)
                    else:
                        st.write("No DDoS/DoS attacks detected.")

            # Anomaly Detection
            elif analysis_type == "Anomaly Detection":
                if st.sidebar.button("Detect Anomalies"):
                    anomalies = detect_anomalies(st.session_state.logs)
                    if isinstance(anomalies, pd.DataFrame) and not anomalies.empty:
                        st.write(f"Anomalous logs detected: {len(anomalies)}")
                        st.dataframe(anomalies)
                    else:
                        st.write("No anomalies detected.")
        else:
            st.warning("Please parse the logs first in the 'Parse Section'.")

# Run the app
if __name__ == "__main__":
    run_streamlit_app()