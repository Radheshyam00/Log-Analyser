import os
import pandas as pd
import numpy as np
import seaborn as sns
from datetime import datetime
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import streamlit as st
import csv
import apache_log_parser
from io import StringIO
import requests
import time
import folium
from folium.plugins import MarkerCluster
from streamlit_folium import folium_static
import pydeck as pdk
import re
import socket
from concurrent import futures
import altair as alt
import plotly.express as px
from ipwhois import IPWhois
from sklearn.preprocessing import StandardScaler


# Define the Apache log line parser
access_log_line_parser = apache_log_parser.make_parser(
    "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\""
)

# Sample regex pattern to extract key fields from the log line
log_pattern = r'(?P<ip_address>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d{3}) (?P<size>\S+) "(?P<referrer>[^"]+)" "(?P<user_agent>[^"]+)"'

# Function to parse each log line using regex
def parse_log_line(line):
    match = re.match(log_pattern, line)
    if match:
        return match.groupdict()
    return None
# Function to parse the log file and convert it to CSV
def parse_log_file_to_csv(logfile, output_filename):
    faulty_lines = 0
    total_line_counter = 0
    write_header = True

    # Prepare an in-memory file using StringIO
    output = StringIO()
    writer = csv.writer(output)

    # Split the logfile content into lines
    lines = logfile.splitlines()

    for line in lines:
        total_line_counter += 1
        try:
            # Parse the log line
            line_data = access_log_line_parser(line)

            # Write the header only once, rename remote_host to ip_address
            if write_header:
                line_data = {key.replace("remote_host", "ip_address"): value for key, value in line_data.items()}
                writer.writerow(line_data.keys())
                write_header = False

            # Write the data values for each line
            writer.writerow(line_data.values())
        except Exception as ex:
            faulty_lines += 1
            print(f"Failed to parse line {total_line_counter}: {line.strip()}")

    # Move the StringIO cursor to the beginning
    output.seek(0)

    # Convert StringIO to bytes and return it
    return output.getvalue().encode(), faulty_lines

# Function to get location information based on IP address
def get_ip_location(ip_address, api_key):
    url = f"https://ipinfo.io/{ip_address}?token={api_key}"
    try:
        response = requests.get(url)

        # Handle successful API response
        if response.status_code == 200:
            return response.json()
        else:
            st.error(f"Failed to get location for IP: {ip_address}, Status Code: {response.status_code}")
            return None
    except Exception as e:
        st.error(f"Error fetching data for IP: {ip_address}, Error: {str(e)}")
        return None

# Function to create and display the world map for IP address locations
def plot_ip_locations_on_map(unauthorized_users):
    # Initialize a map centered around a default location
    map_center = [20, 0]  # Coordinates (latitude, longitude) for the center of the map (global center)
    map_ = folium.Map(location=map_center, zoom_start=2, control_scale=True)

    # Initialize MarkerCluster for better visualization when there are many markers
    marker_cluster = MarkerCluster().add_to(map_)

    # Loop through unauthorized users and add markers to the map
    for _, row in unauthorized_users.iterrows():
        ip_address = row['ip_address']
        location = row['location']
        
        if location and 'loc' in location:  # Check if the location data is valid
            loc = location['loc'].split(',')  # 'loc' is in the format 'lat,lon'
            lat, lon = float(loc[0]), float(loc[1])

            # Add a marker for each unauthorized user IP
            folium.Marker(
                location=[lat, lon],
                popup=f"IP: {ip_address}\nLocation: {location.get('city', 'Unknown')}, {location.get('country', 'Unknown')}",
                icon=folium.Icon(color='red')
            ).add_to(marker_cluster)

    return map_
    
def extract_ip_addresses(log_file):
    ip_list = []
    # Read the uploaded file content as text
    log_content = log_file.getvalue().decode("utf-8")  # Decode bytes to string
    for line in log_content.splitlines():  # Process each line
        # Use regex to find the first non-whitespace sequence (likely the IP address)
        match = re.match(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
        if match:
            ip_list.append(match.group(0))
    return ip_list

# Step 2: Create DataFrame and save IP addresses to CSV
def save_ip_addresses_to_csv(ip_list):
    df = pd.DataFrame(ip_list, columns=['IP Address'])
    csv_file = 'ip_addresses.csv'
    df.to_csv(csv_file, index=False)
    return csv_file, df

# Step 3: Define the Reverse DNS Lookup Function
def reverse_dns_lookup(ip_list, timeout=10):
    """Perform reverse DNS lookup for a list of IP addresses."""
    socket.setdefaulttimeout(timeout)
    count_df = pd.Series(ip_list).value_counts().reset_index()
    count_df.columns = ['ip_address', 'count']
    count_df = count_df.assign(
        perc=count_df['count'] / count_df['count'].sum(),
        cum_perc=lambda df: df['perc'].cumsum()
    )
    
    hosts = []
    max_workers = min(640, len(ip_list) if len(ip_list) > 0 else 1)
    def single_request(ip):
        try:
            hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
            hosts.append([ip, hostname, '@@'.join(aliaslist), '@@'.join(ipaddrlist), None])
        except Exception as e:
            hosts.append([ip, None, None, None, str(e)])
    
    with futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(single_request, count_df['ip_address'])
    
    df = pd.DataFrame(hosts, columns=['ip', 'hostname', 'aliaslist', 'ipaddrlist', 'errors'])
    final_df = pd.merge(count_df, df, left_on='ip_address', right_on='ip', how='left').drop('ip', axis=1)
    return final_df

def load_and_prepare_data(file):
    try:
        df_logs = pd.read_csv(file)

        if df_logs.empty:
            st.error("The dataset is empty.")
            return None

        if 'timestamp' not in df_logs.columns:
            st.error(f"'timestamp' column not found. Available columns are: {df_logs.columns}")
            return None

        df_logs['timestamp'] = pd.to_datetime(df_logs['timestamp'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')
        df_logs.dropna(subset=['timestamp'], inplace=True)
        df_logs.set_index('timestamp', inplace=True)

        return df_logs
    except Exception as e:
        st.error(f"Error while loading or preparing data: {e}")
        return None

# Function to monitor and visualize traffic within a time range
def monitor_traffic_in_range(df_logs, start_time, end_time, resample_interval='h', alert_threshold=3, graph_type='Matplotlib', matplot_graph_type='line'):
    try:
        # Filter data within the specified time range
        filtered_logs = df_logs[(df_logs.index >= start_time) & (df_logs.index <= end_time)]

        if filtered_logs.empty:
            st.warning(f"No data found between {start_time} and {end_time}.")
            return

        # Resample data based on the specified interval
        traffic_volume = filtered_logs.resample(resample_interval).size()

        # Calculate traffic statistics for alerting
        avg_traffic = traffic_volume.mean()
        std_dev_traffic = traffic_volume.std()
        alert_level = avg_traffic + alert_threshold * std_dev_traffic

        # Identify time points where traffic exceeds the alert threshold
        alert_times = traffic_volume[traffic_volume > alert_level]

        # Display the chosen graph type
        with st.expander("Traffic Graph"):
            # st.subheader(f"Displaying {graph_type} graph")

            # Matplotlib Plot
            if graph_type == 'Matplotlib':
                fig, ax = plt.subplots(figsize=(14, 7))
    
                if matplot_graph_type == 'line':
                    ax.plot(traffic_volume.index, traffic_volume.values, label='Traffic Volume', color='blue')
                elif matplot_graph_type == 'bar':
                    ax.bar(traffic_volume.index, traffic_volume.values, label='Traffic Volume', color='blue')
                
                ax.axhline(y=alert_level, color='red', linestyle='--', label='Alert Threshold')
                ax.scatter(alert_times.index, alert_times.values, color='red', label='Alert', marker='x')
                ax.set_xlabel('Timestamp')
                ax.set_ylabel('Number of Requests')
                ax.set_title(f'Traffic Volume from {start_time} to {end_time} - {resample_interval.upper()} Interval')
                ax.legend()
                ax.grid(True)
    
                # Show the Matplotlib plot
                st.pyplot(fig)
    
            # Display the alert times and values
        with st.expander("Alert Options"):
            if not alert_times.empty:
                st.warning("Traffic Alert! High traffic detected at the following times:")
                st.dataframe(alert_times.rename("Requests"))

    except Exception as e:
        st.error(f"Error during traffic monitoring: {e}")


# Function to analyze the top 10 most visited products
def analyze_top_10_products(df):
    try:
        # Extract product IDs or names from the 'request' column (assuming product info is in the URL)
        df['product_id'] = df['request'].str.extract(r'/product/(\d+)')

        # Get the top 10 most visited products
        top_10_products = df['product_id'].value_counts().head(10).reset_index()
        top_10_products.columns = ['Product_ID', 'Count']

        # Display results
        with st.expander("Visualize Top 10 Visited Product "):
                st.bar_chart(top_10_products.set_index('Product_ID')['Count'])
        with st.expander("Download Top 10 Visited Product File"):
                st.write(top_10_products)

    except Exception as e:
        st.error(f"Error during top 10 product analysis: {e}")

# Function to analyze product models from URLs
def analyze_product_models(df):
    try:
        # Extract product models from the 'request' column (adjust the regex if necessary)
        df['product_model'] = df['request'].str.extract(r'/product/\d+/([^/]+)')

        # Get the top 10 most common product models
        top_product_models = df['product_model'].value_counts().head(10).reset_index()
        top_product_models.columns = ['Product_Model', 'Count']

        # Display results
        with st.expander("Visualize Product models"):
            st.bar_chart(top_product_models.set_index('Product_Model')['Count'])
        with st.expander("Download Top 10 Product models File"):
            st.write(top_product_models)

    except Exception as e:
        st.error(f"Error extracting product models: {e}")

# Function to detect bot hits (Googlebot, Bingbot, Slurp, Baiduspider, etc.)
def detect_bots(df_filtered):
    # Define regex patterns for different bots
    bot_patterns = {
        'Googlebot': r"Googlebot|Googlebot/[0-9\.]+|Googlebot-.*|Googlebot-Mobile",
        'Bingbot': r"Bingbot",
        'Slurp': r"Slurp",
        'Baiduspider': r"Baiduspider",
        'YandexBot': r"YandexBot",
        'DuckDuckBot': r"DuckDuckBot",
        'FacebookExternalHit': r"FacebookExternalHit",
        'Twitterbot': r"Twitterbot"
    }
    
    # Initialize an empty dictionary to store bot hits
    bot_hits = {bot_name: None for bot_name in bot_patterns.keys()}
    
    # Loop through each bot pattern and filter the DataFrame
    for bot_name, pattern in bot_patterns.items():
        bot_hits[bot_name] = df_filtered[df_filtered['user_agent'].str.contains(pattern, flags=re.IGNORECASE, na=False)]
    
    return bot_hits

# Function to create and display bot traffic charts
def plot_bot_hits(df_filtered, chart_type='bar'):
    try:
        # Get the bot hits data
        bot_hits = detect_bots(df_filtered)
        
        # Count bot hits for each bot type
        bot_counts = {bot_name: bot_df.shape[0] for bot_name, bot_df in bot_hits.items()}
        
        # Total hits excluding bots
        total_hits = df_filtered.shape[0]
        non_bot_hits = total_hits - sum(bot_counts.values())
        
        # Prepare data for the chart
        bot_counts['Rest Of Data'] = non_bot_hits
        
        # Create the chart
        fig, ax = plt.subplots(figsize=(10, 6))
        
        if chart_type == 'bar':
            # Bar chart
            ax.bar(bot_counts.keys(), bot_counts.values(), color=['#66c2a5', '#fc8d62', '#8da0cb', '#e78ac3', '#a6d854', '#ff7f00', '#d9d9d9', '#ff99ff'])
            ax.set_ylabel('Hit Count')
            ax.set_title('Bot Traffic Breakdown (Bar Chart)')
        
        elif chart_type == 'line':
            # Line chart
            ax.plot(list(bot_counts.keys()), list(bot_counts.values()), marker='o', color='b', linestyle='-', linewidth=2)
            ax.set_ylabel('Hit Count')
            ax.set_title('Bot Traffic Breakdown (Line Chart)')
        
        elif chart_type == 'pie':
            # Pie chart
            pie_data = list(bot_counts.values())
            pie_labels = list(bot_counts.keys())
            pie_explode = [0.1] * len(pie_data)  # Slightly explode each slice for better visibility
            
            ax.pie(pie_data, labels=pie_labels, autopct='%1.1f%%', startangle=90, colors=plt.cm.Paired.colors, explode=pie_explode)
            ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
            ax.set_title('Bot Traffic Breakdown (Pie Chart)')
        
        # Fix xticks for bar and line charts
        if chart_type in ['bar', 'line']:
            ax.set_xticks(range(len(bot_counts)))
            ax.set_xticklabels(list(bot_counts.keys()), rotation=45, ha="right")
            
        with st.expander("Visualize Bot Detection"):
            st.pyplot(fig)
        
        # Display bot counts table
        bot_counts_df = pd.DataFrame(list(bot_counts.items()), columns=["Bot_Type", "Count"])
        bot_counts_df = bot_counts_df.sort_values(by="Count", ascending=False)
        with st.expander("Download Bot Detection File"):
            st.write(bot_counts_df)
        
    except Exception as e:
        st.error(f"Error plotting bot hits: {e}")

# ..............................................................................................................................................................................

# Function to manually parse the timestamp with improved error handling
def parse_timestamp(timestamp_str):
    try:
        return datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
    except ValueError:
        st.warning(f"Invalid timestamp format: {timestamp_str}")
        return pd.NaT


# Function to analyze referrer field with friendly categorization
def analyze_referrer(df):
    if 'referrer' in df.columns:
        # Filter out empty referrers
        df = df[df['referrer'] != "-"]

        # Categorize referrers as "friendly" or "non-friendly"
        df['referrer_category'] = df['referrer'].apply(
            lambda x: "Friendly" if x.startswith("https://www.zanbil.ir") else "Non-Friendly"
        )

        # Count occurrences of each category
        referrer_counts = df['referrer_category'].value_counts().reset_index()
        referrer_counts.columns = ['referrer_category', 'count']

        # List only non-friendly referrers
        non_friendly_referrers = df[df['referrer_category'] == "Non-Friendly"]['referrer'].value_counts().reset_index()
        non_friendly_referrers.columns = ['referrer', 'count']

        return referrer_counts, non_friendly_referrers
    return None, None



# Filter for 5xx status codes and identify high response sizes
def get_5xx_status_ips(df):
    if 'status' in df.columns and 'size' in df.columns:
        # Filter for 5xx status codes
        df_5xx = df[df['status'].between(500, 599)]
        
        # Calculate high response size threshold (e.g., 95th percentile)
        size_threshold = df_5xx['size'].quantile(0.95)
        
        # Mark IPs with high response sizes
        df_5xx['high_response_size'] = df_5xx['size'] > size_threshold
        
        # Group by IP and status code, counting occurrences
        ip_5xx_summary = df_5xx.groupby(['ip_address', 'status', 'high_response_size']).size().reset_index(name='count')
        
        return ip_5xx_summary, size_threshold
    return None, None
    
# Function to detect bots with high request frequency
def detect_high_frequency_bots(df, time_interval='1min', request_threshold=100):
    # Convert the timestamp to datetime if not already
    if df['timestamp'].dtype == 'object':
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    
    # Drop rows with invalid timestamps
    df = df.dropna(subset=['timestamp'])
    
    # Set timestamp as index for resampling
    df.set_index('timestamp', inplace=True)
    
    # Resample and count requests per IP within the time interval
    request_counts = df.groupby('ip_address').resample(time_interval).size().reset_index(name='request_count')
    
    # Identify IPs with request count above the threshold
    high_frequency_bots = request_counts[request_counts['request_count'] > request_threshold]
    
    return high_frequency_bots


# Machine learning for anomaly detection (Isolation Forest)
# Machine learning for anomaly detection (Isolation Forest)
def apply_isolation_forest(df, contamination_threshold=0.05):
    # st.subheader("Anomaly Detection using Isolation Forest")
    # st.markdown("### Anomaly Detection using Isolation Forest")

    if 'size' in df.columns and 'status' in df.columns and 'ip_address' in df.columns:
        # Calculate the size threshold (95th percentile)
        size_threshold = df['size'].quantile(0.95)
    
        # Filter out rows where both the response size is below the threshold and status code is 200
        filtered_df = df[~((df['size'] < size_threshold) & (df['status'] == 200))]
    
        if filtered_df.empty:
            st.write("No data available after applying filtering conditions.")
        else:
            # Prepare data for Isolation Forest (use size and request_count as features)
            filtered_df['request_count'] = filtered_df.groupby('ip_address')['timestamp'].transform('count')
    
            # Remove rows with NaN values in relevant columns
            clean_df = filtered_df[['size', 'request_count']].dropna()
    
            if clean_df.empty:
                st.write("Insufficient data for anomaly detection (missing values).")
            else:
                # Scaling the features
                scaler = StandardScaler()
                features_scaled = scaler.fit_transform(clean_df)
    
                # Apply Isolation Forest
                iso_forest = IsolationForest(contamination=contamination_threshold, random_state=42)
                filtered_df['anomaly'] = iso_forest.fit_predict(features_scaled)
    
                anomalies = filtered_df[filtered_df['anomaly'] == -1]
    
                if not anomalies.empty:
                    
    
                    # Visualize anomalies
                    anomaly_chart = alt.Chart(anomalies).mark_bar(color="purple").encode(
                        x=alt.X('ip_address:N', title="IP Address"),
                        y=alt.Y('size:Q', title="Response Size")
                    ).properties(width=600, height=400)
                    st.altair_chart(anomaly_chart)
                    st.write("Anomalous Requests Detected:")
                    st.write(anomalies[['ip_address', 'size', 'status', 'timestamp']])
                else:
                    st.write("No anomalies detected by Isolation Forest.")
    else:
        st.write("Size, Status, or Request Count column missing for machine learning anomaly detection.")




# Function to extract platform information from user agent
def extract_platform(user_agent):
    if pd.isna(user_agent):
        return "Unknown"
    if "Windows" in user_agent:
        return "Windows"
    elif "Macintosh" in user_agent:
        return "Mac"
    elif "Android" in user_agent:
        return "Android"
    elif "iPhone" in user_agent or "iOS" in user_agent:
        return "iOS"
    elif "Linux" in user_agent:
        return "Linux"
    else:
        return "Other"
# Function to load and process the uploaded file with additional checks
def load_data(uploaded_file):
    try:
        df = pd.read_csv(uploaded_file)
        
        # Ensure essential columns exist
        required_columns = ['timestamp', 'ip_address', 'status', 'size', 'user_agent']
        missing_cols = [col for col in required_columns if col not in df.columns]
        if missing_cols:
            st.error(f"Missing columns: {', '.join(missing_cols)}")
            return None
        
        # Parse timestamp if exists
        if 'timestamp' in df.columns:
            df['timestamp'] = df['timestamp'].apply(parse_timestamp)
        
        # Convert necessary columns to numeric
        if 'status' in df.columns:
            df['status'] = pd.to_numeric(df['status'], errors='coerce')
        if 'size' in df.columns:
            df['size'] = pd.to_numeric(df['size'], errors='coerce')

        return df
    except Exception as e:
        st.error(f"Error loading file: {e}")
        return None
#....................................................................................................................................................................................


# Additional Step: Load Authorized Hostnames from Uploaded CSV File
def load_authorized_hostnames(authorized_file):
    """Load authorized hostnames from a CSV file uploaded via Streamlit."""
    df = pd.read_csv(authorized_file)
    if 'hostname' not in df.columns:
        st.error("CSV file must contain a 'hostname' column.")
        return set()
    return set(df['hostname'].dropna().unique())

# Modify Reverse DNS Lookup Results to Mark Unauthorized Hostnames
def mark_unauthorized_hostnames(reverse_lookup_df, authorized_hostnames):
    """Mark unauthorized hostnames in the DataFrame."""
    reverse_lookup_df['authorized'] = reverse_lookup_df['hostname'].apply(
        lambda hostname: 'Yes' if hostname in authorized_hostnames else 'No'
    )
    return reverse_lookup_df

# Function to load and process the uploaded file with additional checks


# Streamlit app code
def main():
    st.set_page_config(page_title="Apache Log Analyser", layout="wide")
    st.sidebar.title("Apache Log Analyser",)
    feature = st.sidebar.selectbox("Choose a feature", ["Log File Converter","Analysis Section"])
    if feature == "Log File Converter":
        # feature = st.selectbox("Choose a feature", ["Pattern2"])
        feature = st.sidebar.selectbox("Choose a feature", ["Formate-1","Formate-2"])
        
        if feature == "Formate-1":
            # Upload file functionality
            uploaded_file = st.file_uploader("Choose a log file", type=["log","txt"])
            if st.button("Analyze Data "):
                if uploaded_file is not None:

                    logfile_content = uploaded_file.getvalue().decode("utf-8")
            
                    # Convert the log file to CSV (in-memory)
                    output_csv, faulty_lines = parse_log_file_to_csv(logfile_content, "access_log.csv")
                    
                    # Provide a download button for the user to download the CSV
                    st.write(f" {faulty_lines} faulty lines detected.")
                    
            
                    # Read the CSV into a DataFrame for analysis
                    df = pd.read_csv(StringIO(output_csv.decode('utf-8')))  # Convert bytes back to StringIO for reading
            
                    # # Display basic data
                    # if st.checkbox("Show Data Sample"):
                    #     st.write(df.head())
                    st.write("Parsed Data Preview:")
                    st.dataframe(df.head(10))
                    st.download_button("Download CSV", output_csv, file_name="access_log.csv", mime="text/csv")
                        
            
                    # Filter the columns for analysis
                    columns_to_drop = [
                        'remote_logname', 'remote_user', 'time_received', 'time_received_isoformat',
                        'time_received_tz_datetimeobj', 'time_received_tz_isoformat', 'time_received_utc_datetimeobj',
                        'time_received_utc_isoformat', 'request_first_line', 'request_url', 'request_url_scheme',
                        'request_url_netloc', 'request_url_fragment', 'request_url_username', 'request_url_password',
                        'request_url_hostname', 'request_url_port', 'request_url_query_dict', 'request_url_query_list',
                        'request_url_query_simple_dict'
                    ]
                    df_filtered = df.drop(columns=columns_to_drop, errors='ignore')
                    df_filtered['time_received_datetimeobj'] = pd.to_datetime(df_filtered['time_received_datetimeobj'])

        elif feature == "Formate-2":
            uploaded_file = st.file_uploader("Choose a log file", type=["log", "txt"])
            limit = st.sidebar.slider("Max Lines to Parse", 1000, 600000, 100000)
            if st.button("Analyze Data "):

                if uploaded_file is not None:
                    # st.write("File uploaded successfully!")
                    
                    # Initialize lists to hold parsed logs and track progress
                    parsed_logs = []
                    line_count = 0
                      # Allow user to set a limit

                    # Read and parse the file line by line
                    with st.spinner("Parsing log file..."):
                        for line in uploaded_file:
                            line_count += 1
                            parsed_log = parse_log_line(line.decode('utf-8'))  # Decoding bytes to string
                            if parsed_log:
                                parsed_logs.append(parsed_log)
                            
                            # Update progress every 10 lines and break at the user-defined limit
                            # if line_count % 1000 == 0:
                            #     st.write(f"Parsed {line_count} lines...")
                            # if line_count >= limit:
                            #     st.write(f"Reached line limit of {limit}. Stopping parsing.")
                            #     break

                    # Convert parsed data to DataFrame and display summary
                    if parsed_logs:
                        df = pd.DataFrame(parsed_logs)
                        
                        # Clean 'size' column, convert '-' to 0 and make it numeric
                        df['size'] = pd.to_numeric(df['size'], errors='coerce').fillna(0)
                        
                        # Display parsed data summary
                        st.write("Parsed Data Preview:")
                        st.dataframe(df.head(10))
                        
                        # Provide an option to download the parsed data as CSV
                        csv_data = df.to_csv(index=False).encode('utf-8')
                        st.download_button(
                            label="Download Parsed Log as CSV",
                            data=csv_data,
                            file_name="parsed_access_log.csv",
                            mime="text/csv",
                        )

                        st.success(f"Parsed {len(df)} log entries!")
                    else:
                        st.warning("No parsable data found in the file.")

    elif feature == "Analysis Section":
            # Analysis Section
            analysis_type = st.sidebar.selectbox("Choose Analysis Type", [
                "Bot Detection and Analysis",
                "Unauthorized Users Location Finder",
                "IP Extraction and Reverse DNS Lookup",
                "Traffic Monitering and Analysis",
                "Anomaly Detection",
                "Product Analysis Application",
                "Other Analysis"
            ])
    
            # HTTP Status Code Analysis
            if analysis_type == "Error Analysis":
                st.title("Error Analysis")
    
                # Feature selection
                feature = st.selectbox("Choose a feature", ["HTTP Status Code Analysis",
                "Top 10 Hosts",
                "Top 10 Endpoints",
                "Top 10 Error Points",
                "404 Errors Per Day",
                "Status Codes by Date"])
    
                if feature == "HTTP Status Code Analysis":
                    status_freq = df_filtered.groupby(['status']).size().reset_index(name='counts')
                    status_freq['log (count)'] = np.log(status_freq['counts'])
        
                    # Plotting the bar chart for status codes
                    st.subheader("HTTP Status Code Analysis")
                    fig, ax = plt.subplots()
                    sns.barplot(x='status', y='counts', data=status_freq, ax=ax)
                    st.pyplot(fig)
        
                    # Log-transformed counts
                    fig, ax = plt.subplots()
                    sns.barplot(x='status', y='log (count)', data=status_freq, ax=ax)
                    st.pyplot(fig)
    
                # Top 10 Hosts
                elif feature == "Top 10 Hosts":
                    favourite_host = df_filtered.groupby(['ip_address'])['status'].count().sort_values(ascending=False).head(10)
                    st.subheader("Top 10 Hosts")
                    st.bar_chart(favourite_host)
        
                # Top 10 Endpoints
                elif feature == "Top 10 Endpoints":
                    favourite_endpoints = df_filtered.groupby(['request_url_path']).size().sort_values(ascending=False).head(10)
                    st.subheader("Top 10 Endpoints")
                    st.bar_chart(favourite_endpoints)
        
                # Top 10 Error Points
                elif feature == "Top 10 Error Points":
                    top_errorpoints = df_filtered[df_filtered['status'] != 200]
                    top_errorpoints = top_errorpoints.groupby(['request_url_path']).size().sort_values(ascending=False).head(10)
                    st.subheader("Top 10 Error Points")
                    st.bar_chart(top_errorpoints)
        
                # 404 Errors Per Day
                elif feature == "404 Errors Per Day":
                    st.subheader("404 Errors Per Day")
                    start_date = 17
                    end_date = 20
                    for date in range(start_date, end_date + 1):
                        errors = df_filtered[df_filtered['time_received_datetimeobj'].dt.day == date]
                        errors = errors[errors['status'] == 404]['ip_address'].count()
                        st.write(f"There were {errors} errors on {date} of this month!")
        
                # Status Codes by Date
                elif feature == "Status Codes by Date":
                    status_codes = [200, 404, 500]
                    status_code_colors = {200: 'green', 404: 'red', 500: 'blue'}
                    for status in status_codes:
                        df_status = df_filtered[df_filtered['status'] == status]
                        df_status = df_status.groupby(['time_received_datetimeobj']).size().reset_index(name='counts')
        
                        # Plot the data
                        fig, ax = plt.subplots()
                        ax.plot(df_status['time_received_datetimeobj'], df_status['counts'], marker='o', color=status_code_colors.get(status, 'gray'))
                        st.pyplot(fig)
    
                
    
            # Googlebot Hits
            elif analysis_type == "Bot Detection and Analysis":
                st.title("Bot Detection and Analysis")
    
                # File upload for log data
                uploaded_file = st.file_uploader("Upload Log CSV File", type=["csv"])
                
                # Option to choose chart type
                chart_type = st.selectbox("Choose chart type for Bot Traffic Breakdown:", ['bar', 'line', 'pie'])
                
                if uploaded_file:
                    # Load data
                    df = pd.read_csv(uploaded_file)
                    
                    if 'user_agent' in df.columns:
                        # Filter and display bot hits
                        if st.button("Analyze Bot Hits"):
                            plot_bot_hits(df, chart_type=chart_type)
                    else:
                        st.error("The dataset does not contain 'user_agent' column.")
    
            # Unauthorized Users Location Finder
            elif analysis_type == "Unauthorized Users Location Finder":
                st.title("Unauthorized Users Location Finder and Geolocation Analysis")
    
                # Feature selection
                feature = st.sidebar.selectbox("Choose a feature", ["Unauthorized Users Analysis", "Geolocation Analysis-1","Geolocation Analysis-2"])
    
                if feature == "Unauthorized Users Analysis":
                        st.subheader("Unauthorized Users Location Finder")
                        auth_file = st.file_uploader("Upload Authorized Hosts CSV", type=["csv"])
                        logs_file = st.file_uploader("Upload Logs CSV", type=["csv"])
                        api_key = st.text_input("Enter your IPinfo API Key", "ae43dbe640ec07",type="password")
            
                        if st.button("Start Processing"):
                            if auth_file and logs_file and api_key:
                                try:
                                    df_auth_hosts = pd.read_csv(auth_file, encoding='ISO-8859-1')
                                    st.success("Authorized hosts file loaded successfully.")
                                except Exception as e:
                                    st.error(f"Error loading authorized hosts file: {e}")
                                    st.stop()
            
                                # Initialize DataFrame to store unauthorized users
                                unauthorized_users = pd.DataFrame()
            
                                # Process the logs file
                                df_logs = pd.read_csv(logs_file, encoding='ISO-8859-1')
            
                                # Check columns and rename if necessary
                                if 'remote_host' in df_auth_hosts.columns:
                                    df_auth_hosts.rename(columns={'remote_host': 'ip_address'}, inplace=True)
                                elif 'client' not in df_auth_hosts.columns:
                                    st.error("No column named 'ip_address' found in the authorized hosts file. Please check the file.")
                                    st.stop()
            
                                # Merge with the authorized hosts based on IP address
                                merged_df = pd.merge(df_logs, df_auth_hosts[['client']], left_on='ip_address',right_on='client', how='left', indicator=True)
                                unauthorized_users = merged_df[merged_df['_merge'] == 'left_only']
            
                                # Display the unauthorized users
                                with st.expander("Unauthorized Users"):
       
                                    st.write(unauthorized_users[['ip_address', 'request', 'status']])
            
                                # Get locations for unauthorized users
                                    unauthorized_users['location'] = unauthorized_users['ip_address'].apply(
                                        lambda ip: get_ip_location(ip, api_key)
                                    )
            
                                # Show location data
                                with st.expander("Location Data"):
                                    st.write(unauthorized_users[['ip_address', 'location']])
            
                                # Plot the locations on a world map
                                with st.expander("Unauthorized Users Locations on Map"):
                                    # st.subheader("Unauthorized Users Locations on Map")
                                    map_ = plot_ip_locations_on_map(unauthorized_users)
                                    folium_static(map_, width=1335, height=600)  # Display the map in the Streamlit app
            
                            else:
                                st.warning("Please upload both files and provide the API key.")
    
                elif feature == "Geolocation Analysis-1":
                    st.subheader("Geolocation Analysis")
                    logs_file1 = st.file_uploader("Upload Logs CSV", type=["csv"])
                    api_key = st.text_input("Enter your IPinfo API Key","ae43dbe640ec07",type="password")  # Add API key input
                
                    # Define rate limit delay (in seconds)
                    rate_limit_delay = 1 # You can adjust this as per the API's rate limit
                    if st.button("Start Processing"):
                
                        if logs_file1 is not None and api_key:  # Check if both the file and API key are provided
                            try:
                                # Read the logs CSV file
                                df = pd.read_csv(logs_file1, encoding='ISO-8859-1')
                                unique_ips = df['ip_address'].unique()  # Extract unique IP addresses
                                unique_ips_df = pd.DataFrame(unique_ips, columns=['ip_address'])
                                with st.expander("Unique IP Addresses:"):
                                    # st.write("Unique IP Addresses:")
                                    st.write(unique_ips_df)
                                    st.write(f"Total unique IPs: {len(unique_ips)}")
                    
                                st.info("Fetching locations for unique IPs... This may take some time.")
                                locations = []
                    
                                # Iterate through each unique IP and fetch the location data
                                for ip in unique_ips:
                                    location_data = get_ip_location(ip, api_key)  # Now using the api_key
                                    if location_data:
                                        loc = location_data.get('loc', 'N/A').split(',')
                                        latitude, longitude = (loc[0], loc[1]) if len(loc) == 2 else ('N/A', 'N/A')
                                        locations.append({
                                            'ip_address': ip,
                                            'city': location_data.get('city', 'N/A'),
                                            'region': location_data.get('region', 'N/A'),
                                            'country': location_data.get('country', 'N/A'),
                                            'latitude': latitude,
                                            'longitude': longitude
                                        })
                                    else:
                                        # If location data is not available, use 'N/A'
                                        locations.append({
                                            'ip_address': ip,
                                            'city': 'N/A',
                                            'region': 'N/A',
                                            'country': 'N/A',
                                            'latitude': 'N/A',
                                            'longitude': 'N/A'
                                        })
                                    time.sleep(rate_limit_delay)  # Handle rate-limiting of the IP location API
                    
                                # Create DataFrame from the locations list
                                location_df = pd.DataFrame(locations)
                    
                                # Convert latitude and longitude to numeric values and handle errors
                                location_df['latitude'] = pd.to_numeric(location_df['latitude'], errors='coerce')
                                location_df['longitude'] = pd.to_numeric(location_df['longitude'], errors='coerce')
                    
                                # Filter out rows with missing latitude or longitude values
                                location_map = location_df.dropna(subset=['latitude', 'longitude'])
                    
                                # Display the map with markers for each unique IP's location
                                with st.expander("Map of Unique IP Addresses"):
                                    # st.write("Map of Unique IP Addresses")
                                    map_ = folium.Map(location=[0, 0], zoom_start=2)  # Initialize a global map
                    
                                # Add markers for each location on the map
                                    for _, row in location_map.iterrows():
                                        folium.Marker(
                                            location=[row['latitude'], row['longitude']],
                                            popup=f"IP: {row['ip_address']}\nCity: {row['city']}\nRegion: {row['region']}\nCountry: {row['country']}"
                                        ).add_to(map_)
                        
                                    folium_static(map_, width=1335, height=600)  # Display the map in the Streamlit app
                    
                                # Optional: Save the location data to CSV
                                # location_df.to_csv(os.path.join(output_dir, 'unique_ips_locations.csv'), index=False)
                                # st.success("Locations for unique IPs saved to 'unique_ips_locations.csv'")
                    
                            except Exception as e:
                                st.error(f"Error processing logs file: {e}")
                        else:
                            if not api_key:
                                st.warning("Please enter your API key.")
                            if logs_file1 is None:
                                st.warning("Please upload a logs CSV file.")
                elif feature == "Geolocation Analysis-2":

                    # Title and introduction
                    st.title("IP Location Data and Hits by Country")
                    st.markdown("""
                    This tool allows you to upload a CSV file containing IP addresses and get location information for each IP, 
                    as well as statistics on hits by country.
                    """)

                    # File uploader
                    uploaded_file = st.file_uploader("Upload a CSV file with IP addresses", type="csv")

                    # Your IPinfo API key
                    api_key = 'ae43dbe640ec07'  # Replace with your actual API key

                    # Regex pattern to validate IP address
                    ip_pattern = re.compile(r"^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\."
                                            r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\."
                                            r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\."
                                            r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$")

                    # CSV file for storing previously fetched IP locations
                    location_csv = "cached_ip_locations.csv"
                    last_processed_ip_file = "last_processed_ip.txt"

                    # Load cached IP locations if they exist
                    if os.path.exists(location_csv):
                        cached_locations_df = pd.read_csv(location_csv)
                    else:
                        cached_locations_df = pd.DataFrame(columns=['ip_address', 'city', 'region', 'country', 'latitude', 'longitude'])
                    
                    # Function to get location information based on IP address
                    @st.cache_data
                    def get_ip_location1(ip_address, api_key):
                        url = f"https://ipinfo.io/{ip_address}?token={api_key}"
                        headers = {'Accept-Encoding': 'identity'}  # Disable gzip encoding

                        response = requests.get(url, headers=headers)
                        
                        if response.status_code == 200:
                            return response.json()
                        else:
                            return None

                    # Batch processing function with IP validation and caching
                    def process_ip_in_batches(ip_list, api_key, chunk_size=50, save_interval=25):
                        locations = []
                        invalid_ips = []
                        
                        # Filter IPs to avoid redundant API calls for cached locations
                        cached_ips = set(cached_locations_df['ip_address'])
                        ips_to_process = [ip for ip in ip_list if ip not in cached_ips]

                        # Track how many IPs are left to process
                        total_ips = len(ips_to_process)
                        processed_ips = 0  # Counter for processed IPs

                        # Initialize updated_locations_df with the cached locations
                        updated_locations_df = cached_locations_df.copy()

                        progress_text = st.empty()  # Placeholder for updating progress text
                        save_progress_text = st.empty()  # Placeholder for saving progress message

                        for ip in ips_to_process:
                            processed_ips += 1
                            
                            # Update counter with color change
                            if processed_ips < total_ips // 3:
                                color = "red"
                            elif processed_ips < (2 * total_ips) // 3:
                                color = "yellow"
                            else:
                                color = "green"
                            
                            # Update the progress text on the same line
                            progress_text.markdown(f"<p style='color:{color}; font-size:16px;'>Processing IP {processed_ips} of {total_ips}...</p>", unsafe_allow_html=True)

                            # Check if IP matches valid pattern
                            if not ip_pattern.match(ip):
                                invalid_ips.append(ip)  # Add to invalid list if pattern doesn't match
                                continue

                            # Call API only if IP is valid and not cached
                            location_data = get_ip_location1(ip, api_key)
                            if location_data:
                                loc = location_data.get('loc', 'N/A')
                                if ',' in loc:
                                    latitude, longitude = loc.split(',')
                                else:
                                    latitude, longitude = 'N/A', 'N/A'
                                
                                locations.append({
                                    'ip_address': ip,
                                    'city': location_data.get('city', 'N/A'),
                                    'region': location_data.get('region', 'N/A'),
                                    'country': location_data.get('country', 'N/A'),
                                    'latitude': latitude,
                                    'longitude': longitude
                                })
                            else:
                                # Collect invalid IPs
                                invalid_ips.append(ip)

                            # Save the data to CSV after every 'save_interval' calls
                            if processed_ips % save_interval == 0 and locations:
                                new_locations_df = pd.DataFrame(locations)
                                updated_locations_df = pd.concat([updated_locations_df, new_locations_df], ignore_index=True).drop_duplicates('ip_address')
                                updated_locations_df.to_csv(location_csv, index=False)  # Save updated location data to CSV
                                
                                # Update the save progress message on the same line
                                save_progress_text.markdown(f"<p style='color:green;'>Saved progress after processing {processed_ips} IPs.</p>", unsafe_allow_html=True)

                            # Optional: Sleep briefly to avoid hitting API rate limits
                            time.sleep(0.1)  # Adjust based on API limits

                        # Final save to ensure all data is saved at the end
                        if locations:
                            new_locations_df = pd.DataFrame(locations)
                            updated_locations_df = pd.concat([updated_locations_df, new_locations_df], ignore_index=True).drop_duplicates('ip_address')
                            updated_locations_df.to_csv(location_csv, index=False)  # Save final location data to CSV

                        return updated_locations_df, invalid_ips


                    # Main app flow
                    if uploaded_file:
                        # Load the CSV file
                        ip_data = pd.read_csv(uploaded_file)

                        # Check if 'ip_address' column exists
                        if 'ip_address' in ip_data.columns:
                            
                            # Count occurrences of each IP address
                            ip_counts = ip_data['ip_address'].value_counts()

                            # Process IPs in batches with loading spinner
                            unique_ips = ip_counts.index.tolist()
                            with st.spinner("Processing IP locations..."):
                                location_df, invalid_ips = process_ip_in_batches(unique_ips, api_key, chunk_size=50, save_interval=25)

                            # Merge IP count data for accurate country hits
                            location_df = pd.merge(location_df, ip_counts.rename('count'), left_on='ip_address', right_index=True, how='left')

                            # Display location data with unique IPs only
                            st.subheader("IP Location Data (Unique IPs):")
                            st.dataframe(location_df[['ip_address', 'city', 'region', 'country', 'latitude', 'longitude']])

                            # Display invalid IPs, if any
                            if invalid_ips:
                                st.subheader("Invalid IP Addresses:")
                                st.write(invalid_ips)

                            # Calculate hits per country, accounting for duplicate IPs
                            country_hits = location_df.groupby('country')['count'].sum().reset_index()
                            country_hits.columns = ['Country', 'Hits']

                            # Merge with unique location data for plotting
                            country_location = location_df.groupby('country')[['latitude', 'longitude']].first().reset_index()
                            country_hits = pd.merge(country_hits, country_location, left_on='Country', right_on='country').drop(columns=['country'])

                            # Display hits by country in a table
                            st.subheader("Hits by Country (Including Duplicate IPs):")
                            st.dataframe(country_hits)

                            # Display bar chart for hits by country
                            st.bar_chart(country_hits.set_index('Country')['Hits'])

                            # Convert latitude and longitude to numeric
                            country_hits['latitude'] = pd.to_numeric(country_hits['latitude'], errors='coerce')
                            country_hits['longitude'] = pd.to_numeric(country_hits['longitude'], errors='coerce')

                            # Display a map with hit data
                            st.subheader("Hits by Country on the Map:")
                            st.pydeck_chart(pdk.Deck(
                                map_style="mapbox://styles/mapbox/light-v9",
                                initial_view_state=pdk.ViewState(
                                    latitude=0,
                                    longitude=0,
                                    zoom=1,
                                    pitch=50,
                                ),
                                layers=[
                                    pdk.Layer(
                                        "ScatterplotLayer",
                                        data=country_hits,
                                        get_position="[longitude, latitude]",
                                        get_fill_color="[200, 30, 0, 160]",
                                        get_radius="Hits * 10000",  # Scale radius by hit count
                                        radius_min_pixels=5,
                                        radius_max_pixels=100,
                                    ),
                                ],
                            ))

                        else:
                            st.error("The uploaded file must contain an 'ip_address' column.")
                    else:
                        st.info("Please upload a CSV file to get started.")

                        
    
    
            elif analysis_type == "IP Extraction and Reverse DNS Lookup":
                # st.set_page_config(page_title="Log File IP Analysis and Reverse DNS Lookup", layout="wide")
                st.title("Log File IP Analysis and Reverse DNS Lookup")
            
                # Step 1: File upload for log file
                log_file = st.file_uploader("Upload your log file", type=['log', 'txt', 'csv'])
                
                # Step 2: File upload for authorized hostname CSV file
                authorized_file = st.file_uploader("Upload your authorized hostname CSV file", type=['csv'])
                if authorized_file:
                    authorized_hostnames = load_authorized_hostnames(authorized_file)
                    if not authorized_hostnames:
                        st.warning("No valid hostnames found in the authorized file.")
                else:
                    authorized_hostnames = set()
                if st.button("Analyze Data "):
                    if log_file and authorized_hostnames:
                        # Step 3: Extract IP addresses
                        ip_list = extract_ip_addresses(log_file)
                        
                        if not ip_list:
                            st.error("No valid IP addresses found in the uploaded file.")
                            return

                        # Step 4: Save IP addresses to CSV and show DataFrame
                        csv_file, ip_df = save_ip_addresses_to_csv(ip_list)
                        
                        # Display extracted IP addresses with Show/Hide option
                        with st.expander("Show Extracted IP Addresses"):
                            st.dataframe(ip_df)

                        # Step 5: Reverse DNS Lookup
                        st.subheader("Reverse DNS Lookup Results")
                        with st.spinner("Performing reverse DNS lookup. This may take a few moments..."):
                            reverse_lookups = reverse_dns_lookup(ip_list)

                        # Step 6: Mark unauthorized hostnames
                        reverse_lookups = mark_unauthorized_hostnames(reverse_lookups, authorized_hostnames)

                        # Calculate authorized hostname count
                        authorized_count = reverse_lookups['authorized'].value_counts().get('Yes', 0)
                        unauthorized_count = reverse_lookups['authorized'].value_counts().get('No', 0)
                        # Metrics summary in an expandable section
                        with st.expander("Show Metrics Summary"):
                            st.metric("Total Unique IP Addresses", len(reverse_lookups))
                            st.metric("Authorized Hostnames Count", authorized_count)
                            st.metric("Unauthorized Hostnames Count", unauthorized_count)
                            st.metric("Unauthorized Hostnames Percentage", unauthorized_count / len(reverse_lookups))
                            top_ip = reverse_lookups.iloc[0]
                            st.metric("Top IP Address", top_ip['ip_address'], delta=f"{top_ip['perc']:.2%} of total")

                        # Display reverse lookup DataFrame with unauthorized hosts flagged
                        # with st.expander("Show Detailed Reverse DNS Lookup Data"):
                        #     st.write(reverse_lookups)


                        with st.expander("Show Detailed Reverse DNS Lookup Data1"):
                            styled_df = (reverse_lookups.head(20)
                                        .style
                                        .background_gradient(subset=['count', 'perc', 'cum_perc'], cmap='cividis')
                                        .format({'count': '{:,}', 'perc': '{:.1%}', 'cum_perc': '{:.1%}'}))
                            st.write(styled_df.to_html(), unsafe_allow_html=True)

                        # Show IP and Hostname only
                        with st.expander("Show IP Addresses and Hostnames Only"):
                            ip_hostname_df = reverse_lookups[['ip_address', 'hostname', 'authorized']].dropna().reset_index(drop=True)
                            st.dataframe(ip_hostname_df)
                        
                        # Show only authorized hostnames in an expandable section
                        with st.expander("Show Only Authorized Hostnames"):
                            authorized_only_df = reverse_lookups[reverse_lookups['authorized'] == 'Yes'].reset_index(drop=True)
                            st.dataframe(authorized_only_df[['ip_address', 'hostname']])
                        # Visualization in an expandable section
                        with st.expander("Show Visualization"):
                            st.subheader("Top 10 IP Addresses by Count")
                            top_10_df = reverse_lookups.head(10)
                            fig = px.bar(
                                top_10_df,
                                x="ip_address",
                                y="count",
                                text="count",
                                title="Top 10 IP Addresses by Occurrence",
                                labels={"ip_address": "IP Address", "count": "Count"},
                                hover_data=["perc", "cum_perc"]
                            )
                            fig.update_traces(texttemplate='%{text:.2s}', textposition='outside')
                            fig.update_layout(yaxis_title="Count", xaxis_title="IP Address")
                            st.plotly_chart(fig)

                        # Provide CSV download options in an expandable section
                        with st.expander("Download Options"):
                            st.download_button(
                                label="Download Extracted IP Addresses CSV",
                                data=ip_df.to_csv(index=False),
                                file_name='ip_addresses.csv',
                                mime='text/csv'
                            )
                            st.download_button(
                                label="Download Reverse DNS Lookup Results CSV",
                                data=reverse_lookups.to_csv(index=False),
                                file_name='reverse_dns_results.csv',
                                mime='text/csv'
                            )
                            st.download_button(
                                label="Download IP and Hostnames CSV",
                                data=ip_hostname_df.to_csv(index=False),
                                file_name='ip_and_hostnames.csv',
                                mime='text/csv'
                            )

        
            elif analysis_type == "Traffic Monitering and Analysis":
                # Streamlit interface
                st.title("Traffic Monitoring Application with Alerts")
                
                # File upload for log data
                uploaded_file = st.file_uploader("Upload Log CSV File", type=["csv"])
                
                # Date input for start and end time
                start_time = st.text_input("Enter Start Time (e.g., 22/Jan/2019:03:56:14 +0330)", "22/Jan/2019:03:56:14 +0330")
                end_time = st.text_input("Enter End Time (e.g., 22/Jan/2019:14:11:45 +0330)", "22/Jan/2019:14:11:45 +0330")
                
                # Interval selection
                resample_interval = st.selectbox("Select Resampling Interval", ['h', 'd', 'w'], index=0)
                
                # Threshold for alerting (e.g., how many standard deviations above average traffic)
                alert_threshold = st.slider("Alert Threshold (Standard Deviations Above Average)", min_value=0, max_value=5, value=1)
                
                # Graph type selection (Matplotlib only now)
                graph_type = 'Matplotlib'
                
                # Initialize graph type options
                matplot_graph_type = 'line'
                
                # Conditionally display Matplotlib graph options
                matplot_graph_type = st.selectbox("Choose Matplotlib Graph Type", ['line', 'bar'])
                
                # Load and analyze the data when "Analyze Traffic" button is clicked
                if st.button("Analyze Traffic"):
                    if uploaded_file:
                        # Load and prepare data
                        df_logs = load_and_prepare_data(uploaded_file)
                
                        if df_logs is not None:
                            # Convert start and end times to datetime
                            try:
                                start_time_dt = pd.to_datetime(start_time, format='%d/%b/%Y:%H:%M:%S %z')
                                end_time_dt = pd.to_datetime(end_time, format='%d/%b/%Y:%H:%M:%S %z')
                
                                # Run the traffic monitoring within the specified time range
                                monitor_traffic_in_range(df_logs, start_time_dt, end_time_dt, resample_interval=resample_interval, alert_threshold=alert_threshold, graph_type=graph_type, matplot_graph_type=matplot_graph_type)
                            except Exception as e:
                                st.error(f"Error parsing dates: {e}")
                        else:
                            st.warning("Traffic monitoring aborted due to data preparation errors.")
                    else:
                        st.warning("Please upload a CSV file.")
    
            elif analysis_type == "Product Analysis Application":
                    st.title("Product Analysis Application")
                    
                    # File upload for log data
                    uploaded_file = st.file_uploader("Upload Log CSV File", type=["csv"])
                    
                    # Analysis type selection
                    analysis_type = st.sidebar.selectbox("Choose an analysis to display:", ["Top 10 Most Visited Products", "Product Models"])
                    
                    # Proceed with analysis if a file is uploaded
                    if uploaded_file:
                        # Load the data
                        df = load_and_prepare_data(uploaded_file)
                    
                        if df is not None:
                            # Handle "Top 10 Most Visited Products" analysis
                            if analysis_type == "Top 10 Most Visited Products":
                                    if st.button("Analyze Top 10 Most Visited Products"):
                                        analyze_top_10_products(df)
                    
                            # Handle "Product Models" extraction from URLs
                            elif analysis_type == "Product Models":
                                    if st.button("Analyze Product Models"):
                                        analyze_product_models(df)
    
                                
            elif analysis_type == "Anomaly Detection":
                st.title("Anomaly Detection in Access Logs")
                feature = st.sidebar.selectbox(
                        "Choose an analysis to display:",
                        ["Anomaly Detection-1", "Anomaly Detection-2"]
                    )
                if feature == "Anomaly Detection-1":

                    def load_data(uploaded_file):
                        try:
                            df = pd.read_csv(uploaded_file)
                            
                            # Ensure essential columns exist
                            required_columns = ['timestamp', 'ip_address', 'status', 'size', 'user_agent']
                            missing_cols = [col for col in required_columns if col not in df.columns]
                            if missing_cols:
                                st.error(f"Missing columns: {', '.join(missing_cols)}")
                                return None
                            
                            # Parse timestamp if exists
                            if 'timestamp' in df.columns:
                                df['timestamp'] = df['timestamp'].apply(parse_timestamp)
                            
                            # Convert necessary columns to numeric
                            if 'status' in df.columns:
                                df['status'] = pd.to_numeric(df['status'], errors='coerce')
                            if 'size' in df.columns:
                                df['size'] = pd.to_numeric(df['size'], errors='coerce')
                    
                            return df
                        except Exception as e:
                            st.error(f"Error loading file: {e}")
                            return None

                     # Function to classify bots based on user agent
                    def detect_bots(user_agent):
                        bots = ["Googlebot", "Bingbot", "Slurp", "DuckDuckBot", "Baiduspider"]
                        for bot in bots:
                            if bot in user_agent:
                                return bot
                        return "Human"

                    # Upload file functionality
                    uploaded_file = st.file_uploader("Choose a log file", type=["csv"])
                    contamination_slider = st.slider("Anomaly Detection Contamination Threshold", 
                                                                    min_value=0.01, 
                                                                    max_value=0.1, 
                                                                    value=0.05, 
                                                                    step=0.01)
                    if st.button("Start Anomaly Detection"):
                        if uploaded_file is not None:
                            df = load_data(uploaded_file)
                            
                            if df is not None:
                                # st.write("File loaded successfully!")
                                
                                # Show data sample
                                # if st.checkbox("Show Data Sample"):
                                #     st.write(df.head())
                        
                                # ---- Data Preprocessing ----
                                # Extract platform info for user agent analysis
                                if 'user_agent' in df.columns:
                                    df['platform'] = df['user_agent'].apply(extract_platform)
                                    df['bot'] = df['user_agent'].apply(detect_bots)
                        
                                # ---- Anomaly Detection ----
                                st.subheader("Anomaly Detection")
                        
                                # Add Expander for High Frequency Requests
                                with st.expander("High Frequency Requests from IPs"):
                                    # 1. Detecting Anomalies in Request Frequency (IP-based)
                                    if 'ip_address' in df.columns:
                                        ip_request_counts = df['ip_address'].value_counts().reset_index()
                                        ip_request_counts.columns = ['ip_address', 'request_count']
                        
                                        threshold = ip_request_counts['request_count'].mean() + 3 * ip_request_counts['request_count'].std()
                                        anomaly_ips = ip_request_counts[ip_request_counts['request_count'] > threshold]
                        
                                        st.write(f"Threshold for high request count: {threshold}")
                                        if not anomaly_ips.empty:
                                            chart = alt.Chart(anomaly_ips).mark_bar(color="red").encode(
                                                x=alt.X('ip_address:N', title="IP Address"),
                                                y=alt.Y('request_count:Q', title="Request Count")
                                            ).properties(width=600, height=400)
                                            st.altair_chart(chart)
                                            st.write("Anomalous IPs with unusually high request counts:")
                                            st.write(anomaly_ips)
                                        else:
                                            st.write("No IPs with anomalously high request counts detected.")
                                    else:
                                        st.write("IP address column is missing, anomaly detection cannot be performed.")
                                
                                # Add Expander for Large Response Sizes
                                with st.expander("Unusually Large Response Sizes"):
                                    # 2. Detecting Anomalies in Response Size
                                    if 'size' in df.columns:
                                        size_threshold = df['size'].quantile(0.95)
                                        large_responses = df[df['size'] > size_threshold]
                        
                                        st.write(f"Response size threshold (95th percentile): {size_threshold}")
                                        if not large_responses.empty:
                                            size_chart = alt.Chart(df).mark_bar().encode(
                                                x=alt.X('size:Q', bin=alt.Bin(maxbins=50), title="Response Size"),
                                                y=alt.Y('count()', title="Frequency")
                                            ).properties(width=600, height=400) + alt.Chart(pd.DataFrame({'size': [size_threshold]})).mark_rule(color='red').encode(x='size:Q')
                                            st.altair_chart(size_chart)
                                            st.write("Anomalous requests with unusually large response sizes:")
                                            st.write(large_responses[['ip_address', 'size', 'request', 'status']])
                                        else:
                                            st.write("No requests with anomalously large response sizes detected.")
                                    else:
                                        st.write("Response size column is missing, anomaly detection cannot be performed.")
                                
                                # Add Expander for 5xx Status Codes
                                with st.expander("IP Addresses with 5xx Status Codes"):
                                    ip_5xx_summary, size_threshold = get_5xx_status_ips(df)
                                
                                    if ip_5xx_summary is not None:
                                        st.write("Threshold for High Response Size in 5xx Errors:", size_threshold)
                        
                                       
                        
                                        # Create a chart of the 5xx error summary
                                        chart = alt.Chart(ip_5xx_summary).mark_bar().encode(
                                            x=alt.X('ip_address:N', title="IP Address"),
                                            y=alt.Y('count:Q', title="Frequency"),
                                            color='status:N'
                                        ).properties(width=600, height=400)
                                        st.altair_chart(chart)

                                         # Display the 5xx summary
                                        st.write("IP Addresses with 5xx Status Codes:")
                                        st.write(ip_5xx_summary)
                                
                                # --- Referrer Analysis ---
                                with st.expander("Referrer Analysis"):
                                    referrer_counts, non_friendly_referrers = analyze_referrer(df)
                                    
                                    if referrer_counts is not None:
                                        st.write("Referrer Categories Summary")
                                        st.write(referrer_counts)
                                        
                                        # Non-friendly referrers visualization
                                        if not non_friendly_referrers.empty:
                                            st.write("Top Non-Friendly Referrers:")
                                            st.write(non_friendly_referrers)
                                            referrer_chart = alt.Chart(non_friendly_referrers).mark_bar().encode(
                                                x=alt.X('referrer:N', title="Referrer"),
                                                y=alt.Y('count:Q', title="Frequency"),
                                            ).properties(width=600, height=400)
                                            st.altair_chart(referrer_chart)
                                            
                                        else:
                                            st.write("No non-friendly referrers detected.")
                        
                                # Add Expander for Isolation Forest Anomalies
                                with st.expander("Isolation Forest Anomalies (Request Frequency and Response Size)"):
                                    # Add slider to allow user to adjust contamination threshold for Isolation Forest
                                    
                                    
                                    apply_isolation_forest(df, contamination_threshold=contamination_slider)
                elif feature == "Anomaly Detection-2":
                    # File upload section
                    file_path = st.file_uploader("Upload Access Log CSV", type=["csv"])
                    
                    # User input for chunk size and contamination threshold
                    chunk_size = st.number_input("Chunk Size for Reading CSV", min_value=1000, value=100000, step=1000)
                    contamination_threshold = st.slider("Set Anomaly Detection Threshold (Contamination)", 0.01, 0.20, 0.05, step=0.01)
                    
                    # User-defined thresholds for status, size, and request rate
                    status_threshold = st.slider("Set Status Threshold", min_value=0, max_value=500, value=400, step=1)
                    size_threshold = st.slider("Set Size Threshold", min_value=0, max_value=5000, value=3000, step=100)
                    request_rate_threshold = st.slider("Set Request Rate Threshold (requests/min)", 1, 100, 20, step=1)
                    
                    # Button to start anomaly detection
                    if st.button("Start Anomaly Detection"):
                        if file_path:
                            try:
                                # Load the dataset and process it in chunks
                                all_chunks = []
                                chunks = pd.read_csv(file_path, chunksize=chunk_size)
                    
                                # Concatenate all chunks into a single DataFrame
                                for chunk in chunks:
                                    all_chunks.append(chunk)
                                df_logs = pd.concat(all_chunks, ignore_index=True)
                    
                                # Prepare data for anomaly detection
                                df_logs['size'] = pd.to_numeric(df_logs['size'], errors='coerce')
                                df_logs['status'] = pd.to_numeric(df_logs['status'], errors='coerce')
                                df_logs['timestamp'] = pd.to_datetime(df_logs['timestamp'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')
                                df_logs.dropna(subset=['size', 'status', 'timestamp'], inplace=True)
                    
                                # Calculate request rate per IP address (requests per minute)
                                df_logs['minute'] = df_logs['timestamp'].dt.floor('T')
                                request_counts = df_logs.groupby(['ip_address', 'minute']).size().reset_index(name='request_rate')
                                df_logs = pd.merge(df_logs, request_counts, on=['ip_address', 'minute'])
                    
                                # Train Isolation Forest model with contamination threshold
                                X = df_logs[['size', 'status', 'request_rate']]
                                anomaly_model = IsolationForest(contamination=contamination_threshold, random_state=42)
                                df_logs['anomaly'] = anomaly_model.fit_predict(X)
                    
                                # Filter anomalies and normal data
                                anomalies = df_logs[df_logs['anomaly'] == -1]
                                normal_data = df_logs[df_logs['anomaly'] != -1]

                                with st.expander("Detected Anomalies"):
                                    st.write("Detected Anomalies:")
                                    st.dataframe(anomalies[['ip_address', 'request', 'status', 'size', 'request_rate']])
                        
                                # Plot Size vs Time with threshold
                                with st.expander("Size vs Time with Threshold"):
                                    st.write("Size vs Time with Threshold")
                                    size_chart = alt.Chart(df_logs).mark_line().encode(
                                        x='timestamp:T',
                                        y='size:Q',
                                        color=alt.condition(
                                            alt.datum.size > size_threshold,
                                            alt.value('red'),  # Anomalous
                                            alt.value('blue')  # Normal
                                        ),
                                        tooltip=['timestamp', 'size']
                                    ).properties(width=700, height=400, title="Size Over Time with Threshold")
                        
                                    st.altair_chart(size_chart)
                    
                                # Plot Status vs Time with threshold
                                with st.expander("Status vs Time with Threshold"):
                                    st.write("Status vs Time with Threshold")
                                    status_chart = alt.Chart(df_logs).mark_line().encode(
                                        x='timestamp:T',
                                        y='status:Q',
                                        color=alt.condition(
                                            alt.datum.status > status_threshold,
                                            alt.value('red'),  # Anomalous
                                            alt.value('blue')  # Normal
                                        ),
                                        tooltip=['timestamp', 'status']
                                    ).properties(width=700, height=400, title="Status Over Time with Threshold")
                        
                                    st.altair_chart(status_chart)
                    
                                # Plot Request Rate Over Time with threshold
                                with st.expander("Request Rate Over Time with Threshold"):
                                    st.write("Request Rate Over Time with Threshold")
                                    request_rate_chart = alt.Chart(df_logs).mark_line().encode(
                                        x='timestamp:T',
                                        y='request_rate:Q',
                                        color=alt.condition(
                                            alt.datum.request_rate > request_rate_threshold,
                                            alt.value('red'),  # Anomalous
                                            alt.value('green')  # Normal
                                        ),
                                        tooltip=['timestamp', 'request_rate']
                                    ).properties(width=700, height=400, title="Request Rate Over Time with Threshold")
                        
                                    st.altair_chart(request_rate_chart)
        
                                # Plotting anomalies vs normal data
                                with st.expander("Request Rate Over Time with Threshold"):
                                    st.write("Anomaly Distribution")
                                    chart = alt.Chart(df_logs).mark_circle(size=60).encode(
                                        x='size',
                                        y='status',
                                        color=alt.condition(
                                            alt.datum.anomaly == -1,  # Color anomalies differently
                                            alt.value('red'),  # Color for anomalies
                                            alt.value('blue')  # Color for normal data
                                        ),
                                        tooltip=['ip_address', 'request', 'status', 'size']
                                    ).properties(
                                        width=700,
                                        height=400,
                                        title="Anomalies in Size and Status"
                                    )
                        
                                    st.altair_chart(chart)
                    
                            except FileNotFoundError:
                                st.error("Error: File not found. Please provide the correct file path.")
                            except Exception as e:
                                st.error(f"An unexpected error occurred: {e}")
                        else:
                            st.warning("Please upload a CSV file to proceed with anomaly detection.")
    
            elif analysis_type == "Other Analysis":
                st.title("Other Analysis")
                feature = st.sidebar.selectbox(
                        "Choose an analysis to display:",
                        ["Operating Systems", "IP Status Traffic", "User Agent Analysis", "Performance Monitoring",
                         "Referral Analysis", "Top Requested Pages", "404 Error Logs", "Security Insights",
                         "Further Behavior Analysis"]
                    )
                
                uploaded_file = st.file_uploader("Upload your Access Log CSV", type=["csv"])
                # output_dir = 'useCaseFileM'
    
                if uploaded_file is not None:
                    # Read the uploaded CSV file into a DataFrame
                    @st.cache_data
                    def load_data(uploaded_file):
                        return pd.read_csv(uploaded_file)
                
                    df = load_data(uploaded_file)
                    
                
                  
                    if st.button("Analyze Data "):
                        # ---- 1. Extract Operating Systems from User-Agent ----
                        if feature == "Operating Systems":
                            def extract_os(user_agent):
                                if 'Windows' in user_agent:
                                    return 'Windows'
                                elif 'Macintosh' in user_agent:
                                    return 'Mac'
                                elif 'Android' in user_agent:
                                    return 'Android'
                                elif 'iPhone' in user_agent or 'iOS' in user_agent:
                                    return 'iOS'
                                elif 'Linux' in user_agent:
                                    return 'Linux'
                                else:
                                    return 'Other'
                    
                            df['os'] = df['user_agent'].apply(extract_os)
                            os_counts = df['os'].value_counts().reset_index()
                            os_counts.columns = ['Operating_System', 'Count']
                    
                            # Plotting
                            with st.expander("Visualizeed Options"):
                                st.bar_chart(os_counts.set_index('Operating_System')['Count'])
                            with st.expander("Download Options"):
                                st.write(os_counts)
                    
                            # os_counts.to_csv(os.path.join(output_dir, 'operating_systems.csv'), index=False
                    
                        # ---- 3. Traffic Analysis ----
                        elif feature == "IP Status Traffic":
                            ip_status_traffic = df.groupby(['ip_address', 'status']).size().reset_index(name='count')
                    
                            # Plotting
                            ip_status_traffic_pivot = ip_status_traffic.pivot(index='ip_address', columns='status', values='count').fillna(0)
                            with st.expander("Visualized Options"):
                                st.bar_chart(ip_status_traffic_pivot.sum(axis=0))
                            with st.expander("Download Options"):
                                st.write(ip_status_traffic)
                    
                            # ip_status_traffic.to_csv(os.path.join(output_dir, 'ip_status_traffic.csv'), index=False)
                    
                        # ---- 4. User Behavior Analysis (User Agent) ----
                        elif feature == "User Agent Analysis":
                            user_agent_analysis = df['user_agent'].value_counts().reset_index()
                            user_agent_analysis.columns = ['user_agent', 'count']
                    
                            # Plotting
                            with st.expander("Visualized Options"):
                                st.bar_chart(user_agent_analysis.set_index('user_agent')['count'])
                            with st.expander("Download Options"):
                                st.write(user_agent_analysis)
                    
                            # user_agent_analysis.to_csv(os.path.join(output_dir, 'user_agent_analysis.csv'), index=False)
                    
                        # ---- 5. Performance Monitoring (Request Sizes and Status) ----
                        elif feature == "Performance Monitoring":
                            status_size_analysis = df.groupby(['status'])['size'].agg(['mean', 'max', 'min', 'sum']).reset_index()
                    
                            # Plotting
                            with st.expander("Visualized Options"):
                                st.bar_chart(status_size_analysis.set_index('status')['mean'])
                            with st.expander("Download Options"):
                                st.write(status_size_analysis)
                    
                            # status_size_analysis.to_csv(os.path.join(output_dir, 'status_size_analysis.csv'), index=False)
                    
                        
                        # ---- 7. Referral Analysis ----
                        elif feature == "Referral Analysis":
                            referrer_analysis = df['referrer'].value_counts().reset_index()
                            referrer_analysis.columns = ['referrer', 'count']
                    
                            # Plotting
                            with st.expander("Visualized Options"):
                                st.bar_chart(referrer_analysis.set_index('referrer')['count'])
                            with st.expander("Download Options"):
                                st.write(referrer_analysis)
                    
                            # referrer_analysis.to_csv(os.path.join(output_dir, 'referrer_analysis.csv'), index=False)
                    
                        # ---- 8. Top Requested Pages ----
                        elif feature == "Top Requested Pages":
                            df['page'] = df['request'].str.extract(r'GET (\S+)')
                            top_pages = df['page'].value_counts().head(10)
                    
                            # Plotting
                            with st.expander("Visualized Options"):
                                st.bar_chart(top_pages)
                            with st.expander("Download Options"):
                                st.write(top_pages)
                    
                            # top_pages.to_csv(os.path.join(output_dir, 'top_requested_pages.csv'), header=['count'])
                    
                        # ---- 9. 404 Error Logs ----
                        elif feature == "404 Error Logs":
                            error_logs = df[df['status'] == 404]
                    
                            # Displaying 404 errors
                            with st.expander("Download Options"):
                                st.write(error_logs)
                                st.write(f"Total 404 errors: {len(error_logs)}")
                    
                            # error_logs.to_csv(os.path.join(output_dir, 'error_logs_404.csv'), index=False)
                    
                        # ---- 10. Security Insights ----
                        elif feature == "Security Insights":
                            # High-Frequency IPs
                            high_freq_ips = df['ip_address'].value_counts().reset_index()
                            high_freq_ips.columns = ['ip_address', 'count']
                    
                            # Plotting
                            with st.expander("Visualized Options"):
                                st.bar_chart(high_freq_ips.set_index('ip_address')['count'])
                            with st.expander("Download Options"):
                                st.write(high_freq_ips)
                    
                            # high_freq_ips.to_csv(os.path.join(output_dir, 'high_frequency_ips.csv'), index=False)
                    
                        # ---- 11. Further Behavior Analysis ----
                        elif feature == "Further Behavior Analysis":
                            # Most Common Platforms (User-Agent Analysis)
                            df['platform'] = df['user_agent'].str.extract(r'\(([^)]+)\)')
                            platform_analysis = df['platform'].value_counts().reset_index()
                            platform_analysis.columns = ['platform', 'count']
                    
                            # Plotting
                            with st.expander("Visualized Options"):
                                st.bar_chart(platform_analysis.set_index('platform')['count'])
                            with st.expander("Download Options"):
                                st.write(platform_analysis)
                    
                            # platform_analysis.to_csv(os.path.join(output_dir, 'platform_analysis.csv'), index=False)
                    
                        # st.write("All CSV files are saved in the 'useCaseFileM' folder.")
                    else:
                        st.warning("Please upload a CSV file to proceed with analysis.")
    
                

# Run the Streamlit app
if __name__ == "__main__":
    main()
