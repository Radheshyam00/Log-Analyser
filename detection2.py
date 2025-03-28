import streamlit as st
import pandas as pd
import requests
from ipaddress import ip_address, ip_network

# Replace with your ipinfo API token
IPINFO_API_TOKEN = "ae43dbe640ec07"

# Function to fetch IP details from ipinfo
def get_ipinfo(ip_address):
    """Fetch IP details from ipinfo."""
    url = f"https://ipinfo.io/{ip_address}?token={IPINFO_API_TOKEN}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        st.error(f"Error fetching data for {ip_address}: {response.status_code}")
        return None

# Function to validate IP type (trusted, proxy, or regular)
def validate_ip(ip_address):
    """Validate if an IP is authenticated or from a proxy."""
    ip_info = get_ipinfo(ip_address)
    if not ip_info:
        return "Error fetching IP information"

    # Check if IP belongs to a known bot (e.g., Googlebot, Bingbot)
    organization = ip_info.get("org", "")
    trusted_bots = ["Google", "Microsoft", "Amazon"]  # Extend as needed
    for bot in trusted_bots:
        if bot in organization:
            return f"Authenticated IP: Belongs to {bot}"

    # Check if IP belongs to a proxy or hosting provider
    proxy_indicators = ["Data Center", "Hosting", "Proxy", "VPN", "Cloud"]
    for indicator in proxy_indicators:
        if indicator in organization:
            return "Proxy/Hosting Provider IP Detected"
    
    return "Regular IP or insufficient information for classification"

# Function to detect potential IP spoofing with validation
def detect_ip_spoofing_with_validation(df):
    """Detect IP spoofing and classify IP types."""
    private_ip_ranges = [
        ip_network("10.0.0.0/8"),
        ip_network("172.16.0.0/12"),
        ip_network("192.168.0.0/16"),
        ip_network("127.0.0.0/8"),
        ip_network("169.254.0.0/16"),  # Link-local addresses
    ]

    # Check if the IP is private
    df["is_private"] = df["ip_address"].apply(
        lambda ip: any(ip_address(ip) in network for network in private_ip_ranges) if ip_address(ip) else False
    )
    
    # Classify IPs using ipinfo
    df["ip_classification"] = df["ip_address"].apply(validate_ip)
    
    return df

# Streamlit App
def main():
    st.title("IP Spoofing and Classification Tool")
    
    # Input Section
    st.sidebar.header("Settings")
    ip_list_input = st.sidebar.text_area("Enter IPs (one per line)", placeholder="e.g., 54.36.149.41\n31.56.96.51\n40.77.167.129")
    analyze_button = st.sidebar.button("Analyze IPs")

    if analyze_button and ip_list_input:
        # Process input
        ip_list = ip_list_input.splitlines()
        ip_list = [ip.strip() for ip in ip_list if ip.strip()]  # Clean and filter empty lines
        
        # Create DataFrame
        data = {"ip_address": ip_list}
        df = pd.DataFrame(data)
        
        # Run spoofing detection and classification
        with st.spinner("Analyzing IPs..."):
            result_df = detect_ip_spoofing_with_validation(df)

        # Display Results
        st.success("Analysis Complete!")
        st.dataframe(result_df)
    elif not ip_list_input and analyze_button:
        st.warning("Please enter at least one IP address.")

if __name__ == "__main__":
    main()
