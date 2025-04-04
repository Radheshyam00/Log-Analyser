import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from statsmodels.tsa.statespace.sarimax import SARIMAX
from statsmodels.tsa.stattools import adfuller
from sklearn.metrics import mean_absolute_error

# Streamlit UI components
st.title('Traffic Forecasting with SARIMA')

# Upload file
uploaded_file = st.file_uploader("Upload your CSV file", type=["csv"])

# Parameters for training
st.sidebar.header("Model Training Parameters")
p_value = st.sidebar.slider("p (AR term)", 0, 5, 1)
d_value = st.sidebar.slider("d (Differencing term)", 0, 2, 1)
q_value = st.sidebar.slider("q (MA term)", 0, 5, 1)
P_value = st.sidebar.slider("P (Seasonal AR term)", 0, 5, 1)
D_value = st.sidebar.slider("D (Seasonal Differencing term)", 0, 2, 1)
Q_value = st.sidebar.slider("Q (Seasonal MA term)", 0, 5, 1)
seasonal_period = st.sidebar.slider("Seasonal Period (s)", 30, 120, 60)

if uploaded_file is not None:
    # Load and display data
    df = pd.read_csv(uploaded_file)

    # Ensure the timestamp column is in the correct datetime format
    try:
        # Specify the datetime format for parsing
        df['timestamp'] = pd.to_datetime(df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z')
        st.write("Data Preview:", df.head())
    except Exception as e:
        st.error(f"Error parsing datetime: {e}")
        st.stop()

    # Prepare the data
    df.set_index('timestamp', inplace=True)  # Set the timestamp as the index

    # Aggregate data to requests per minute
    requests_per_minute = df.resample('T').size()

    # Visualize the time series
    st.subheader("Requests Per Minute")
    fig, ax = plt.subplots(figsize=(12, 6))
    requests_per_minute.plot(ax=ax)
    ax.set_title("Requests Per Minute")
    ax.set_xlabel("Time")
    ax.set_ylabel("Requests")
    st.pyplot(fig)

    # Check for stationarity using ADF test
    result = adfuller(requests_per_minute)
    st.write(f"ADF Statistic: {result[0]}")
    st.write(f"p-value: {result[1]}")

    # If p-value > 0.05, the series is not stationary and may need differencing
    # In case it's non-stationary, apply differencing
    if result[1] > 0.05:
        requests_per_minute_diff = requests_per_minute.diff().dropna()  # First order differencing
        result_diff = adfuller(requests_per_minute_diff)
        st.write(f"ADF Statistic (Differenced): {result_diff[0]}")
        st.write(f"p-value (Differenced): {result_diff[1]}")
        requests_per_minute = requests_per_minute_diff  # Use the differenced series

    # Train on all data for future prediction (without using test set)
    train = requests_per_minute  # Use entire data for training

    # Fit SARIMA model (order=(p,d,q), seasonal_order=(P,D,Q,s))
    model = SARIMAX(train, order=(p_value, d_value, q_value), seasonal_order=(P_value, D_value, Q_value, seasonal_period))
    model_fit = model.fit(disp=False)

    # Make forecast for the next 60 minutes
    forecast_steps = st.sidebar.slider("Forecast Steps (minutes)", 10, 180, 60)  # Number of minutes to forecast
    forecast = model_fit.forecast(steps=forecast_steps)

    # Plot the results
    st.subheader("Forecast for Future")
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.plot(train.index, train, label="Training Data")
    ax.plot(pd.date_range(train.index[-1], periods=forecast_steps, freq='T'), forecast, label="Forecast", color='red')
    ax.legend()
    ax.set_title(f"Requests Per Minute Prediction for the Next {forecast_steps} Minutes")
    ax.set_xlabel("Time")
    ax.set_ylabel("Requests")
    st.pyplot(fig)

    # Optionally display the model summary
    st.subheader("Model Summary")
    st.text(model_fit.summary())

    # Optionally, save the trained model
    import joblib
    joblib.dump(model_fit, 'sarima_model.pkl')
    st.write("Model has been saved.")

    # Display the forecasted values
    st.write(f"Forecasted values for the next {forecast_steps} minutes:", forecast)
