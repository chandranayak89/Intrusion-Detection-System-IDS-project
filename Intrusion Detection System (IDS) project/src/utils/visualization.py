#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Visualization Module
This module provides visualization utilities for network traffic and intrusion detection.
"""

import os
import logging
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import seaborn as sns
from datetime import datetime, timedelta
from collections import Counter

# Setup logging
logger = logging.getLogger('ids.visualization')

def set_plot_style(dark_mode=False):
    """
    Set the style for matplotlib plots.
    
    Args:
        dark_mode (bool): Whether to use dark mode
    """
    if dark_mode:
        plt.style.use('dark_background')
        sns.set_style("darkgrid")
    else:
        plt.style.use('ggplot')
        sns.set_style("whitegrid")
        
    # Set font sizes
    plt.rcParams['font.size'] = 12
    plt.rcParams['axes.titlesize'] = 14
    plt.rcParams['axes.labelsize'] = 12
    
    # Set figure size
    plt.rcParams['figure.figsize'] = (12, 8)

def plot_packet_count_over_time(packets, time_interval='1min', output_file=None):
    """
    Plot packet count over time.
    
    Args:
        packets (list or pd.DataFrame): List of packet dictionaries or DataFrame
        time_interval (str): Time interval for grouping (e.g., '1min', '1s')
        output_file (str, optional): Path to save the plot
        
    Returns:
        matplotlib.figure.Figure: The figure object
    """
    logger.info("Plotting packet count over time")
    
    # Convert to DataFrame if needed
    if not isinstance(packets, pd.DataFrame):
        df = pd.DataFrame(packets)
    else:
        df = packets.copy()
        
    # Ensure timestamp is in datetime format
    if 'timestamp' in df.columns:
        if df['timestamp'].dtype == 'object':
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Group by time interval and count packets
        packet_counts = df.groupby(pd.Grouper(key='timestamp', freq=time_interval)).size()
        
        # Plot
        fig, ax = plt.subplots()
        packet_counts.plot(kind='line', marker='o', ax=ax)
        
        # Format x-axis
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        plt.xticks(rotation=45)
        
        # Add labels and title
        plt.xlabel('Time')
        plt.ylabel('Packet Count')
        plt.title(f'Packet Count Over Time (Interval: {time_interval})')
        plt.tight_layout()
        
        if output_file:
            plt.savefig(output_file)
            logger.info(f"Plot saved to {output_file}")
            
        return fig
    else:
        logger.warning("No timestamp column found in data")
        return None

def plot_protocol_distribution(packets, output_file=None):
    """
    Plot protocol distribution as a pie chart.
    
    Args:
        packets (list or pd.DataFrame): List of packet dictionaries or DataFrame
        output_file (str, optional): Path to save the plot
        
    Returns:
        matplotlib.figure.Figure: The figure object
    """
    logger.info("Plotting protocol distribution")
    
    # Convert to DataFrame if needed
    if not isinstance(packets, pd.DataFrame):
        df = pd.DataFrame(packets)
    else:
        df = packets.copy()
        
    if 'protocol' in df.columns:
        # Count protocols
        protocol_counts = df['protocol'].value_counts()
        
        # Plot
        fig, ax = plt.subplots()
        protocol_counts.plot(kind='pie', autopct='%1.1f%%', ax=ax)
        
        # Add title
        plt.title('Protocol Distribution')
        plt.ylabel('')  # Hide the label
        plt.tight_layout()
        
        if output_file:
            plt.savefig(output_file)
            logger.info(f"Plot saved to {output_file}")
            
        return fig
    else:
        logger.warning("No protocol column found in data")
        return None

def plot_port_activity(packets, top_n=10, output_file=None):
    """
    Plot the most active ports.
    
    Args:
        packets (list or pd.DataFrame): List of packet dictionaries or DataFrame
        top_n (int): Number of top ports to show
        output_file (str, optional): Path to save the plot
        
    Returns:
        matplotlib.figure.Figure: The figure object
    """
    logger.info(f"Plotting top {top_n} port activity")
    
    # Convert to DataFrame if needed
    if not isinstance(packets, pd.DataFrame):
        df = pd.DataFrame(packets)
    else:
        df = packets.copy()
        
    # Create separate plots for source and destination ports
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 7))
    
    # Source ports
    if 'src_port' in df.columns:
        src_port_counts = df['src_port'].value_counts().nlargest(top_n)
        src_port_counts.plot(kind='barh', ax=ax1)
        ax1.set_title(f'Top {top_n} Source Ports')
        ax1.set_xlabel('Count')
        ax1.set_ylabel('Port')
    else:
        ax1.text(0.5, 0.5, 'No source port data', ha='center', va='center')
        logger.warning("No src_port column found in data")
        
    # Destination ports
    if 'dst_port' in df.columns:
        dst_port_counts = df['dst_port'].value_counts().nlargest(top_n)
        dst_port_counts.plot(kind='barh', ax=ax2)
        ax2.set_title(f'Top {top_n} Destination Ports')
        ax2.set_xlabel('Count')
        ax2.set_ylabel('Port')
    else:
        ax2.text(0.5, 0.5, 'No destination port data', ha='center', va='center')
        logger.warning("No dst_port column found in data")
        
    plt.tight_layout()
    
    if output_file:
        plt.savefig(output_file)
        logger.info(f"Plot saved to {output_file}")
        
    return fig

def plot_ip_connections(packets, top_n=10, output_file=None):
    """
    Plot IP address connections.
    
    Args:
        packets (list or pd.DataFrame): List of packet dictionaries or DataFrame
        top_n (int): Number of top IPs to show
        output_file (str, optional): Path to save the plot
        
    Returns:
        matplotlib.figure.Figure: The figure object
    """
    logger.info(f"Plotting top {top_n} IP connections")
    
    # Convert to DataFrame if needed
    if not isinstance(packets, pd.DataFrame):
        df = pd.DataFrame(packets)
    else:
        df = packets.copy()
        
    # Create separate plots for source and destination IPs
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 7))
    
    # Source IPs
    if 'src_ip' in df.columns:
        src_ip_counts = df['src_ip'].value_counts().nlargest(top_n)
        src_ip_counts.plot(kind='barh', ax=ax1)
        ax1.set_title(f'Top {top_n} Source IPs')
        ax1.set_xlabel('Count')
        ax1.set_ylabel('IP Address')
    else:
        ax1.text(0.5, 0.5, 'No source IP data', ha='center', va='center')
        logger.warning("No src_ip column found in data")
        
    # Destination IPs
    if 'dst_ip' in df.columns:
        dst_ip_counts = df['dst_ip'].value_counts().nlargest(top_n)
        dst_ip_counts.plot(kind='barh', ax=ax2)
        ax2.set_title(f'Top {top_n} Destination IPs')
        ax2.set_xlabel('Count')
        ax2.set_ylabel('IP Address')
    else:
        ax2.text(0.5, 0.5, 'No destination IP data', ha='center', va='center')
        logger.warning("No dst_ip column found in data")
        
    plt.tight_layout()
    
    if output_file:
        plt.savefig(output_file)
        logger.info(f"Plot saved to {output_file}")
        
    return fig

def plot_packet_length_histogram(packets, bins=20, output_file=None):
    """
    Plot a histogram of packet lengths.
    
    Args:
        packets (list or pd.DataFrame): List of packet dictionaries or DataFrame
        bins (int): Number of bins for the histogram
        output_file (str, optional): Path to save the plot
        
    Returns:
        matplotlib.figure.Figure: The figure object
    """
    logger.info("Plotting packet length histogram")
    
    # Convert to DataFrame if needed
    if not isinstance(packets, pd.DataFrame):
        df = pd.DataFrame(packets)
    else:
        df = packets.copy()
        
    if 'length' in df.columns:
        # Plot
        fig, ax = plt.subplots()
        sns.histplot(df['length'], bins=bins, kde=True, ax=ax)
        
        # Add labels and title
        plt.xlabel('Packet Length (bytes)')
        plt.ylabel('Count')
        plt.title('Packet Length Distribution')
        plt.tight_layout()
        
        if output_file:
            plt.savefig(output_file)
            logger.info(f"Plot saved to {output_file}")
            
        return fig
    else:
        logger.warning("No length column found in data")
        return None

def plot_anomaly_scores(scores, threshold=None, output_file=None):
    """
    Plot anomaly scores with optional threshold.
    
    Args:
        scores (list or np.ndarray): Anomaly scores
        threshold (float, optional): Anomaly threshold
        output_file (str, optional): Path to save the plot
        
    Returns:
        matplotlib.figure.Figure: The figure object
    """
    logger.info("Plotting anomaly scores")
    
    # Convert to numpy array
    scores = np.array(scores)
    
    # Plot
    fig, ax = plt.subplots()
    plt.plot(scores, marker='o', linestyle='-', markersize=4)
    
    # Add threshold line if provided
    if threshold is not None:
        plt.axhline(y=threshold, color='red', linestyle='--', label=f'Threshold ({threshold})')
        
        # Color anomalous points
        anomalies = scores < threshold
        if anomalies.any():
            plt.scatter(
                np.where(anomalies)[0], 
                scores[anomalies],
                color='red', 
                s=80, 
                label='Anomalies'
            )
            
        plt.legend()
        
    # Add labels and title
    plt.xlabel('Sample Index')
    plt.ylabel('Anomaly Score')
    plt.title('Anomaly Detection Scores')
    plt.tight_layout()
    
    if output_file:
        plt.savefig(output_file)
        logger.info(f"Plot saved to {output_file}")
        
    return fig

def plot_feature_importance(feature_names, importances, top_n=20, output_file=None):
    """
    Plot feature importance.
    
    Args:
        feature_names (list): Names of features
        importances (list or np.ndarray): Importance scores
        top_n (int): Number of top features to show
        output_file (str, optional): Path to save the plot
        
    Returns:
        matplotlib.figure.Figure: The figure object
    """
    logger.info(f"Plotting top {top_n} feature importances")
    
    # Sort features by importance
    indices = np.argsort(importances)[::-1]
    top_indices = indices[:top_n]
    
    # Get top features and scores
    top_features = [feature_names[i] for i in top_indices]
    top_importances = [importances[i] for i in top_indices]
    
    # Plot
    fig, ax = plt.subplots()
    plt.barh(range(len(top_features)), top_importances, align='center')
    plt.yticks(range(len(top_features)), top_features)
    
    # Add labels and title
    plt.xlabel('Importance')
    plt.ylabel('Feature')
    plt.title(f'Top {top_n} Feature Importances')
    plt.tight_layout()
    
    if output_file:
        plt.savefig(output_file)
        logger.info(f"Plot saved to {output_file}")
        
    return fig

def plot_alerts_timeline(alerts, interval='1h', output_file=None):
    """
    Plot alerts timeline.
    
    Args:
        alerts (list or pd.DataFrame): List of alert dictionaries or DataFrame
        interval (str): Time interval for grouping
        output_file (str, optional): Path to save the plot
        
    Returns:
        matplotlib.figure.Figure: The figure object
    """
    logger.info("Plotting alerts timeline")
    
    # Convert to DataFrame if needed
    if not isinstance(alerts, pd.DataFrame):
        df = pd.DataFrame(alerts)
    else:
        df = alerts.copy()
        
    if 'timestamp' in df.columns:
        # Ensure timestamp is in datetime format
        if df['timestamp'].dtype == 'object':
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
        # Group by time interval and count alerts
        alert_counts = df.groupby(pd.Grouper(key='timestamp', freq=interval)).size()
        
        # Plot
        fig, ax = plt.subplots()
        alert_counts.plot(kind='line', marker='o', ax=ax)
        
        # Format x-axis
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))
        plt.xticks(rotation=45)
        
        # Add labels and title
        plt.xlabel('Time')
        plt.ylabel('Alert Count')
        plt.title(f'Alerts Over Time (Interval: {interval})')
        plt.tight_layout()
        
        if output_file:
            plt.savefig(output_file)
            logger.info(f"Plot saved to {output_file}")
            
        return fig
    else:
        logger.warning("No timestamp column found in alerts data")
        return None

def plot_alerts_by_type(alerts, output_file=None):
    """
    Plot alerts by type.
    
    Args:
        alerts (list or pd.DataFrame): List of alert dictionaries or DataFrame
        output_file (str, optional): Path to save the plot
        
    Returns:
        matplotlib.figure.Figure: The figure object
    """
    logger.info("Plotting alerts by type")
    
    # Convert to DataFrame if needed
    if not isinstance(alerts, pd.DataFrame):
        df = pd.DataFrame(alerts)
    else:
        df = alerts.copy()
        
    if 'type' in df.columns:
        # Count alert types
        type_counts = df['type'].value_counts()
        
        # Plot
        fig, ax = plt.subplots()
        type_counts.plot(kind='bar', ax=ax)
        
        # Add labels and title
        plt.xlabel('Alert Type')
        plt.ylabel('Count')
        plt.title('Alerts by Type')
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        if output_file:
            plt.savefig(output_file)
            logger.info(f"Plot saved to {output_file}")
            
        return fig
    else:
        logger.warning("No type column found in alerts data")
        return None

def plot_alerts_by_severity(alerts, output_file=None):
    """
    Plot alerts by severity.
    
    Args:
        alerts (list or pd.DataFrame): List of alert dictionaries or DataFrame
        output_file (str, optional): Path to save the plot
        
    Returns:
        matplotlib.figure.Figure: The figure object
    """
    logger.info("Plotting alerts by severity")
    
    # Convert to DataFrame if needed
    if not isinstance(alerts, pd.DataFrame):
        df = pd.DataFrame(alerts)
    else:
        df = alerts.copy()
        
    if 'severity' in df.columns:
        # Count alert severities
        severity_counts = df['severity'].value_counts()
        
        # Plot
        fig, ax = plt.subplots()
        
        # Define colors for severity levels
        severity_colors = {
            'critical': 'darkred',
            'high': 'red',
            'medium': 'orange',
            'low': 'green',
            'info': 'blue'
        }
        
        # Get colors for each severity
        colors = [severity_colors.get(str(s).lower(), 'gray') for s in severity_counts.index]
        
        # Create bar chart
        bars = severity_counts.plot(kind='bar', color=colors, ax=ax)
        
        # Add labels and title
        plt.xlabel('Severity')
        plt.ylabel('Count')
        plt.title('Alerts by Severity')
        plt.xticks(rotation=0)
        plt.tight_layout()
        
        if output_file:
            plt.savefig(output_file)
            logger.info(f"Plot saved to {output_file}")
            
        return fig
    else:
        logger.warning("No severity column found in alerts data")
        return None

def plot_traffic_heatmap(packets, time_interval='1h', output_file=None):
    """
    Plot traffic heatmap by hour and day.
    
    Args:
        packets (list or pd.DataFrame): List of packet dictionaries or DataFrame
        time_interval (str): Time interval for grouping
        output_file (str, optional): Path to save the plot
        
    Returns:
        matplotlib.figure.Figure: The figure object
    """
    logger.info("Plotting traffic heatmap")
    
    # Convert to DataFrame if needed
    if not isinstance(packets, pd.DataFrame):
        df = pd.DataFrame(packets)
    else:
        df = packets.copy()
        
    if 'timestamp' in df.columns:
        # Ensure timestamp is in datetime format
        if df['timestamp'].dtype == 'object':
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
        # Extract hour and day
        df['hour'] = df['timestamp'].dt.hour
        df['day'] = df['timestamp'].dt.day_name()
        
        # Count packets by hour and day
        heatmap_data = df.groupby(['day', 'hour']).size().unstack(fill_value=0)
        
        # Define day order
        day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        heatmap_data = heatmap_data.reindex(day_order)
        
        # Plot
        fig, ax = plt.subplots(figsize=(12, 8))
        sns.heatmap(heatmap_data, cmap='YlOrRd', annot=True, fmt='g', ax=ax)
        
        # Add labels and title
        plt.xlabel('Hour of Day')
        plt.ylabel('Day of Week')
        plt.title('Traffic Heatmap by Hour and Day')
        plt.tight_layout()
        
        if output_file:
            plt.savefig(output_file)
            logger.info(f"Plot saved to {output_file}")
            
        return fig
    else:
        logger.warning("No timestamp column found in data")
        return None

def generate_dashboard(packets, alerts=None, output_dir=None):
    """
    Generate a dashboard with multiple plots.
    
    Args:
        packets (list or pd.DataFrame): List of packet dictionaries or DataFrame
        alerts (list or pd.DataFrame, optional): List of alert dictionaries or DataFrame
        output_dir (str, optional): Directory to save the plots
        
    Returns:
        list: List of generated figures
    """
    logger.info("Generating dashboard")
    
    # Create output directory if specified
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        
    # Set plot style
    set_plot_style()
    
    # List to store figures
    figures = []
    
    # Generate network traffic plots
    if output_dir:
        packet_time_file = os.path.join(output_dir, 'packet_count_over_time.png')
        protocol_file = os.path.join(output_dir, 'protocol_distribution.png')
        port_file = os.path.join(output_dir, 'port_activity.png')
        ip_file = os.path.join(output_dir, 'ip_connections.png')
        length_file = os.path.join(output_dir, 'packet_length_histogram.png')
        heatmap_file = os.path.join(output_dir, 'traffic_heatmap.png')
    else:
        packet_time_file = protocol_file = port_file = ip_file = length_file = heatmap_file = None
    
    # Packet count over time
    fig1 = plot_packet_count_over_time(packets, output_file=packet_time_file)
    if fig1:
        figures.append(fig1)
        
    # Protocol distribution
    fig2 = plot_protocol_distribution(packets, output_file=protocol_file)
    if fig2:
        figures.append(fig2)
        
    # Port activity
    fig3 = plot_port_activity(packets, output_file=port_file)
    if fig3:
        figures.append(fig3)
        
    # IP connections
    fig4 = plot_ip_connections(packets, output_file=ip_file)
    if fig4:
        figures.append(fig4)
        
    # Packet length histogram
    fig5 = plot_packet_length_histogram(packets, output_file=length_file)
    if fig5:
        figures.append(fig5)
        
    # Traffic heatmap
    fig6 = plot_traffic_heatmap(packets, output_file=heatmap_file)
    if fig6:
        figures.append(fig6)
    
    # Generate alert plots if alerts are provided
    if alerts is not None:
        if output_dir:
            alerts_time_file = os.path.join(output_dir, 'alerts_timeline.png')
            alerts_type_file = os.path.join(output_dir, 'alerts_by_type.png')
            alerts_severity_file = os.path.join(output_dir, 'alerts_by_severity.png')
        else:
            alerts_time_file = alerts_type_file = alerts_severity_file = None
            
        # Alerts timeline
        fig7 = plot_alerts_timeline(alerts, output_file=alerts_time_file)
        if fig7:
            figures.append(fig7)
            
        # Alerts by type
        fig8 = plot_alerts_by_type(alerts, output_file=alerts_type_file)
        if fig8:
            figures.append(fig8)
            
        # Alerts by severity
        fig9 = plot_alerts_by_severity(alerts, output_file=alerts_severity_file)
        if fig9:
            figures.append(fig9)
    
    logger.info(f"Generated {len(figures)} dashboard plots")
    return figures

def save_dashboard_html(figures, output_file):
    """
    Save dashboard as an HTML file.
    
    Args:
        figures (list): List of matplotlib figures
        output_file (str): Path to save the HTML file
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Import required libraries
        from matplotlib.backends.backend_agg import FigureCanvasAgg
        from base64 import b64encode
        import io
        
        # Create HTML content
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>IDS Dashboard</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    margin: 20px;
                    background-color: #f5f5f5;
                }
                h1 {
                    color: #333;
                    text-align: center;
                }
                .dashboard {
                    display: flex;
                    flex-wrap: wrap;
                    justify-content: center;
                }
                .plot {
                    margin: 10px;
                    padding: 10px;
                    background-color: white;
                    border-radius: 5px;
                    box-shadow: 0 0 5px rgba(0, 0, 0, 0.2);
                }
                img {
                    max-width: 100%;
                    height: auto;
                }
            </style>
        </head>
        <body>
            <h1>IDS Dashboard</h1>
            <div class="dashboard">
        """
        
        # Add figures to HTML
        for i, fig in enumerate(figures):
            # Convert figure to PNG image
            canvas = FigureCanvasAgg(fig)
            png_output = io.BytesIO()
            canvas.print_png(png_output)
            png_encoded = b64encode(png_output.getvalue()).decode('utf-8')
            
            # Add image to HTML
            html_content += f"""
                <div class="plot">
                    <img src="data:image/png;base64,{png_encoded}" />
                </div>
            """
            
            # Close the figure to free memory
            plt.close(fig)
            
        # Close HTML tags
        html_content += """
            </div>
        </body>
        </html>
        """
        
        # Save HTML to file
        with open(output_file, 'w') as f:
            f.write(html_content)
            
        logger.info(f"Dashboard saved to {output_file}")
        return True
        
    except Exception as e:
        logger.error(f"Error saving dashboard to HTML: {e}")
        return False

if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    # Create sample data
    timestamps = [datetime.now() + timedelta(minutes=i) for i in range(100)]
    protocols = np.random.choice(['TCP', 'UDP', 'ICMP'], 100, p=[0.7, 0.2, 0.1])
    lengths = np.random.normal(500, 200, 100).astype(int)
    src_ips = np.random.choice(['192.168.1.' + str(i) for i in range(1, 10)], 100)
    dst_ips = np.random.choice(['10.0.0.' + str(i) for i in range(1, 5)], 100)
    src_ports = np.random.choice(range(1024, 65536), 100)
    dst_ports = np.random.choice([80, 443, 22, 25, 53], 100)
    
    # Create packet DataFrame
    packets_df = pd.DataFrame({
        'timestamp': timestamps,
        'protocol': protocols,
        'length': lengths,
        'src_ip': src_ips,
        'dst_ip': dst_ips,
        'src_port': src_ports,
        'dst_port': dst_ports
    })
    
    # Create sample alerts
    alert_timestamps = [datetime.now() + timedelta(minutes=i*5) for i in range(20)]
    alert_types = np.random.choice(['Signature', 'Anomaly', 'Rate'], 20, p=[0.4, 0.3, 0.3])
    alert_severities = np.random.choice(['Low', 'Medium', 'High', 'Critical'], 20, p=[0.4, 0.3, 0.2, 0.1])
    
    # Create alerts DataFrame
    alerts_df = pd.DataFrame({
        'timestamp': alert_timestamps,
        'type': alert_types,
        'severity': alert_severities
    })
    
    # Generate dashboard
    output_dir = 'dashboard_output'
    figures = generate_dashboard(packets_df, alerts_df, output_dir)
    
    # Save dashboard as HTML
    save_dashboard_html(figures, os.path.join(output_dir, 'dashboard.html')) 