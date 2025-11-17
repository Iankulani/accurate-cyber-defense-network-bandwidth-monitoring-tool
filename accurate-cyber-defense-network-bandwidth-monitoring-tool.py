import sys
import time
import argparse
import psutil
from collections import defaultdict, deque
from datetime import datetime, timedelta
import socket
import threading
import csv
import platform
import os
import json
import math
from typing import Dict, List, Tuple, Optional, Any
import select
from pathlib import Path

# GUI imports
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.animation as animation
from matplotlib import style
import numpy as np

class BandwidthMonitorCore:
    """Core functionality for bandwidth monitoring"""
    
    def __init__(self):
        self.monitoring = False
        self.start_time = None
        self.traffic_data = defaultdict(lambda: {
            'upload': 0, 
            'download': 0,
            'upload_history': deque(maxlen=100),
            'download_history': deque(maxlen=100),
            'timestamps': deque(maxlen=100),
            'pid': None,
            'port': None,
            'protocol': 'Unknown',
            'process_name': 'Unknown'
        })
        
        self.historical_data = []
        self.update_interval = 1.0  # seconds
        self.old_stats = {}
        self.current_interface = None
        self.target_ip = None
        self.running = True
        self.data_lock = threading.Lock()
        self.callbacks = []
        self.realtime_data = deque(maxlen=300)
        self.peak_bandwidth = {'download': 0, 'upload': 0}
        self.alerts = []
        self.alert_threshold = 100 * 1024 * 1024  # 100 MB/s default threshold
        
    def register_callback(self, callback):
        """Register callback for real-time updates"""
        self.callbacks.append(callback)
    
    def notify_callbacks(self, data):
        """Notify all registered callbacks"""
        for callback in self.callbacks:
            try:
                callback(data)
            except Exception as e:
                print(f"Callback error: {e}")
    
    def get_network_interfaces(self) -> List[str]:
        """Get available network interfaces"""
        return list(psutil.net_if_addrs().keys())
    
    def get_interface_stats(self) -> Dict:
        """Get interface statistics"""
        return psutil.net_io_counters(pernic=True)
    
    def validate_ip(self, ip: str) -> bool:
        """Validate an IP address"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                return True
            except socket.error:
                return False
    
    def get_process_name(self, pid: int) -> str:
        """Get process name from PID"""
        try:
            if pid:
                process = psutil.Process(pid)
                return process.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return "Unknown"
    
    def get_network_stats(self) -> Dict:
        """Get current network statistics per connection"""
        stats = {}
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.laddr and conn.raddr:
                    ip = conn.raddr.ip
                    if ip not in stats:
                        stats[ip] = {
                            'pid': conn.pid,
                            'upload': 0,
                            'download': 0,
                            'port': conn.raddr.port,
                            'protocol': self.determine_protocol(conn.raddr.port),
                            'process_name': self.get_process_name(conn.pid)
                        }
        except Exception as e:
            print(f"Error getting network stats: {e}")
        
        return stats
    
    def determine_protocol(self, port: int) -> str:
        """Determine protocol based on port number"""
        common_ports = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 465: "SMTPS", 587: "SMTP",
            993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            27017: "MongoDB", 6379: "Redis", 11211: "Memcached"
        }
        return common_ports.get(port, f"Port {port}")
    
    def calculate_bandwidth_usage(self) -> Tuple[float, float]:
        """Calculate total bandwidth usage in MB/s"""
        total_download = 0
        total_upload = 0
        
        with self.data_lock:
            for data in self.traffic_data.values():
                total_download += data['download']
                total_upload += data['upload']
        
        return total_download / (1024 * 1024), total_upload / (1024 * 1024)
    
    def monitor_bandwidth(self):
        """Background thread to monitor bandwidth"""
        last_time = time.time()
        
        while self.monitoring and self.running:
            current_time = time.time()
            elapsed = current_time - last_time
            
            if elapsed < self.update_interval:
                time.sleep(self.update_interval - elapsed)
                continue
            
            try:
                # Get current stats
                new_stats = self.get_network_stats()
                interface_stats = self.get_interface_stats()
                
                if self.current_interface and self.current_interface in interface_stats:
                    io_counters = interface_stats[self.current_interface]
                    
                    # Calculate bandwidth for each IP
                    for ip, data in new_stats.items():
                        if self.target_ip.lower() != 'all' and ip != self.target_ip:
                            continue
                        
                        # Update traffic data with process info
                        with self.data_lock:
                            if ip not in self.traffic_data:
                                self.traffic_data[ip].update({
                                    'pid': data['pid'],
                                    'port': data['port'],
                                    'protocol': data['protocol'],
                                    'process_name': data['process_name']
                                })
                        
                        # Simulate bandwidth data (in real implementation, you'd track bytes)
                        download_rate = np.random.randint(0, 100 * 1024)  # Random data for demo
                        upload_rate = np.random.randint(0, 50 * 1024)     # Random data for demo
                        
                        with self.data_lock:
                            self.traffic_data[ip]['download'] += download_rate
                            self.traffic_data[ip]['upload'] += upload_rate
                            
                            # Update history
                            self.traffic_data[ip]['download_history'].append(
                                self.traffic_data[ip]['download'] / (1024 * 1024)
                            )
                            self.traffic_data[ip]['upload_history'].append(
                                self.traffic_data[ip]['upload'] / (1024 * 1024)
                            )
                            self.traffic_data[ip]['timestamps'].append(current_time)
                            
                            # Update peak bandwidth
                            total_bandwidth = download_rate + upload_rate
                            if total_bandwidth > self.peak_bandwidth['download']:
                                self.peak_bandwidth['download'] = total_bandwidth
                            
                            # Check alerts
                            if total_bandwidth > self.alert_threshold:
                                self.add_alert(f"High bandwidth usage detected: {ip} - {total_bandwidth/1024/1024:.2f} MB/s")
                
                # Update real-time data for graphs
                total_download, total_upload = self.calculate_bandwidth_usage()
                self.realtime_data.append({
                    'timestamp': current_time,
                    'download': total_download,
                    'upload': total_upload,
                    'total': total_download + total_upload
                })
                
                # Notify callbacks
                self.notify_callbacks({
                    'type': 'update',
                    'data': dict(self.traffic_data),
                    'totals': {'download': total_download, 'upload': total_upload},
                    'timestamp': current_time
                })
                
                self.old_stats = new_stats
                last_time = current_time
                
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(1)
    
    def add_alert(self, message: str):
        """Add a new alert"""
        alert = {
            'timestamp': datetime.now(),
            'message': message,
            'acknowledged': False
        }
        self.alerts.append(alert)
        self.notify_callbacks({'type': 'alert', 'alert': alert})
    
    def get_alerts(self, unacknowledged_only: bool = False) -> List[Dict]:
        """Get alerts"""
        if unacknowledged_only:
            return [alert for alert in self.alerts if not alert['acknowledged']]
        return self.alerts
    
    def acknowledge_alert(self, index: int):
        """Acknowledge an alert"""
        if 0 <= index < len(self.alerts):
            self.alerts[index]['acknowledged'] = True
    
    def start_monitoring(self, interface: str, target_ip: str):
        """Start monitoring bandwidth"""
        if self.monitoring:
            return False
        
        self.current_interface = interface
        self.target_ip = target_ip
        self.monitoring = True
        self.start_time = datetime.now()
        
        # Clear previous data
        with self.data_lock:
            self.traffic_data.clear()
            self.realtime_data.clear()
            self.peak_bandwidth = {'download': 0, 'upload': 0}
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_bandwidth, daemon=True)
        self.monitor_thread.start()
        
        return True
    
    def stop_monitoring(self):
        """Stop monitoring bandwidth"""
        if not self.monitoring:
            return
        
        self.monitoring = False
        end_time = datetime.now()
        duration = end_time - self.start_time
        
        # Save historical data
        timestamp = datetime.now()
        with self.data_lock:
            for ip, data in self.traffic_data.items():
                self.historical_data.append({
                    'timestamp': timestamp,
                    'ip': ip,
                    'download': data['download'] / (1024 * 1024),
                    'upload': data['upload'] / (1024 * 1024),
                    'total': (data['download'] + data['upload']) / (1024 * 1024),
                    'interface': self.current_interface,
                    'duration_seconds': duration.total_seconds(),
                    'pid': data['pid'],
                    'port': data['port'],
                    'protocol': data['protocol'],
                    'process_name': data['process_name']
                })
        
        self.notify_callbacks({'type': 'stopped', 'duration': duration})
        return duration
    
    def export_data(self, filename: str, format_type: str = 'csv'):
        """Export collected data"""
        try:
            if format_type.lower() == 'csv':
                with open(filename, 'w', newline='') as csvfile:
                    fieldnames = ['timestamp', 'ip', 'download_mb', 'upload_mb', 
                                 'total_mb', 'interface', 'duration_seconds',
                                 'pid', 'port', 'protocol', 'process_name']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    
                    writer.writeheader()
                    for record in self.historical_data:
                        writer.writerow({
                            'timestamp': record['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                            'ip': record['ip'],
                            'download_mb': record['download'],
                            'upload_mb': record['upload'],
                            'total_mb': record['total'],
                            'interface': record['interface'],
                            'duration_seconds': record['duration_seconds'],
                            'pid': record.get('pid', ''),
                            'port': record.get('port', ''),
                            'protocol': record.get('protocol', ''),
                            'process_name': record.get('process_name', '')
                        })
            
            elif format_type.lower() == 'json':
                with open(filename, 'w') as jsonfile:
                    json.dump(self.historical_data, jsonfile, default=str, indent=2)
            
            return True
        except Exception as e:
            print(f"Export error: {e}")
            return False
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics"""
        with self.data_lock:
            total_download = sum(data['download'] for data in self.traffic_data.values()) / (1024 * 1024)
            total_upload = sum(data['upload'] for data in self.traffic_data.values()) / (1024 * 1024)
            total_connections = len(self.traffic_data)
            
            # Find top talkers
            top_talkers = sorted(
                self.traffic_data.items(),
                key=lambda x: x[1]['download'] + x[1]['upload'],
                reverse=True
            )[:5]
        
        return {
            'total_download': total_download,
            'total_upload': total_upload,
            'total_bandwidth': total_download + total_upload,
            'total_connections': total_connections,
            'peak_download': self.peak_bandwidth['download'] / (1024 * 1024),
            'peak_upload': self.peak_bandwidth['upload'] / (1024 * 1024),
            'monitoring_duration': datetime.now() - self.start_time if self.start_time else timedelta(0),
            'top_talkers': top_talkers
        }
    
    def cleanup(self):
        """Clean up resources"""
        self.running = False
        self.monitoring = False


class BandwidthMonitorGUI:
    """Graphical User Interface for Bandwidth Monitor"""
    
    def __init__(self, core: BandwidthMonitorCore):
        self.core = core
        self.root = tk.Tk()
        self.setup_gui()
        self.core.register_callback(self.on_data_update)
        self.setup_plots()
        self.animation = None
        self.start_animation()
    
    def setup_gui(self):
        """Setup the main GUI window"""
        self.root.title("Network Bandwidth Monitor Pro")
        self.root.geometry("1400x900")
        self.root.configure(bg='#2c003e')
        
        # Set theme colors
        self.colors = {
            'primary': '#2c003e',
            'secondary': '#4a0072',
            'accent1': '#ff0055',
            'accent2': '#ff4081',
            'text': '#ffffff',
            'text_secondary': '#cccccc',
            'background': '#1a0029',
            'card_bg': '#3c1053'
        }
        
        # Configure styles
        self.setup_styles()
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create main frame
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_detailed_view_tab()
        self.create_graphs_tab()
        self.create_alerts_tab()
        self.create_settings_tab()
        
        # Create status bar
        self.create_status_bar()
    
    def setup_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('Custom.TFrame', background=self.colors['background'])
        style.configure('Custom.TLabelframe', background=self.colors['background'], foreground=self.colors['text'])
        style.configure('Custom.TLabelframe.Label', background=self.colors['background'], foreground=self.colors['accent1'])
        style.configure('Custom.TButton', background=self.colors['accent1'], foreground=self.colors['text'])
        style.configure('Custom.TCheckbutton', background=self.colors['background'], foreground=self.colors['text'])
        
        # Configure notebook style
        style.configure('Custom.TNotebook', background=self.colors['primary'])
        style.configure('Custom.TNotebook.Tab', background=self.colors['secondary'], foreground=self.colors['text'])
        style.map('Custom.TNotebook.Tab', background=[('selected', self.colors['accent1'])])
    
    def create_menu_bar(self):
        """Create the menu bar"""
        menubar = tk.Menu(self.root, bg=self.colors['secondary'], fg=self.colors['text'])
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0, bg=self.colors['secondary'], fg=self.colors['text'])
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Monitoring Session", command=self.new_session)
        file_menu.add_command(label="Export Data", command=self.export_data)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0, bg=self.colors['secondary'], fg=self.colors['text'])
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Refresh", command=self.refresh_view)
        view_menu.add_command(label="Reset Counters", command=self.reset_counters)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0, bg=self.colors['secondary'], fg=self.colors['text'])
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Network Scanner", command=self.open_network_scanner)
        tools_menu.add_command(label="Port Scanner", command=self.open_port_scanner)
        tools_menu.add_command(label="Packet Analyzer", command=self.open_packet_analyzer)
        
        # Settings menu
        settings_menu = tk.Menu(menubar, tearoff=0, bg=self.colors['secondary'], fg=self.colors['text'])
        menubar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(label="Preferences", command=self.open_preferences)
        settings_menu.add_command(label="Alert Settings", command=self.open_alert_settings)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0, bg=self.colors['secondary'], fg=self.colors['text'])
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="User Guide", command=self.show_user_guide)
        help_menu.add_command(label="About", command=self.show_about)
    
    def create_dashboard_tab(self):
        """Create the dashboard tab"""
        dashboard_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(dashboard_frame, text="Dashboard")
        
        # Control panel
        control_frame = ttk.LabelFrame(dashboard_frame, text="Monitoring Controls", style='Custom.TLabelframe')
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Interface selection
        ttk.Label(control_frame, text="Network Interface:", background=self.colors['background'], 
                 foreground=self.colors['text']).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        
        self.interface_var = tk.StringVar()
        interfaces = self.core.get_network_interfaces()
        self.interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var, values=interfaces)
        self.interface_combo.grid(row=0, column=1, padx=5, pady=5)
        if interfaces:
            self.interface_combo.set(interfaces[0])
        
        # IP selection
        ttk.Label(control_frame, text="Target IP:", background=self.colors['background'],
                 foreground=self.colors['text']).grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        
        self.ip_var = tk.StringVar(value="all")
        self.ip_entry = ttk.Entry(control_frame, textvariable=self.ip_var)
        self.ip_entry.grid(row=0, column=3, padx=5, pady=5)
        
        # Control buttons
        self.start_button = ttk.Button(control_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.grid(row=0, column=4, padx=5, pady=5)
        
        self.stop_button = ttk.Button(control_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=5, padx=5, pady=5)
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(dashboard_frame, text="Real-time Statistics", style='Custom.TLabelframe')
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create statistics labels
        self.stats_vars = {}
        stats_grid = [
            ("Total Download:", "total_download", "0.00 MB"),
            ("Total Upload:", "total_upload", "0.00 MB"),
            ("Total Bandwidth:", "total_bandwidth", "0.00 MB"),
            ("Active Connections:", "active_connections", "0"),
            ("Monitoring Duration:", "duration", "00:00:00"),
            ("Peak Download:", "peak_download", "0.00 MB/s"),
            ("Peak Upload:", "peak_upload", "0.00 MB/s")
        ]
        
        for i, (label, key, default) in enumerate(stats_grid):
            ttk.Label(stats_frame, text=label, background=self.colors['background'],
                     foreground=self.colors['text']).grid(row=i//2, column=(i%2)*2, padx=5, pady=2, sticky=tk.W)
            
            self.stats_vars[key] = tk.StringVar(value=default)
            ttk.Label(stats_frame, textvariable=self.stats_vars[key], background=self.colors['background'],
                     foreground=self.colors['accent2'], font=('Arial', 10, 'bold')).grid(
                     row=i//2, column=(i%2)*2+1, padx=5, pady=2, sticky=tk.W)
        
        # Top connections frame
        top_conn_frame = ttk.LabelFrame(dashboard_frame, text="Top Connections", style='Custom.TLabelframe')
        top_conn_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create treeview for top connections
        columns = ('IP', 'Download', 'Upload', 'Total', 'Process')
        self.top_conn_tree = ttk.Treeview(top_conn_frame, columns=columns, show='headings', height=8)
        
        for col in columns:
            self.top_conn_tree.heading(col, text=col)
            self.top_conn_tree.column(col, width=120)
        
        self.top_conn_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_detailed_view_tab(self):
        """Create detailed view tab"""
        detailed_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(detailed_frame, text="Detailed View")
        
        # Create treeview for all connections
        columns = ('IP Address', 'Download (MB)', 'Upload (MB)', 'Total (MB)', 
                  'PID', 'Port', 'Protocol', 'Process Name')
        
        self.detailed_tree = ttk.Treeview(detailed_frame, columns=columns, show='headings', height=20)
        
        # Configure columns
        column_widths = [150, 100, 100, 100, 80, 80, 100, 150]
        for col, width in zip(columns, column_widths):
            self.detailed_tree.heading(col, text=col)
            self.detailed_tree.column(col, width=width)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(detailed_frame, orient=tk.VERTICAL, command=self.detailed_tree.yview)
        self.detailed_tree.configure(yscrollcommand=scrollbar.set)
        
        self.detailed_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=5, pady=5)
    
    def create_graphs_tab(self):
        """Create graphs and charts tab"""
        graphs_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(graphs_frame, text="Graphs & Charts")
        
        # Create matplotlib figure with dark theme
        plt.style.use('dark_background')
        self.fig = Figure(figsize=(12, 8), dpi=100, facecolor=self.colors['background'])
        self.fig.suptitle('Network Bandwidth Usage', color=self.colors['text'])
        
        # Create subplots
        self.ax1 = self.fig.add_subplot(221)  # Real-time bandwidth
        self.ax2 = self.fig.add_subplot(222)  # Protocol distribution
        self.ax3 = self.fig.add_subplot(223)  # Top IPs by bandwidth
        self.ax4 = self.fig.add_subplot(224)  # Historical trends
        
        # Configure plot colors
        for ax in [self.ax1, self.ax2, self.ax3, self.ax4]:
            ax.set_facecolor(self.colors['card_bg'])
            ax.title.set_color(self.colors['text'])
            ax.xaxis.label.set_color(self.colors['text_secondary'])
            ax.yaxis.label.set_color(self.colors['text_secondary'])
            ax.tick_params(colors=self.colors['text_secondary'])
        
        # Create canvas
        self.canvas = FigureCanvasTkAgg(self.fig, graphs_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_alerts_tab(self):
        """Create alerts and notifications tab"""
        alerts_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(alerts_frame, text="Alerts")
        
        # Alerts control frame
        alert_control_frame = ttk.LabelFrame(alerts_frame, text="Alert Controls", style='Custom.TLabelframe')
        alert_control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(alert_control_frame, text="Clear All Alerts", command=self.clear_alerts).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(alert_control_frame, text="Acknowledge All", command=self.acknowledge_all_alerts).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Alerts list
        alerts_list_frame = ttk.LabelFrame(alerts_frame, text="Active Alerts", style='Custom.TLabelframe')
        alerts_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.alerts_text = scrolledtext.ScrolledText(
            alerts_list_frame, 
            wrap=tk.WORD, 
            width=80, 
            height=20,
            bg=self.colors['card_bg'],
            fg=self.colors['text'],
            insertbackground=self.colors['text']
        )
        self.alerts_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.alerts_text.config(state=tk.DISABLED)
    
    def create_settings_tab(self):
        """Create settings tab"""
        settings_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(settings_frame, text="Settings")
        
        # General settings
        general_frame = ttk.LabelFrame(settings_frame, text="General Settings", style='Custom.TLabelframe')
        general_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(general_frame, text="Update Interval (seconds):", background=self.colors['background'],
                 foreground=self.colors['text']).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        
        self.interval_var = tk.StringVar(value="1.0")
        ttk.Entry(general_frame, textvariable=self.interval_var).grid(row=0, column=1, padx=5, pady=5)
        
        # Alert settings
        alert_settings_frame = ttk.LabelFrame(settings_frame, text="Alert Settings", style='Custom.TLabelframe')
        alert_settings_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(alert_settings_frame, text="Bandwidth Threshold (MB/s):", background=self.colors['background'],
                 foreground=self.colors['text']).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        
        self.threshold_var = tk.StringVar(value="100")
        ttk.Entry(alert_settings_frame, textvariable=self.threshold_var).grid(row=0, column=1, padx=5, pady=5)
        
        # Save button
        ttk.Button(settings_frame, text="Save Settings", command=self.save_settings).pack(pady=10)
    
    def create_status_bar(self):
        """Create status bar"""
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def setup_plots(self):
        """Initialize the plots"""
        # Real-time bandwidth plot
        self.ax1.set_title('Real-time Bandwidth Usage')
        self.ax1.set_ylabel('MB/s')
        self.ax1.grid(True, alpha=0.3)
        self.download_line, = self.ax1.plot([], [], label='Download', color='#ff0055')
        self.upload_line, = self.ax1.plot([], [], label='Upload', color='#ff4081')
        self.ax1.legend()
        
        # Protocol distribution plot
        self.ax2.set_title('Protocol Distribution')
        
        # Top IPs plot
        self.ax3.set_title('Top IPs by Bandwidth')
        
        # Historical trends plot
        self.ax4.set_title('Historical Trends')
        self.ax4.set_ylabel('MB')
        self.ax4.grid(True, alpha=0.3)
    
    def start_animation(self):
        """Start the graph animation"""
        def animate(frame):
            if hasattr(self, 'core') and self.core.realtime_data:
                # Update real-time plot
                times = [data['timestamp'] for data in self.core.realtime_data]
                downloads = [data['download'] for data in self.core.realtime_data]
                uploads = [data['upload'] for data in self.core.realtime_data]
                
                if times and downloads and uploads:
                    # Convert timestamps to relative time
                    base_time = times[0]
                    rel_times = [t - base_time for t in times]
                    
                    self.download_line.set_data(rel_times, downloads)
                    self.upload_line.set_data(rel_times, uploads)
                    
                    self.ax1.relim()
                    self.ax1.autoscale_view()
                    
                    # Update other plots periodically
                    if frame % 10 == 0:
                        self.update_protocol_chart()
                        self.update_top_ips_chart()
                        self.update_historical_chart()
            
            return self.download_line, self.upload_line
        
        self.animation = animation.FuncAnimation(
            self.fig, animate, interval=1000, blit=False, cache_frame_data=False
        )
    
    def update_protocol_chart(self):
        """Update protocol distribution chart"""
        self.ax2.clear()
        self.ax2.set_title('Protocol Distribution')
        self.ax2.set_facecolor(self.colors['card_bg'])
        
        # Count protocols (simulated data)
        protocols = ['HTTP', 'HTTPS', 'DNS', 'SSH', 'Other']
        counts = [45, 30, 15, 5, 5]
        
        colors = ['#ff0055', '#ff4081', '#e91e63', '#ad1457', '#880e4f']
        self.ax2.pie(counts, labels=protocols, colors=colors, autopct='%1.1f%%', startangle=90)
    
    def update_top_ips_chart(self):
        """Update top IPs chart"""
        self.ax3.clear()
        self.ax3.set_title('Top IPs by Bandwidth')
        self.ax3.set_facecolor(self.colors['card_bg'])
        
        # Get top IPs (simulated data)
        ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1', '8.8.8.8', '1.1.1.1']
        bandwidth = [120, 85, 60, 45, 30]
        
        colors = ['#ff0055', '#ff4081', '#e91e63', '#ad1457', '#880e4f']
        bars = self.ax3.bar(ips, bandwidth, color=colors)
        
        self.ax3.tick_params(axis='x', rotation=45)
        self.ax3.set_ylabel('MB')
        
        # Add value labels on bars
        for bar, value in zip(bars, bandwidth):
            self.ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1, 
                         f'{value}', ha='center', va='bottom', color=self.colors['text'])
    
    def update_historical_chart(self):
        """Update historical trends chart"""
        self.ax4.clear()
        self.ax4.set_title('Historical Trends')
        self.ax4.set_facecolor(self.colors['card_bg'])
        self.ax4.set_ylabel('MB')
        self.ax4.grid(True, alpha=0.3)
        
        # Simulated historical data
        hours = list(range(24))
        download_trend = [50 + 20 * math.sin(h/3) for h in hours]
        upload_trend = [30 + 10 * math.cos(h/2) for h in hours]
        
        self.ax4.plot(hours, download_trend, label='Download', color='#ff0055', linewidth=2)
        self.ax4.plot(hours, upload_trend, label='Upload', color='#ff4081', linewidth=2)
        self.ax4.legend()
        self.ax4.set_xlabel('Hours')
    
    def on_data_update(self, data):
        """Handle data updates from core"""
        if data['type'] == 'update':
            self.update_dashboard(data)
        elif data['type'] == 'alert':
            self.handle_alert(data['alert'])
    
    def update_dashboard(self, data):
        """Update dashboard with new data"""
        # Update statistics
        summary = self.core.get_summary_stats()
        
        self.stats_vars['total_download'].set(f"{summary['total_download']:.2f} MB")
        self.stats_vars['total_upload'].set(f"{summary['total_upload']:.2f} MB")
        self.stats_vars['total_bandwidth'].set(f"{summary['total_bandwidth']:.2f} MB")
        self.stats_vars['active_connections'].set(str(summary['total_connections']))
        self.stats_vars['duration'].set(str(summary['monitoring_duration']).split('.')[0])
        self.stats_vars['peak_download'].set(f"{summary['peak_download']:.2f} MB/s")
        self.stats_vars['peak_upload'].set(f"{summary['peak_upload']:.2f} MB/s")
        
        # Update top connections
        self.update_top_connections(summary['top_talkers'])
        
        # Update detailed view
        self.update_detailed_view(data['data'])
    
    def update_top_connections(self, top_talkers):
        """Update top connections treeview"""
        # Clear existing items
        for item in self.top_conn_tree.get_children():
            self.top_conn_tree.delete(item)
        
        # Add new items
        for ip, data in top_talkers:
            download_mb = data['download'] / (1024 * 1024)
            upload_mb = data['upload'] / (1024 * 1024)
            total_mb = download_mb + upload_mb
            
            self.top_conn_tree.insert('', tk.END, values=(
                ip, f"{download_mb:.2f}", f"{upload_mb:.2f}", f"{total_mb:.2f}", data.get('process_name', 'Unknown')
            ))
    
    def update_detailed_view(self, traffic_data):
        """Update detailed view treeview"""
        # Clear existing items
        for item in self.detailed_tree.get_children():
            self.detailed_tree.delete(item)
        
        # Add new items
        for ip, data in traffic_data.items():
            download_mb = data['download'] / (1024 * 1024)
            upload_mb = data['upload'] / (1024 * 1024)
            total_mb = download_mb + upload_mb
            
            self.detailed_tree.insert('', tk.END, values=(
                ip, f"{download_mb:.2f}", f"{upload_mb:.2f}", f"{total_mb:.2f}",
                data.get('pid', ''), data.get('port', ''), data.get('protocol', ''),
                data.get('process_name', 'Unknown')
            ))
    
    def handle_alert(self, alert):
        """Handle new alerts"""
        self.alerts_text.config(state=tk.NORMAL)
        
        timestamp = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        self.alerts_text.insert(tk.END, f"[{timestamp}] {alert['message']}\n")
        
        # Scroll to bottom
        self.alerts_text.see(tk.END)
        self.alerts_text.config(state=tk.DISABLED)
        
        # Show notification
        if not alert['acknowledged']:
            messagebox.showwarning("Bandwidth Alert", alert['message'])
    
    def start_monitoring(self):
        """Start monitoring"""
        interface = self.interface_var.get()
        target_ip = self.ip_var.get()
        
        if not interface:
            messagebox.showerror("Error", "Please select a network interface")
            return
        
        if target_ip and target_ip.lower() != 'all' and not self.core.validate_ip(target_ip):
            messagebox.showerror("Error", "Invalid IP address format")
            return
        
        if self.core.start_monitoring(interface, target_ip):
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.status_var.set(f"Monitoring {interface} - Target: {target_ip}")
        else:
            messagebox.showerror("Error", "Failed to start monitoring")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        duration = self.core.stop_monitoring()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_var.set(f"Monitoring stopped - Duration: {duration}")
    
    def new_session(self):
        """Start new monitoring session"""
        if self.core.monitoring:
            self.stop_monitoring()
        # Reset UI elements
        for var in self.stats_vars.values():
            var.set("0.00 MB")
    
    def export_data(self):
        """Export data to file"""
        if not self.core.historical_data:
            messagebox.showwarning("Warning", "No data available to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            format_type = 'csv' if filename.lower().endswith('.csv') else 'json'
            if self.core.export_data(filename, format_type):
                messagebox.showinfo("Success", f"Data exported to {filename}")
            else:
                messagebox.showerror("Error", "Failed to export data")
    
    def refresh_view(self):
        """Refresh the current view"""
        if self.core.monitoring:
            summary = self.core.get_summary_stats()
            self.update_dashboard({'data': dict(self.core.traffic_data)})
    
    def reset_counters(self):
        """Reset all counters"""
        if messagebox.askyesno("Confirm", "Reset all counters?"):
            with self.core.data_lock:
                for data in self.core.traffic_data.values():
                    data['download'] = 0
                    data['upload'] = 0
                    data['download_history'].clear()
                    data['upload_history'].clear()
                    data['timestamps'].clear()
            
            self.core.peak_bandwidth = {'download': 0, 'upload': 0}
            self.refresh_view()
    
    def open_network_scanner(self):
        """Open network scanner tool"""
        messagebox.showinfo("Network Scanner", "Network Scanner tool would open here")
    
    def open_port_scanner(self):
        """Open port scanner tool"""
        messagebox.showinfo("Port Scanner", "Port Scanner tool would open here")
    
    def open_packet_analyzer(self):
        """Open packet analyzer tool"""
        messagebox.showinfo("Packet Analyzer", "Packet Analyzer tool would open here")
    
    def open_preferences(self):
        """Open preferences dialog"""
        messagebox.showinfo("Preferences", "Preferences dialog would open here")
    
    def open_alert_settings(self):
        """Open alert settings dialog"""
        messagebox.showinfo("Alert Settings", "Alert Settings dialog would open here")
    
    def show_user_guide(self):
        """Show user guide"""
        guide_window = tk.Toplevel(self.root)
        guide_window.title("User Guide")
        guide_window.geometry("600x400")
        guide_window.configure(bg=self.colors['background'])
        
        text_area = scrolledtext.ScrolledText(
            guide_window,
            wrap=tk.WORD,
            width=70,
            height=25,
            bg=self.colors['card_bg'],
            fg=self.colors['text']
        )
        text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        guide_text = """
        Network Bandwidth Monitor Pro - User Guide
        
        1. GETTING STARTED
           - Select a network interface from the dropdown
           - Enter target IP or 'all' for all IPs
           - Click 'Start Monitoring' to begin
        
        2. DASHBOARD
           - Real-time statistics and top connections
           - Total bandwidth usage and active connections
           - Monitoring duration and peak rates
        
        3. DETAILED VIEW
           - Comprehensive list of all connections
           - Process information and protocol details
           - Individual bandwidth usage per connection
        
        4. GRAPHS & CHARTS
           - Real-time bandwidth graphs
           - Protocol distribution pie chart
           - Top IPs by bandwidth
           - Historical trends analysis
        
        5. ALERTS
           - Bandwidth threshold alerts
           - System notifications
           - Alert history and management
        
        6. SETTINGS
           - Update interval configuration
           - Alert threshold settings
           - Application preferences
        """
        
        text_area.insert(tk.END, guide_text)
        text_area.config(state=tk.DISABLED)
    
    def show_about(self):
        """Show about dialog"""
        about_text = f"""
        Network Bandwidth Monitor Pro
        
        Version: 2.0.0
        Developed by: Network Tools Team
        
        Features:
        • Real-time bandwidth monitoring
        • Detailed connection analysis
        • Graphical data representation
        • Custom alert system
        • Data export capabilities
        • Multi-interface support
        
        Theme: Red & Purple Dark Theme
        """
        
        messagebox.showinfo("About", about_text)
    
    def clear_alerts(self):
        """Clear all alerts"""
        if messagebox.askyesno("Confirm", "Clear all alerts?"):
            self.core.alerts.clear()
            self.alerts_text.config(state=tk.NORMAL)
            self.alerts_text.delete(1.0, tk.END)
            self.alerts_text.config(state=tk.DISABLED)
    
    def acknowledge_all_alerts(self):
        """Acknowledge all alerts"""
        for alert in self.core.alerts:
            alert['acknowledged'] = True
        
        self.alerts_text.config(state=tk.NORMAL)
        self.alerts_text.delete(1.0, tk.END)
        
        for alert in self.core.alerts:
            timestamp = alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            status = "ACKNOWLEDGED" if alert['acknowledged'] else "PENDING"
            self.alerts_text.insert(tk.END, f"[{timestamp}] [{status}] {alert['message']}\n")
        
        self.alerts_text.config(state=tk.DISABLED)
    
    def save_settings(self):
        """Save application settings"""
        try:
            self.core.update_interval = float(self.interval_var.get())
            self.core.alert_threshold = float(self.threshold_var.get()) * 1024 * 1024
            messagebox.showinfo("Success", "Settings saved successfully")
        except ValueError:
            messagebox.showerror("Error", "Invalid values in settings")
    
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()


class BandwidthMonitorCLI:
    """Command Line Interface for Bandwidth Monitor"""
    
    def __init__(self, core: BandwidthMonitorCore):
        self.core = core
        self.monitor_thread = None
        self.display_thread = None
    
    def clear_screen(self):
        """Clear the terminal screen"""
        if platform.system() == "Windows":
            os.system('cls')
        else:
            os.system('clear')
    
    def print_banner(self):
        """Print the application banner"""
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║           NETWORK BANDWIDTH MONITOR PRO (CLI)               ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║ Interface: {self.core.current_interface:<15} Target IP: {self.core.target_ip:<15} ║")
        print(f"║ Status: {'ACTIVE' if self.core.monitoring else 'INACTIVE':<10} "
              f"Start Time: {self.core.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.core.start_time else 'N/A':<20} ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print()
    
    def display_stats(self):
        """Display statistics in the terminal"""
        while self.core.monitoring and self.core.running:
            self.clear_screen()
            self.print_banner()
            self.print_current_stats()
            time.sleep(2)
    
    def print_current_stats(self):
        """Print current bandwidth statistics"""
        with self.core.data_lock:
            if not self.core.traffic_data:
                print("No traffic data available yet...")
                return
            
            # Sort by total bandwidth
            sorted_data = sorted(
                self.core.traffic_data.items(),
                key=lambda x: x[1]['download'] + x[1]['upload'],
                reverse=True
            )
            
            print("┌───────────────────┬─────────────┬─────────────┬─────────────┬─────────────────┐")
            print("│ IP Address        │ Download    │ Upload      │ Total       │ Process         │")
            print("├───────────────────┼─────────────┼─────────────┼─────────────┼─────────────────┤")
            
            for ip, data in sorted_data[:10]:  # Show top 10
                download_mb = data['download'] / (1024 * 1024)
                upload_mb = data['upload'] / (1024 * 1024)
                total_mb = download_mb + upload_mb
                process_name = data.get('process_name', 'Unknown')[:15]
                
                print(f"│ {ip:<17} │ {download_mb:>9.2f} MB │ {upload_mb:>9.2f} MB │ {total_mb:>9.2f} MB │ {process_name:<15} │")
            
            print("└───────────────────┴─────────────┴─────────────┴─────────────┴─────────────────┘")
            
            # Print summary
            summary = self.core.get_summary_stats()
            print(f"\nSummary:")
            print(f"  Total Download: {summary['total_download']:.2f} MB")
            print(f"  Total Upload: {summary['total_upload']:.2f} MB")
            print(f"  Active Connections: {summary['total_connections']}")
            print(f"  Monitoring Duration: {summary['monitoring_duration']}")
            print(f"  Peak Download: {summary['peak_download']:.2f} MB/s")
            print(f"  Peak Upload: {summary['peak_upload']:.2f} MB/s")
            
            # Print alerts
            unacknowledged_alerts = self.core.get_alerts(unacknowledged_only=True)
            if unacknowledged_alerts:
                print(f"\nAlerts ({len(unacknowledged_alerts)} unacknowledged):")
                for alert in unacknowledged_alerts[-3:]:  # Show last 3 alerts
                    print(f"  ! {alert['message']}")
            
            # Print commands
            print("\nCommands: [s]top monitoring, [e]xport data, [r]efresh, [q]uit")
    
    def handle_user_input(self):
        """Handle user input during monitoring"""
        while self.core.monitoring and self.core.running:
            try:
                if sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                    cmd = sys.stdin.readline().strip().lower()
                    
                    if cmd == 's':
                        self.core.stop_monitoring()
                    elif cmd == 'e':
                        self.export_data_cli()
                    elif cmd == 'r':
                        pass  # Refresh happens automatically
                    elif cmd == 'q':
                        self.core.running = False
                        self.core.monitoring = False
            except:
                pass
            
            time.sleep(0.1)
    
    def export_data_cli(self):
        """Export data from CLI"""
        if not self.core.historical_data:
            print("No data available to export!")
            time.sleep(2)
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"bandwidth_data_{timestamp}.csv"
        
        if self.core.export_data(filename, 'csv'):
            print(f"Data exported to {filename}")
        else:
            print("Error exporting data!")
        
        time.sleep(2)
    
    def interactive_setup(self):
        """Interactive setup for monitoring"""
        self.clear_screen()
        print("╔══════════════════════════════════════════════════╗")
        print("║           NETWORK BANDWIDTH MONITOR PRO (CLI)   ║")
        print("╚══════════════════════════════════════════════════╝")
        print("\nInteractive Setup\n")
        
        # Select network interface
        interfaces = self.core.get_network_interfaces()
        if not interfaces:
            print("No network interfaces found!")
            return
        
        print("Available network interfaces:")
        for i, interface in enumerate(interfaces, 1):
            print(f"{i}. {interface}")
        
        while True:
            try:
                choice = input("\nSelect interface (number): ")
                if not choice:
                    continue
                choice = int(choice)
                if 1 <= choice <= len(interfaces):
                    selected_interface = interfaces[choice - 1]
                    break
                print("Invalid selection!")
            except ValueError:
                print("Please enter a number!")
        
        # Enter target IP
        print("\nEnter target IP address to monitor (or 'all' for all IPs):")
        while True:
            ip = input("IP: ").strip()
            if not ip:
                continue
            if ip.lower() == 'all' or self.core.validate_ip(ip):
                break
            print("Invalid IP address format!")
        
        # Start monitoring
        self.start_monitoring_cli(selected_interface, ip)
    
    def start_monitoring_cli(self, interface: str, target_ip: str):
        """Start monitoring from CLI"""
        if not self.core.start_monitoring(interface, target_ip):
            print("Failed to start monitoring!")
            return
        
        # Start display thread
        self.display_thread = threading.Thread(target=self.display_stats, daemon=True)
        self.display_thread.start()
        
        # Handle user input
        self.handle_user_input()
    
    def run_from_args(self, args):
        """Run the monitor with command-line arguments"""
        if not args.interface:
            print("Available network interfaces:")
            interfaces = self.core.get_network_interfaces()
            for i, interface in enumerate(interfaces, 1):
                print(f"{i}. {interface}")
            return
        
        if not args.ip:
            print("Please specify an IP address to monitor or 'all' for all IPs")
            return
        
        if not self.core.validate_ip(args.ip) and args.ip.lower() != 'all':
            print("Invalid IP address format!")
            return
        
        self.start_monitoring_cli(args.interface, args.ip)


class NetworkTools:
    """Additional network tools and utilities"""
    
    @staticmethod
    def network_scanner(subnet: str = "192.168.1.0/24") -> List[Dict]:
        """Simple network scanner"""
        # This is a simplified version - in real implementation, use scapy or similar
        print(f"Scanning network: {subnet}")
        return [
            {"ip": "192.168.1.1", "hostname": "router", "status": "online"},
            {"ip": "192.168.1.100", "hostname": "pc-1", "status": "online"},
            {"ip": "192.168.1.101", "hostname": "pc-2", "status": "online"},
        ]
    
    @staticmethod
    def port_scanner(ip: str, ports: List[int] = None) -> List[Dict]:
        """Simple port scanner"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995]
        
        print(f"Scanning ports on: {ip}")
        results = []
        for port in ports:
            # Simulate port scanning
            is_open = np.random.random() > 0.8  # 20% chance port is "open"
            if is_open:
                results.append({"port": port, "status": "open", "service": "unknown"})
        
        return results
    
    @staticmethod
    def speed_test() -> Dict[str, float]:
        """Network speed test"""
        print("Running speed test...")
        time.sleep(2)  # Simulate test
        
        return {
            "download_speed": 85.5,  # Mbps
            "upload_speed": 22.3,    # Mbps
            "ping": 15,              # ms
            "jitter": 2.1            # ms
        }


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Network Bandwidth Monitor Pro")
    parser.add_argument('-i', '--interface', help="Network interface to monitor")
    parser.add_argument('-ip', '--ip', help="IP address to monitor (or 'all' for all IPs)")
    parser.add_argument('--gui', action='store_true', help="Launch GUI interface")
    parser.add_argument('--cli', action='store_true', help="Launch CLI interface")
    
    args = parser.parse_args()
    
    # Initialize core
    core = BandwidthMonitorCore()
    
    try:
        if args.gui or (not args.cli and not args.interface and not args.ip):
            # Launch GUI
            print("Launching Network Bandwidth Monitor Pro GUI...")
            gui = BandwidthMonitorGUI(core)
            gui.run()
        else:
            # Launch CLI
            cli = BandwidthMonitorCLI(core)
            if args.interface or args.ip:
                cli.run_from_args(args)
            else:
                cli.interactive_setup()
    
    except KeyboardInterrupt:
        print("\n\nApplication stopped by user.")
    except Exception as e:
        print(f"\n\nUnexpected error: {e}")
    finally:
        core.cleanup()


if __name__ == "__main__":
    main()