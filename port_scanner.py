"""
Advanced Port Scanner with Modern GUI & CLI Engine
A comprehensive tool to scan ports, identify services, measure latency, grab banners, and export results.
"""

import os
import sys
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue
import time
from datetime import datetime
import json
import csv
import re
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Expanded common port to service mapping
PORT_SERVICES = {
    20: "FTP Data",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "MS RPC",
    137: "NetBIOS Name",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    179: "BGP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD/Printer",
    520: "RIP",
    521: "RIPng",
    543: "Kerberos Login",
    544: "Kerberos Shell",
    546: "DHCPv6 Client",
    547: "DHCPv6 Server",
    554: "RTSP",
    587: "SMTP Submission",
    631: "IPP/CUPS",
    636: "LDAPS",
    873: "rsync",
    902: "VMware Server",
    989: "FTPS Data",
    990: "FTPS Control",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1194: "OpenVPN",
    1433: "MS SQL Server",
    1434: "MS SQL Monitor",
    1521: "Oracle DB",
    1701: "L2TP",
    1723: "PPTP",
    1812: "RADIUS Auth",
    1813: "RADIUS Accounting",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel SSL",
    2086: "WHM",
    2087: "WHM SSL",
    2181: "Zookeeper",
    2222: "SSH Alt",
    2375: "Docker",
    2376: "Docker SSL",
    3000: "Node.js/Grafana",
    3128: "Squid Proxy",
    3306: "MySQL",
    3389: "RDP",
    3690: "SVN",
    4000: "ICQ",
    4443: "Pharos",
    4444: "Metasploit",
    5000: "Flask/UPnP",
    5001: "Synology",
    5060: "SIP",
    5061: "SIP TLS",
    5432: "PostgreSQL",
    5631: "pcAnywhere",
    5672: "RabbitMQ",
    5900: "VNC",
    5901: "VNC-1",
    5984: "CouchDB",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    6000: "X11",
    6379: "Redis",
    6443: "Kubernetes API",
    6666: "IRC Alt",
    6667: "IRC",
    7001: "WebLogic",
    7002: "WebLogic SSL",
    7070: "RealServer",
    7077: "Spark Master",
    8000: "HTTP Alt",
    8008: "HTTP Alt",
    8080: "HTTP Proxy",
    8081: "HTTP Proxy Alt",
    8443: "HTTPS Alt",
    8888: "HTTP Alt",
    9000: "PHP-FPM/SonarQube",
    9090: "Prometheus",
    9092: "Kafka",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    9418: "Git",
    9999: "Urchin",
    10000: "Webmin",
    10050: "Zabbix Agent",
    10051: "Zabbix Server",
    11211: "Memcached",
    15672: "RabbitMQ Mgmt",
    27017: "MongoDB",
    27018: "MongoDB Shard",
    27019: "MongoDB Config",
    28017: "MongoDB Web",
    50000: "Jenkins",
    50070: "Hadoop HDFS",
    50075: "Hadoop DataNode",
    60000: "HBase Master",
    60010: "HBase Master Web",
    60020: "HBase RegionServer",
    60030: "HBase RS Web"
}


def parse_ports(port_input: str) -> list[int]:
    """
    Parse flexible port string specifications into a sorted list of unique port integers.
    Supports formats like: '80', '1-1024', '22, 80, 443', '80, 443, 8000-8080'.
    """
    ports = set()
    parts = [p.strip() for p in port_input.split(",") if p.strip()]
    if not parts:
        raise ValueError("Port list cannot be empty.")
    
    for part in parts:
        if "-" in part:
            sub = part.split("-")
            if len(sub) != 2:
                raise ValueError(f"Invalid port range format: '{part}'")
            start, end = int(sub[0]), int(sub[1])
            if start > end:
                raise ValueError(f"Start port ({start}) cannot be greater than end port ({end})")
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError(f"Ports must be between 1 and 65535. Range '{part}' is out of bounds.")
            ports.update(range(start, end + 1))
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                raise ValueError(f"Port {p} is out of valid range (1-65535).")
            ports.add(p)
            
    return sorted(list(ports))


def resolve_target(target: str) -> tuple[str, str]:
    """
    Resolve IP or hostname. Returns (ip_address, resolved_name).
    """
    target = target.strip()
    if not target:
        raise ValueError("Target host/IP cannot be empty.")
    try:
        ip = socket.gethostbyname(target)
        return ip, target
    except socket.gaierror:
        raise ValueError(f"Could not resolve host '{target}'")


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    """
    Attempt to grab service banner from an open port.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Send HTTP request probe for common HTTP ports
        if port in (80, 8080, 8000, 8081, 8888, 3000, 5000):
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nUser-Agent: PortScanner/2.0\r\n\r\n")
        elif port == 443 or port == 8443:
            sock.close()
            return "TLS/SSL Encrypted Endpoint"
        else:
            # Send generic newline probe to trigger service greeting
            sock.sendall(b"\r\n")
            
        banner_bytes = sock.recv(1024)
        sock.close()
        
        banner = banner_bytes.decode('utf-8', errors='ignore').strip()
        lines = [line.strip() for line in banner.splitlines() if line.strip()]
        if lines:
            first_line = lines[0]
            for l in lines:
                if l.lower().startswith("server:"):
                    return l
            return first_line[:80]
    except Exception:
        pass
    return ""


def get_service_info(port: int) -> tuple[str, str]:
    """Get standard service name and description for a port"""
    if port in PORT_SERVICES:
        service = PORT_SERVICES[port]
        return service, f"Standard {service} service"
    
    try:
        service = socket.getservbyport(port)
        return service.upper(), f"Known {service} service"
    except OSError:
        return "UNKNOWN", "Unregistered port service"


def scan_single_port(ip: str, port: int, timeout: float, do_banner: bool = False) -> dict | None:
    """
    Scan a single TCP port and return result dict if open.
    """
    try:
        start_t = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        res = sock.connect_ex((ip, port))
        end_t = time.perf_counter()
        sock.close()
        
        if res == 0:
            latency_ms = (end_t - start_t) * 1000.0
            service, desc = get_service_info(port)
            banner = ""
            if do_banner:
                banner = grab_banner(ip, port, timeout=min(timeout, 1.5))
            
            return {
                "port": port,
                "status": "Open",
                "latency_ms": round(latency_ms, 1),
                "service": service,
                "description": desc,
                "banner": banner
            }
    except Exception:
        pass
    return None


class ModernButton(tk.Canvas):
    """Custom modern rounded button with smooth hover animation effects"""
    def __init__(self, parent, text, command=None, width=120, height=40, 
                 bg_color="#6366f1", hover_color="#4f46e5", text_color="white", **kwargs):
        super().__init__(parent, width=width, height=height, 
                        highlightthickness=0, bg=parent.cget("bg"), cursor="hand2", **kwargs)
        
        self.command = command
        self.bg_color = bg_color
        self.hover_color = hover_color
        self.text_color = text_color
        self.current_color = bg_color
        self.text = text
        self.width = width
        self.height = height
        self.enabled = True
        
        self.draw_button()
        
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.bind("<Button-1>", self.on_click)
    
    def draw_button(self):
        self.delete("all")
        radius = 8
        self.create_arc(0, 0, radius*2, radius*2, start=90, extent=90, 
                       fill=self.current_color, outline=self.current_color)
        self.create_arc(self.width-radius*2, 0, self.width, radius*2, start=0, extent=90,
                       fill=self.current_color, outline=self.current_color)
        self.create_arc(0, self.height-radius*2, radius*2, self.height, start=180, extent=90,
                       fill=self.current_color, outline=self.current_color)
        self.create_arc(self.width-radius*2, self.height-radius*2, self.width, self.height, 
                       start=270, extent=90, fill=self.current_color, outline=self.current_color)
        self.create_rectangle(radius, 0, self.width-radius, self.height, 
                             fill=self.current_color, outline=self.current_color)
        self.create_rectangle(0, radius, self.width, self.height-radius, 
                             fill=self.current_color, outline=self.current_color)
        
        self.create_text(self.width//2, self.height//2, text=self.text,
                        fill=self.text_color, font=("Segoe UI", 10, "bold"))
    
    def on_enter(self, event):
        if self.enabled:
            self.current_color = self.hover_color
            self.draw_button()
    
    def on_leave(self, event):
        if self.enabled:
            self.current_color = self.bg_color
            self.draw_button()
    
    def on_click(self, event):
        if self.enabled and self.command:
            self.command()
    
    def set_enabled(self, enabled):
        self.enabled = enabled
        if not enabled:
            self.current_color = "#4b5563"
            self.config(cursor="")
        else:
            self.current_color = self.bg_color
            self.config(cursor="hand2")
        self.draw_button()


class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 Advanced Port Scanner 2.0")
        self.root.geometry("1050x750")
        self.root.minsize(920, 650)
        
        # Sleek dark theme colors
        self.colors = {
            "bg_dark": "#0f172a",
            "bg_card": "#1e293b",
            "bg_input": "#334155",
            "accent": "#6366f1",
            "accent_hover": "#4f46e5",
            "success": "#10b981",
            "warning": "#f59e0b",
            "error": "#ef4444",
            "text_primary": "#f8fafc",
            "text_secondary": "#94a3b8",
            "border": "#475569"
        }
        
        self.root.configure(bg=self.colors["bg_dark"])
        self.setup_styles()
        
        # State variables
        self.scanning = False
        self.scan_results = []
        self.result_queue = queue.Queue()
        self.total_ports = 0
        self.scanned_ports = 0
        self.target_ip = ""
        self.target_host = ""
        
        self.create_ui()
        self.process_results()
    
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        
        style.configure("Custom.Treeview",
                       background=self.colors["bg_card"],
                       foreground=self.colors["text_primary"],
                       rowheight=35,
                       fieldbackground=self.colors["bg_card"],
                       borderwidth=0)
        style.configure("Custom.Treeview.Heading",
                       background=self.colors["bg_input"],
                       foreground=self.colors["text_primary"],
                       borderwidth=0,
                       font=("Segoe UI", 10, "bold"))
        style.map("Custom.Treeview",
                 background=[("selected", self.colors["accent"])],
                 foreground=[("selected", self.colors["text_primary"])])
        
        style.configure("Custom.Horizontal.TProgressbar",
                       background=self.colors["accent"],
                       troughcolor=self.colors["bg_input"],
                       borderwidth=0,
                       lightcolor=self.colors["accent"],
                       darkcolor=self.colors["accent"])
        
        style.configure("Dark.TCheckbutton",
                        background=self.colors["bg_card"],
                        foreground=self.colors["text_primary"],
                        font=("Segoe UI", 10))
        style.map("Dark.TCheckbutton",
                  background=[("active", self.colors["bg_card"])],
                  foreground=[("active", self.colors["accent"])])

    def create_ui(self):
        main_container = tk.Frame(self.root, bg=self.colors["bg_dark"])
        main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        self.create_header(main_container)
        self.create_control_panel(main_container)
        self.create_progress_section(main_container)
        self.create_results_section(main_container)
        self.create_status_bar(main_container)
    
    def create_header(self, parent):
        header_frame = tk.Frame(parent, bg=self.colors["bg_dark"])
        header_frame.pack(fill=tk.X, pady=(0, 15))
        
        title_label = tk.Label(header_frame, 
                               text="🔍 Advanced Port Scanner 2.0",
                               font=("Segoe UI", 22, "bold"),
                               fg=self.colors["text_primary"],
                               bg=self.colors["bg_dark"])
        title_label.pack(side=tk.LEFT)
        
        subtitle_label = tk.Label(header_frame,
                                 text="Multi-threaded network reconnaissance & banner grabber",
                                 font=("Segoe UI", 11),
                                 fg=self.colors["text_secondary"],
                                 bg=self.colors["bg_dark"])
        subtitle_label.pack(side=tk.LEFT, padx=(15, 0), pady=(6, 0))

    def create_control_panel(self, parent):
        card = tk.Frame(parent, bg=self.colors["bg_card"], padx=20, pady=18)
        card.pack(fill=tk.X, pady=(0, 15))
        
        input_frame = tk.Frame(card, bg=self.colors["bg_card"])
        input_frame.pack(fill=tk.X)
        
        # Target IP / Hostname input
        target_container = tk.Frame(input_frame, bg=self.colors["bg_card"])
        target_container.pack(side=tk.LEFT, padx=(0, 15))
        
        target_label = tk.Label(target_container, text="Target IP / Hostname",
                             font=("Segoe UI", 10),
                             fg=self.colors["text_secondary"],
                             bg=self.colors["bg_card"])
        target_label.pack(anchor=tk.W)
        
        self.target_entry = tk.Entry(target_container, width=22,
                                  font=("Segoe UI", 11),
                                  bg=self.colors["bg_input"],
                                  fg=self.colors["text_primary"],
                                  insertbackground=self.colors["text_primary"],
                                  relief=tk.FLAT,
                                  highlightthickness=2,
                                  highlightbackground=self.colors["border"],
                                  highlightcolor=self.colors["accent"])
        self.target_entry.pack(pady=(5, 0), ipady=6)
        self.target_entry.insert(0, "127.0.0.1")
        
        # Ports input
        port_container = tk.Frame(input_frame, bg=self.colors["bg_card"])
        port_container.pack(side=tk.LEFT, padx=(0, 15))
        
        port_label = tk.Label(port_container, text="Ports (Range or List)",
                              font=("Segoe UI", 10),
                              fg=self.colors["text_secondary"],
                              bg=self.colors["bg_card"])
        port_label.pack(anchor=tk.W)
        
        self.ports_entry = tk.Entry(port_container, width=22,
                                   font=("Segoe UI", 11),
                                   bg=self.colors["bg_input"],
                                   fg=self.colors["text_primary"],
                                   insertbackground=self.colors["text_primary"],
                                   relief=tk.FLAT,
                                   highlightthickness=2,
                                   highlightbackground=self.colors["border"],
                                   highlightcolor=self.colors["accent"])
        self.ports_entry.pack(pady=(5, 0), ipady=6)
        self.ports_entry.insert(0, "1-1024")
        
        # Timeout input
        timeout_container = tk.Frame(input_frame, bg=self.colors["bg_card"])
        timeout_container.pack(side=tk.LEFT, padx=(0, 15))
        
        timeout_label = tk.Label(timeout_container, text="Timeout (sec)",
                                 font=("Segoe UI", 10),
                                 fg=self.colors["text_secondary"],
                                 bg=self.colors["bg_card"])
        timeout_label.pack(anchor=tk.W)
        
        self.timeout_entry = tk.Entry(timeout_container, width=8,
                                      font=("Segoe UI", 11),
                                      bg=self.colors["bg_input"],
                                      fg=self.colors["text_primary"],
                                      insertbackground=self.colors["text_primary"],
                                      relief=tk.FLAT,
                                      highlightthickness=2,
                                      highlightbackground=self.colors["border"],
                                      highlightcolor=self.colors["accent"])
        self.timeout_entry.pack(pady=(5, 0), ipady=6)
        self.timeout_entry.insert(0, "0.5")
        
        # Threads input
        threads_container = tk.Frame(input_frame, bg=self.colors["bg_card"])
        threads_container.pack(side=tk.LEFT, padx=(0, 15))
        
        threads_label = tk.Label(threads_container, text="Threads",
                                 font=("Segoe UI", 10),
                                 fg=self.colors["text_secondary"],
                                 bg=self.colors["bg_card"])
        threads_label.pack(anchor=tk.W)
        
        self.threads_entry = tk.Entry(threads_container, width=8,
                                       font=("Segoe UI", 11),
                                       bg=self.colors["bg_input"],
                                       fg=self.colors["text_primary"],
                                       insertbackground=self.colors["text_primary"],
                                       relief=tk.FLAT,
                                       highlightthickness=2,
                                       highlightbackground=self.colors["border"],
                                       highlightcolor=self.colors["accent"])
        self.threads_entry.pack(pady=(5, 0), ipady=6)
        self.threads_entry.insert(0, "100")
        
        # Action Buttons
        button_frame = tk.Frame(input_frame, bg=self.colors["bg_card"])
        button_frame.pack(side=tk.RIGHT)
        
        self.scan_button = ModernButton(button_frame, "🚀 Start Scan",
                                        command=self.start_scan,
                                        width=120, height=38,
                                        bg_color=self.colors["accent"],
                                        hover_color=self.colors["accent_hover"])
        self.scan_button.pack(side=tk.LEFT, padx=(0, 8), pady=(15, 0))
        
        self.stop_button = ModernButton(button_frame, "⏹ Stop",
                                        command=self.stop_scan,
                                        width=90, height=38,
                                        bg_color=self.colors["error"],
                                        hover_color="#dc2626")
        self.stop_button.pack(side=tk.LEFT, padx=(0, 8), pady=(15, 0))
        self.stop_button.set_enabled(False)
        
        self.export_button = ModernButton(button_frame, "📄 Export",
                                          command=self.export_results,
                                          width=90, height=38,
                                          bg_color=self.colors["success"],
                                          hover_color="#059669")
        self.export_button.pack(side=tk.LEFT, pady=(15, 0))
        
        # Options row (Presets + Banner check)
        options_frame = tk.Frame(card, bg=self.colors["bg_card"])
        options_frame.pack(fill=tk.X, pady=(15, 0))
        
        quick_label = tk.Label(options_frame, text="Presets:",
                               font=("Segoe UI", 10, "bold"),
                               fg=self.colors["text_secondary"],
                               bg=self.colors["bg_card"])
        quick_label.pack(side=tk.LEFT)
        
        presets = [
            ("Common (1-1024)", "1-1024"),
            ("Extended (1-10000)", "1-10000"),
            ("Full (1-65535)", "1-65535"),
            ("Web Ports", "80, 443, 8080, 8443, 3000, 5000, 8000"),
            ("Database", "3306, 5432, 27017, 6379, 1433, 1521")
        ]
        
        for text, val in presets:
            btn = tk.Button(options_frame, text=text,
                           font=("Segoe UI", 8, "bold"),
                           bg=self.colors["bg_input"],
                           fg=self.colors["text_primary"],
                           activebackground=self.colors["accent"],
                           activeforeground=self.colors["text_primary"],
                           relief=tk.FLAT,
                           padx=8, pady=3,
                           cursor="hand2",
                           command=lambda v=val: self.set_port_preset(v))
            btn.pack(side=tk.LEFT, padx=(8, 0))
            
        # Banner grabbing checkbox
        self.banner_var = tk.BooleanVar(value=True)
        self.banner_cb = ttk.Checkbutton(options_frame, text="Grab Service Banners",
                                         variable=self.banner_var,
                                         style="Dark.TCheckbutton")
        self.banner_cb.pack(side=tk.RIGHT)

    def set_port_preset(self, preset_value):
        self.ports_entry.delete(0, tk.END)
        self.ports_entry.insert(0, preset_value)

    def create_progress_section(self, parent):
        progress_frame = tk.Frame(parent, bg=self.colors["bg_card"], padx=20, pady=12)
        progress_frame.pack(fill=tk.X, pady=(0, 15))
        
        info_frame = tk.Frame(progress_frame, bg=self.colors["bg_card"])
        info_frame.pack(fill=tk.X)
        
        self.progress_label = tk.Label(info_frame, text="Ready to scan",
                                       font=("Segoe UI", 10),
                                       fg=self.colors["text_secondary"],
                                       bg=self.colors["bg_card"])
        self.progress_label.pack(side=tk.LEFT)
        
        self.progress_percent = tk.Label(info_frame, text="0%",
                                         font=("Segoe UI", 10, "bold"),
                                         fg=self.colors["accent"],
                                         bg=self.colors["bg_card"])
        self.progress_percent.pack(side=tk.RIGHT)
        
        self.progress_bar = ttk.Progressbar(progress_frame, 
                                            style="Custom.Horizontal.TProgressbar",
                                            mode="determinate")
        self.progress_bar.pack(fill=tk.X, pady=(8, 0))

    def create_results_section(self, parent):
        results_card = tk.Frame(parent, bg=self.colors["bg_card"])
        results_card.pack(fill=tk.BOTH, expand=True)
        
        # Results header & search bar
        header_frame = tk.Frame(results_card, bg=self.colors["bg_card"], padx=20, pady=12)
        header_frame.pack(fill=tk.X)
        
        results_title = tk.Label(header_frame, text="📊 Scan Results",
                                font=("Segoe UI", 13, "bold"),
                                fg=self.colors["text_primary"],
                                bg=self.colors["bg_card"])
        results_title.pack(side=tk.LEFT)
        
        self.results_count = tk.Label(header_frame, text="0 open ports found",
                                     font=("Segoe UI", 10),
                                     fg=self.colors["text_secondary"],
                                     bg=self.colors["bg_card"])
        self.results_count.pack(side=tk.LEFT, padx=(15, 0))
        
        # Search Entry box
        search_container = tk.Frame(header_frame, bg=self.colors["bg_card"])
        search_container.pack(side=tk.RIGHT)
        
        search_label = tk.Label(search_container, text="🔍 Filter:",
                                font=("Segoe UI", 10),
                                fg=self.colors["text_secondary"],
                                bg=self.colors["bg_card"])
        search_label.pack(side=tk.LEFT, padx=(0, 5))
        
        self.search_entry = tk.Entry(search_container, width=20,
                                     font=("Segoe UI", 10),
                                     bg=self.colors["bg_input"],
                                     fg=self.colors["text_primary"],
                                     insertbackground=self.colors["text_primary"],
                                     relief=tk.FLAT,
                                     highlightthickness=1,
                                     highlightbackground=self.colors["border"],
                                     highlightcolor=self.colors["accent"])
        self.search_entry.pack(side=tk.LEFT, ipady=3)
        self.search_entry.bind("<KeyRelease>", self.filter_results)
        
        # Treeview frame
        tree_frame = tk.Frame(results_card, bg=self.colors["bg_card"], padx=20)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        columns = ("port", "status", "latency", "service", "banner")
        self.results_tree = ttk.Treeview(tree_frame, columns=columns, 
                                         show="headings", style="Custom.Treeview")
        
        self.results_tree.heading("port", text="Port", command=lambda: self.sort_tree("port", False))
        self.results_tree.heading("status", text="Status")
        self.results_tree.heading("latency", text="Latency (ms)", command=lambda: self.sort_tree("latency", False))
        self.results_tree.heading("service", text="Service")
        self.results_tree.heading("banner", text="Banner / Description")
        
        self.results_tree.column("port", width=80, anchor=tk.CENTER)
        self.results_tree.column("status", width=90, anchor=tk.CENTER)
        self.results_tree.column("latency", width=110, anchor=tk.CENTER)
        self.results_tree.column("service", width=150, anchor=tk.W)
        self.results_tree.column("banner", width=450, anchor=tk.W)
        
        # Tag configuration for colored badges
        self.results_tree.tag_configure("open_row", foreground=self.colors["success"])
        
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, 
                                  command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Right-click context menu
        self.context_menu = tk.Menu(self.root, tearoff=0, bg=self.colors["bg_card"], fg=self.colors["text_primary"])
        self.context_menu.add_command(label="Copy Target:Port", command=self.copy_target_port)
        self.context_menu.add_command(label="Copy Service Info", command=self.copy_service_info)
        self.context_menu.add_command(label="Copy Banner", command=self.copy_banner_info)
        self.results_tree.bind("<Button-3>", self.show_context_menu)

    def show_context_menu(self, event):
        item = self.results_tree.identify_row(event.y)
        if item:
            self.results_tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def copy_target_port(self):
        sel = self.results_tree.selection()
        if sel:
            vals = self.results_tree.item(sel[0], "values")
            port = vals[0]
            host = self.target_host or self.target_ip or "127.0.0.1"
            self.root.clipboard_clear()
            self.root.clipboard_append(f"{host}:{port}")

    def copy_service_info(self):
        sel = self.results_tree.selection()
        if sel:
            vals = self.results_tree.item(sel[0], "values")
            self.root.clipboard_clear()
            self.root.clipboard_append(f"Port {vals[0]} ({vals[3]})")

    def copy_banner_info(self):
        sel = self.results_tree.selection()
        if sel:
            vals = self.results_tree.item(sel[0], "values")
            self.root.clipboard_clear()
            self.root.clipboard_append(vals[4])

    def sort_tree(self, col, reverse):
        l = [(self.results_tree.set(k, col), k) for k in self.results_tree.get_children('')]
        try:
            l.sort(key=lambda t: float(t[0]), reverse=reverse)
        except ValueError:
            l.sort(reverse=reverse)

        for index, (val, k) in enumerate(l):
            self.results_tree.move(k, '', index)

        self.results_tree.heading(col, command=lambda: self.sort_tree(col, not reverse))

    def filter_results(self, event=None):
        query = self.search_entry.get().strip().lower()
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
            
        for res in self.scan_results:
            port = str(res["port"])
            service = str(res["service"]).lower()
            banner = str(res["banner"] or res["description"]).lower()
            if not query or query in port or query in service or query in banner:
                banner_text = res["banner"] if res["banner"] else res["description"]
                self.results_tree.insert("", tk.END, values=(
                    res["port"], res["status"], f"{res['latency_ms']} ms", res["service"], banner_text
                ), tags=("open_row",))

    def create_status_bar(self, parent):
        status_frame = tk.Frame(parent, bg=self.colors["bg_dark"])
        status_frame.pack(fill=tk.X, pady=(8, 0))
        
        self.status_label = tk.Label(status_frame, 
                                    text="💡 Tip: Right-click any row to copy Target:Port or Banner details",
                                    font=("Segoe UI", 9),
                                    fg=self.colors["text_secondary"],
                                    bg=self.colors["bg_dark"])
        self.status_label.pack(side=tk.LEFT)
        
        self.time_label = tk.Label(status_frame, text="",
                                  font=("Segoe UI", 9),
                                  fg=self.colors["text_secondary"],
                                  bg=self.colors["bg_dark"])
        self.time_label.pack(side=tk.RIGHT)

    def start_scan(self):
        target_str = self.target_entry.get().strip()
        ports_str = self.ports_entry.get().strip()
        timeout_str = self.timeout_entry.get().strip()
        threads_str = self.threads_entry.get().strip()
        do_banner = self.banner_var.get()
        
        try:
            ip, host = resolve_target(target_str)
            self.target_ip = ip
            self.target_host = host
            port_list = parse_ports(ports_str)
            timeout = float(timeout_str)
            threads = int(threads_str)
            
            if timeout <= 0:
                raise ValueError("Timeout must be greater than 0.")
            if threads < 1 or threads > 500:
                raise ValueError("Threads must be between 1 and 500.")
        except ValueError as e:
            messagebox.showerror("Invalid Input", str(e))
            return

        # Clear UI state
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.scan_results.clear()
        self.search_entry.delete(0, tk.END)
        
        self.scanning = True
        self.scan_button.set_enabled(False)
        self.stop_button.set_enabled(True)
        
        self.total_ports = len(port_list)
        self.scanned_ports = 0
        self.progress_bar["value"] = 0
        self.progress_bar["maximum"] = self.total_ports
        
        self.start_time = time.time()
        
        host_info = f"{host} ({ip})" if host != ip else ip
        self.status_label.config(text=f"⏳ Scanning {self.total_ports} ports on {host_info}...")
        
        scan_thread = threading.Thread(target=self.scan_worker,
                                       args=(ip, port_list, timeout, threads, do_banner))
        scan_thread.daemon = True
        scan_thread.start()

    def scan_worker(self, ip, port_list, timeout, max_threads, do_banner):
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(scan_single_port, ip, port, timeout, do_banner): port 
                       for port in port_list}
            
            for future in as_completed(futures):
                if not self.scanning:
                    executor.shutdown(wait=False)
                    break
                
                res = future.result()
                self.scanned_ports += 1
                
                if res:
                    self.result_queue.put(("result", res))
                
                self.result_queue.put(("progress", self.scanned_ports))
        
        self.result_queue.put(("done", None))

    def process_results(self):
        try:
            while True:
                msg_type, data = self.result_queue.get_nowait()
                
                if msg_type == "result":
                    res = data
                    self.scan_results.append(res)
                    banner_text = res["banner"] if res["banner"] else res["description"]
                    self.results_tree.insert("", tk.END, values=(
                        res["port"], res["status"], f"{res['latency_ms']} ms", res["service"], banner_text
                    ), tags=("open_row",))
                    self.results_count.config(text=f"{len(self.scan_results)} open ports found")
                    
                elif msg_type == "progress":
                    self.progress_bar["value"] = data
                    percent = int((data / self.total_ports) * 100)
                    self.progress_percent.config(text=f"{percent}%")
                    self.progress_label.config(text=f"Scanning port {data} of {self.total_ports}")
                    
                    elapsed = time.time() - self.start_time
                    self.time_label.config(text=f"Elapsed: {elapsed:.1f}s")
                    
                elif msg_type == "done":
                    self.scan_complete()
                    
        except queue.Empty:
            pass
        
        self.root.after(40, self.process_results)

    def scan_complete(self):
        self.scanning = False
        self.scan_button.set_enabled(True)
        self.stop_button.set_enabled(False)
        
        elapsed = time.time() - self.start_time
        self.progress_label.config(text=f"Scan complete! Found {len(self.scan_results)} open ports")
        self.progress_percent.config(text="100%")
        self.time_label.config(text=f"Total time: {elapsed:.1f}s")
        
        host_info = f"{self.target_host} ({self.target_ip})" if self.target_host != self.target_ip else self.target_ip
        self.status_label.config(
            text=f"✅ Completed - {len(self.scan_results)} open ports found on {host_info} in {elapsed:.1f}s"
        )

    def stop_scan(self):
        self.scanning = False
        self.scan_button.set_enabled(True)
        self.stop_button.set_enabled(False)
        self.status_label.config(text="⚠️ Scan stopped by user")

    def export_results(self):
        if not self.scan_results:
            messagebox.showwarning("No Results", "No scan results to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[
                ("JSON files", "*.json"),
                ("Text files", "*.txt"),
                ("CSV files", "*.csv"),
                ("All files", "*.*")
            ],
            title="Export Port Scan Results"
        )
        
        if not filename:
            return
            
        try:
            ext = os.path.splitext(filename)[1].lower()
            if ext == ".json":
                export_data = {
                    "target_host": self.target_host,
                    "target_ip": self.target_ip,
                    "scan_date": datetime.now().isoformat(),
                    "open_ports_count": len(self.scan_results),
                    "results": self.scan_results
                }
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(export_data, f, indent=2)
                    
            elif ext == ".csv":
                with open(filename, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Port", "Status", "Latency (ms)", "Service", "Description", "Banner"])
                    for r in self.scan_results:
                        writer.writerow([r["port"], r["status"], r["latency_ms"], r["service"], r["description"], r["banner"]])
                        
            else:  # TXT
                with open(filename, "w", encoding="utf-8") as f:
                    f.write("Port Scan Results\n")
                    f.write(f"Target: {self.target_host} ({self.target_ip})\n")
                    f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 70 + "\n\n")
                    f.write(f"{'Port':<8}{'Status':<10}{'Latency':<12}{'Service':<18}{'Banner / Description'}\n")
                    f.write("-" * 70 + "\n")
                    for r in self.scan_results:
                        b = r["banner"] if r["banner"] else r["description"]
                        f.write(f"{r['port']:<8}{r['status']:<10}{str(r['latency_ms'])+' ms':<12}{r['service']:<18}{b}\n")
                    f.write("\n" + "=" * 70 + "\n")
                    f.write(f"Total open ports: {len(self.scan_results)}\n")
                    
            messagebox.showinfo("Export Successful", f"Scan results saved to:\n{filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export: {str(e)}")


def main_gui():
    root = tk.Tk()
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width - 1050) // 2
    y = (screen_height - 750) // 2
    root.geometry(f"1050x750+{x}+{y}")
    
    app = PortScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main_gui()
