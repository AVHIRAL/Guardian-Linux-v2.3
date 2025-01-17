import sqlite3
import os
import subprocess
import sys
import time
import signal
import psutil
from threading import Thread
from datetime import datetime

def log_event(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("/var/log/guardian.log", "a", encoding='utf-8') as log_file:
        log_file.write(f"{timestamp} - {message}\n")

def validate_input(user_input):
    if not isinstance(user_input, str):
        raise ValueError("Invalid input type")
    if ";" in user_input or "--" in user_input:
        raise ValueError("Potential SQL injection detected")
    return user_input

def find_database_path():
    possible_paths = ["/var/lib/myapp/database.db", "/usr/local/myapp/database.db", "/home/user/myapp/database.db"]
    for path in possible_paths:
        if os.path.exists(path):
            return path
    raise FileNotFoundError("Database file not found in predefined locations.")

class SQLDatabase:
    def __init__(self):
        self.db_path = find_database_path()
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()

    def execute_query(self, query, params=()):
        validated_params = tuple(validate_input(param) for param in params)
        self.cursor.execute(query, validated_params)
        self.conn.commit()

    def fetch_results(self, query, params=()):
        validated_params = tuple(validate_input(param) for param in params)
        self.cursor.execute(query, validated_params)
        return self.cursor.fetchall()

    def close(self):
        self.conn.close()

class RansomwareProtection(Thread):
    def __init__(self, watch_directories):
        super().__init__(daemon=True)
        self.watch_directories = watch_directories

    def run(self):
        while True:
            for directory in self.watch_directories:
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if os.path.getmtime(file_path) - os.path.getctime(file_path) < 1:
                            log_event("Suspicious activity detected: " + file_path)

class MalwareScanner(Thread):
    def __init__(self, watch_paths):
        super().__init__(daemon=True)
        self.watch_paths = watch_paths

    def run(self):
        while True:
            self.scan_for_malware()
            time.sleep(60)

    def scan_for_malware(self):
        for path in self.watch_paths:
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file.endswith(('.py', '.sh', '.pl')):
                        file_path = os.path.join(root, file)
                        if self.is_malicious(file_path):
                            log_event("Malicious script detected: " + file_path)

    def is_malicious(self, file_path):
        return os.path.getsize(file_path) > 50000

class NetworkMonitor(Thread):
    def __init__(self, threshold, public_ip):
        super().__init__()
        self.threshold = threshold
        self.public_ip = public_ip  # Public IP of your router to exclude
        self.ip_counts = {}

    def run(self):
        while True:
            try:
                self.monitor_network_activity()
            except Exception as e:
                log_event(f"Error in NetworkMonitor: {str(e)}")

    def monitor_network_activity(self):
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == "ESTABLISHED":
                ip = conn.raddr.ip if conn.raddr else 'Unknown'
                if self.is_local_or_public_ip(ip):
                    continue  # Skip local IPs and the router's public IP
                self.ip_counts[ip] = self.ip_counts.get(ip, 0) + 1
                if self.ip_counts[ip] > self.threshold:
                    log_event(f"Suspect network activity: {ip} has reached {self.ip_counts[ip]} connections")
                    if self.ip_counts[ip] > self.threshold * 2:
                        self.block_ip(ip)

    def is_local_or_public_ip(self, ip_address):
        # Skip private IPs and your router's public IP
        return ip_address.startswith("192.168.") or ip_address == self.public_ip

    def block_ip(self, ip_address):
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'])
        log_event(f"Blocked IP address: {ip_address}")

class Guardian:
    def __init__(self, public_ip):
        self.active = True
        self.public_ip = public_ip
        self.setup_signal_handlers()
        self.threads = [
            RansomwareProtection(["/home", "/var/www"]),
            MalwareScanner(["/usr/local/bin", "/usr/bin"]),
            NetworkMonitor(100, public_ip)
        ]

    def setup_signal_handlers(self):
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)

    def start(self):
        log_event("Guardian started successfully.")
        for thread in self.threads:
            thread.start()
        try:
            while True:
                time.sleep(1)  # Keep the main thread alive.
        except KeyboardInterrupt:
            self.stop(None, None)

    def stop(self, signum, frame):
        self.active = False
        log_event("Guardian stopped.")
        for thread in self.threads:
            thread.join()  # Ensure all threads are cleanly stopped
        sys.exit(0)

    def status(self):
        return "Actif" if self.active else "Inactif"

if __name__ == "__main__":
    public_ip = "VOTRE IP PUBLIQUE"  # Replace with your actual public IP
    guardian = Guardian(public_ip)
    if "--start" in sys.argv:
        guardian.start()
    elif "--stop" in sys.argv:
        subprocess.run(["systemctl", "stop", "guardian.service"])
    elif "--status" in sys.argv:
        print("Guardian is active." if guardian.active else "Guardian is not active.")
