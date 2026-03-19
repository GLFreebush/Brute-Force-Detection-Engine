import re
import time
import logging

class BruteForceDetector:
    def __init__(self, log_file, threshold=5, time_window=300):
        self.log_file = log_file
        self.threshold = threshold  # failed attempts before blocking
        self.time_window = time_window  # 5 minutes
        self.failed_attempts = {}
        self.blocked_ips = {}
        
    def parse_logs(self):
        try:
            with open(self.log_file, 'r') as f:
                for line in f:
                    self.analyze_log(line)
        except FileNotFoundError:
            logging.error(f"Log file {self.log_file} not found")
    
    def analyze_log(self, log_line):
        # Extract IP and failed login attempts
        match = re.search(r'(\d+\.\d+\.\d+\.\d+).*Failed login', log_line)
        if match:
            ip = match.group(1)
            self.record_failed_attempt(ip)
    
    def record_failed_attempt(self, ip):
        current_time = time.time()
        
        if ip not in self.failed_attempts:
            self.failed_attempts[ip] = []
        
        # Add timestamp of failed attempt
        self.failed_attempts[ip].append(current_time)
        
        # Remove old attempts outside time window
        self.failed_attempts[ip] = [
            timestamp for timestamp in self.failed_attempts[ip]
            if current_time - timestamp < self.time_window
        ]
        
        # Check if threshold exceeded
        if len(self.failed_attempts[ip]) >= self.threshold:
            self.block_ip(ip)
    
    def block_ip(self, ip):
        if ip not in self.blocked_ips:
            self.blocked_ips[ip] = time.time()
            logging.warning(f"ALERT: Blocking IP {ip} - Too many failed attempts")
            print(f"🚨 IP {ip} has been BLOCKED")

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    detector = BruteForceDetector('system_logs.txt')

