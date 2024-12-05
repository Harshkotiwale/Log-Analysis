import re
import csv
from collections import defaultdict
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_log_line(line):
    """
    Parse a single line of the log file.
    Returns a dictionary with extracted details or None if the line is invalid.
    """
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<datetime>[^\]]+)\] '
        r'"(?P<method>\w+) (?P<endpoint>[^\s]+) HTTP/\d\.\d" (?P<status>\d{3}) (?P<size>\d+)'
        r'(?: "(?P<extra>.+)")?'
    )
    match = log_pattern.match(line)
    if match:
        return match.groupdict()
    else:
        logging.warning(f"Skipping malformed log entry: {line}")
        return None

def count_requests_by_ip(log_lines):
    """
    Count the number of requests made by each IP address.
    """
    ip_count = defaultdict(int)
    for line in log_lines:
        data = parse_log_line(line)
        if data:
            ip_count[data['ip']] += 1
    return ip_count

def find_most_accessed_endpoint(log_lines):
    """
    Find the most frequently accessed endpoint.
    """
    endpoint_count = defaultdict(int)
    for line in log_lines:
        data = parse_log_line(line)
        if data:
            endpoint_count[data['endpoint']] += 1
    most_accessed = max(endpoint_count.items(), key=lambda x: x[1], default=None)
    return most_accessed

def detect_suspicious_activity(log_lines):
    """
    Detect suspicious activity (e.g., multiple failed login attempts).
    """
    failed_logins = defaultdict(int)
    for line in log_lines:
        data = parse_log_line(line)
        if data and data['status'] == '401':
            failed_logins[data['ip']] += 1
    return failed_logins

def save_to_csv(filename, ip_count, suspicious_activity):
    """
    Save analysis results to a CSV file.
    """
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_count.items():
            writer.writerow([ip, count])
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, attempts in suspicious_activity.items():
            writer.writerow([ip, attempts])

def main():
    log_file = "sample.log"
    output_csv = "log_analysis_results.csv"
    
    try:
        with open(log_file, 'r') as f:
            log_lines = f.readlines()
    except FileNotFoundError:
        logging.error(f"Log file '{log_file}' not found.")
        return
    
    # Analyze log file
    ip_count = count_requests_by_ip(log_lines)
    most_accessed_endpoint = find_most_accessed_endpoint(log_lines)
    suspicious_activity = detect_suspicious_activity(log_lines)
    
    # Print results
    print("Requests per IP:")
    print("IP Address           Request Count")
    for ip, count in ip_count.items():
        print(f"{ip:<20} {count}")
    
    if most_accessed_endpoint:
        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, attempts in suspicious_activity.items():
        print(f"{ip:<20} {attempts}")
    
    # Save results to CSV
    save_to_csv(output_csv, ip_count, suspicious_activity)
    logging.info(f"Analysis results saved to {output_csv}")

if __name__ == "__main__":
    main()
