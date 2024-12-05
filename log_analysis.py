
import re
import csv
from collections import Counter
from prettytable import PrettyTable

# Configuration
log_file_path = "sample.log"
output_csv_path = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10


def parse_log_file(file_path):
    """
    Parses web server logs into structured data.
    Args:
        file_path: Path to log file
    Returns:
        List of dicts containing IP, method, endpoint, and status
    """
    with open(file_path, "r") as file:
        logs = file.readlines()
    log_data = []
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*?\] "(?P<method>\w+) (?P<endpoint>\S+) HTTP/\d+\.\d+" (?P<status>\d+) .*'
    )
    for line in logs:
        match = log_pattern.match(line)
        if match:
            log_data.append(match.groupdict())
    return log_data


def analyze_requests_per_ip(log_data):
    """
    Counts requests from each IP address.

    Args:
        log_data: Parsed log entries
    Returns:
        List of (IP, count) tuples, sorted by count
    """
    ip_counter = Counter(log['ip'] for log in log_data)
    return ip_counter.most_common()


def analyze_most_accessed_endpoint(log_data):
    """
    Finds the most frequently accessed endpoint.

    Args:
        log_data: Parsed log entries
    Returns:
        Tuple of (endpoint, count) or None
    """
    endpoint_counter = Counter(log['endpoint'] for log in log_data)
    most_accessed = endpoint_counter.most_common(1)
    return most_accessed[0] if most_accessed else None


def detect_suspicious_activity(log_data, threshold=FAILED_LOGIN_THRESHOLD):
    """
    Identifies IPs with excessive failed logins.

    Args:
        log_data: Parsed log entries
        threshold: Failed login limit
    Returns:
        Dict of suspicious IPs and their failed counts
    """
    failed_login_counter = Counter(
        log['ip'] for log in log_data if log['status'] == '401'
    )
    suspicious_ips = {ip: count for ip, count in failed_login_counter.items() if count > threshold}
    return suspicious_ips


def save_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, output_path):
    """
    Exports results to CSV format.

    Args:
        ip_requests: IP traffic data
        most_accessed_endpoint: Popular endpoint data
        suspicious_activity: Security alerts
        output_path: Target file path
    """
    with open(output_path, mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)

        # Write requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests:
            writer.writerow([ip, count])

        # Write Most Frequently Accessed Endpoint:
        writer.writerow([])
        writer.writerow(["Most Frequently Accessed Endpoint:", "Access Count"])
        if most_accessed_endpoint:
            writer.writerow(most_accessed_endpoint)

        # Write suspicious activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])


def display_results(ip_requests, most_accessed_endpoint, suspicious_activity):
    """
    Show results in terminal using formatted tables.

    Args:
        ip_requests: IP traffic data
        most_accessed_endpoint: Popular endpoint data
        suspicious_activity: Security alerts
    """
    print("\n=== Requests Per IP ===")
    table = PrettyTable(["IP Address", "Request Count"])
    for ip, count in ip_requests:
        table.add_row([ip, count])
    print(table)

    print("\n=== Most Frequently Accessed Endpoint ===")
    if most_accessed_endpoint:
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    else:
        print("No endpoints accessed.")

    print("\n=== Suspicious Activity Detected ===")
    if suspicious_activity:
        suspicious_table = PrettyTable(["IP Address", "Failed Login Attempts"])
        for ip, count in suspicious_activity.items():
            suspicious_table.add_row([ip, count])
        print(suspicious_table)
    else:
        print("No suspicious activity detected.")


def main():
    """
    Run complete analysis workflow:
    Parse logs → Analyze data → Generate reports
    """
    # Parse the log file
    log_data = parse_log_file(log_file_path)

    # Analyze the log data
    ip_requests = analyze_requests_per_ip(log_data)
    most_accessed_endpoint = analyze_most_accessed_endpoint(log_data)
    suspicious_activity = detect_suspicious_activity(log_data)

    # Display the results
    display_results(ip_requests, most_accessed_endpoint, suspicious_activity)

    # Save the results to a CSV file
    save_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, output_csv_path)

    print(f"\nResults saved to {output_csv_path}")


if __name__ == "__main__":
    main()