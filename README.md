# VRV-Security-Python-Intern-Assignment
Overview
This project analyzes web server log files to track traffic patterns, detect security threats, and generate useful reports. It is designed as an assignment for a security-focused Python internship at VRV Security.

Features
Parse web server logs and extract useful data such as IP addresses, HTTP methods, status codes, and accessed endpoints.
Track requests per IP address and identify potential brute-force login attempts.
Flag IPs with failed login attempts (HTTP status code 401) exceeding a configured threshold.
Generate a detailed report in both terminal and CSV format, including:
Number of requests made by each IP address
The most frequently accessed endpoint
Suspicious activity based on failed login attempts
Prerequisites
Before running this project, make sure you have the following installed:

Python 3.x
Necessary Python libraries:
re (Regex)
csv
collections
prettytable
You can install the required libraries using:

bash
Copy code
pip install prettytable
Configuration
log_file_path: Path to the log file you want to analyze (e.g., sample.log).
output_csv_path: Path where you want to save the CSV report (e.g., log_analysis_results.csv).
FAILED_LOGIN_THRESHOLD: The threshold value for failed login attempts. Default is 10.
How to Use
Place your log file (e.g., sample.log) in the same directory as the script or provide the correct path to the log file.
Run the script:
bash
Copy code
python log_analysis.py
After execution, the results will be displayed in the terminal and saved to a CSV file (log_analysis_results.csv).
Example Output in Terminal
bash
Copy code
=== Requests Per IP ===
+---------------+---------------+
|   IP Address  | Request Count |
+---------------+---------------+
|  203.0.113.5  |       8       |
| 198.51.100.23 |       8       |
|  192.168.1.1  |       7       |
|    10.0.0.2   |       6       |
| 192.168.1.100 |       5       |
+---------------+---------------+

=== Most Frequently Accessed Endpoint ===
/login (Accessed 13 times)

=== Suspicious Activity Detected ===
No suspicious activity detected.
Example Output in CSV
csv
Copy code
IP Address,Request Count
203.0.113.5,8
198.51.100.23,8
192.168.1.1,7
10.0.0.2,6
192.168.1.100,5

Most Frequently Accessed Endpoint:,Access Count
/login,13

Suspicious Activity Detected
IP Address,Failed Login Attempts
Future Enhancements
Implement more detailed filtering based on log levels and HTTP methods.
Add support for more log formats.
Integrate with a web interface for real-time log monitoring.
License
This project is licensed under the MIT License.
