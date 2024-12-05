# VRV-Security-Python-Intern-Assignment
# Overview
This project analyzes web server log files to track traffic patterns, detect security threats, and generate useful reports. It is designed as an assignment for a security-focused Python internship at VRV Security.

# Features
1.Parse web server logs and extract useful data such as IP addresses, HTTP methods, status codes, and accessed endpoints.
2.Track requests per IP address and identify potential brute-force login attempts.
3.Flag IPs with failed login attempts (HTTP status code 401) exceeding a configured threshold.
4.Generate a detailed report in both terminal and CSV format, including:
  - Number of requests made by each IP address
  - The most frequently accessed endpoint
  - Suspicious activity based on failed login attempts
# Prerequisites
Before running this project, make sure you have the following installed:
Python 3.x
# Necessary Python libraries:
1.re (Regex)
2.csv
3.collections
4.prettytable

IP Address,Failed Login Attempts
Future Enhancements
Implement more detailed filtering based on log levels and HTTP methods.
Add support for more log formats.
Integrate with a web interface for real-time log monitoring.
License
This project is licensed under the MIT License.
