# VRV-Security-Python-Intern-Assignment
# Overview
This project analyzes web server log files to track traffic patterns, detect security threats, and generate useful reports. It is designed as an assignment for a security-focused Python internship at VRV Security.

# Features
- Parse web server logs and extract useful data such as IP addresses, HTTP methods, status codes, and accessed endpoints.
- Track requests per IP address and identify potential brute-force login attempts.
- Flag IPs with failed login attempts (HTTP status code 401) exceeding a configured threshold.
- Generate a detailed report in both terminal and CSV format, including:
  - Number of requests made by each IP address
  - The most frequently accessed endpoint
  - Suspicious activity based on failed login attempts
# Prerequisites
Before running this project, make sure you have the following installed:
- Python 3.x
# Necessary Python libraries:
- re (Regex)
- csv
- collections
- prettytable

You can install the required libraries using:
`pip install prettytable`
