# Wazuh
Wazuh Security Project
This project demonstrates how Wazuh was configured and utilized to detect and monitor various security events, including malicious activities, vulnerabilities, and system changes.

Features Implemented
1. Detecting Mimikatz
Configured Wazuh to detect Mimikatz usage in real-time.
Created custom alerts for Mimikatz detection based on Sysmon logs.
Outcome: Successfully identified and alerted on Mimikatz execution.
2. File Integrity Monitoring (FIM)
Monitored changes in critical directories (e.g., C:\Users\Public).
Detected unauthorized modifications to files and directories.
Key Feature: Detailed change logs using the syscheck.diff field.
Demonstrated both automated detection and manual configuration for older systems.
3. Vulnerability Detection
Enabled the Wazuh Vulnerability Detector module.
Configured /var/ossec/etc/ossec.conf to analyze software versions and identify known vulnerabilities.
Outcome: Detected vulnerabilities with detailed metadata for actionable insights.
4. SQL Injection Detection
Monitored Apache server logs for SQL injection attempts.
Simulated SQL injection attacks using crafted HTTP requests.
Outcome: Wazuh generated alerts for malicious SQL injection activities.
