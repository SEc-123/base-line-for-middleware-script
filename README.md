# Baseline Security Scripts for Apache, Nginx, and Tomcat

This repository contains Python scripts for performing baseline security checks on Apache HTTP Server, Nginx, and Tomcat. Each script inspects critical configurations and provides recommendations to enhance the security of your web and application servers.

## Scripts Overview

### 1. Apache Baseline Security Script (`apache_detect.py`)
#### Features:
- **Global Configuration Checks**:
  - Validates `ServerTokens`, `ServerSignature`, and `Timeout` settings.
  - Ensures HTTPS is enabled globally.
  - Verifies the presence of necessary security headers (e.g., `X-Frame-Options`, `Content-Security-Policy`).
- **Virtual Host Checks**:
  - Inspects virtual host configurations for HTTPS and HSTS.
  - Checks for appropriate directory permissions and access restrictions.
- **Module Validation**:
  - Recommends disabling unnecessary modules.
  - Ensures critical modules (e.g., `ssl_module`, `headers_module`) are enabled.
- **Logging**:
  - Confirms `ErrorLog` and `CustomLog` configurations are present.
  - Suggests appropriate log levels.
- **File Permission Checks**:
  - Scans configuration and virtual host files for overly permissive permissions.

#### Usage:
1. **Install Python 3**:
   ```bash
   sudo apt install python3  # For Debian/Ubuntu
   sudo yum install python3  # For CentOS/RHEL
   ```
2. **Run the script**:
   ```bash
   sudo python3 apache_detect.py
   ```
3. **Interpret results**:
   - Issues are listed with recommended fixes.
   - No issues? You'll see: `No security issues detected!`

---

### 2. Nginx Baseline Security Script (`nginx_detect.py`)
#### Features:
- **Global Configuration Checks**:
  - Validates `worker_processes`, `ssl_protocols`, and `server_tokens`.
  - Ensures HTTPS is enforced with proper SSL/TLS versions.
- **Virtual Host Checks**:
  - Inspects HSTS and HTTPS configurations for all enabled sites.
  - Verifies directory indexing is disabled (`autoindex off`).
- **Logging**:
  - Ensures `access_log` and `error_log` are properly configured.
  - Recommends appropriate log formatting.
- **File Permissions**:
  - Validates permissions for configuration files and virtual host directories.
- **Security Headers**:
  - Checks for `X-Frame-Options`, `X-Content-Type-Options`, and `Content-Security-Policy` headers.

#### Usage:
1. **Install Python 3**:
   ```bash
   sudo apt install python3  # For Debian/Ubuntu
   sudo yum install python3  # For CentOS/RHEL
   ```
2. **Run the script**:
   ```bash
   sudo python3 nginx_detect.py
   ```
3. **Results**:
   - Any detected issues will be listed with remediation advice.
   - If secure, you'll see: `No security issues detected!`

---

### 3. Tomcat Baseline Security Script (`tomcat_detect.py`)
#### Features:
- **`server.xml` Configuration**:
  - Validates HTTPS (port 443, `SSLEnabled=true`).
  - Suggests disabling AJP connector unless necessary.
  - Ensures `maxThreads` and `acceptCount` are configured.
  - Recommends binding to `127.0.0.1` for internal services.
- **`web.xml` Configuration**:
  - Verifies session timeout settings.
  - Ensures TRACE HTTP method is disabled.
  - Checks for disabled default servlet to reduce attack surface.
- **User Management (`tomcat-users.xml`)**:
  - Checks for strong passwords for administrative accounts.
  - Validates roles and permissions for minimal privileges.
- **Security Policies (`catalina.policy`)**:
  - Ensures strict security policies are enforced.
- **File and Directory Permissions**:
  - Scans for overly permissive file and directory permissions.
- **Logging**:
  - Verifies appropriate log levels (`INFO` or stricter).

#### Usage:
1. **Install Python 3**:
   ```bash
   sudo apt install python3  # For Debian/Ubuntu
   sudo yum install python3  # For CentOS/RHEL
   ```
2. **Run the script**:
   ```bash
   sudo python3 tomcat_detect.py
   ```
3. **Results**:
   - Issues will be detailed with actionable recommendations.
   - Secure systems show: `No security issues detected!`

---

## Common Requirements
1. **Permissions**:
   - Ensure the user running the scripts has read access to the configuration files. Use `sudo` if needed.
2. **Python Installation**:
   - All scripts require Python 3.
3. **File Paths**:
   - Update script paths to match your server’s configurations if they differ from the defaults.

---

## Recommendations for Regular Checks
- Add the scripts to a cron job for automated periodic checks:
  ```bash
  crontab -e
  ```
  Example entry (runs daily at 3 AM):
  ```
  0 3 * * * /usr/bin/python3 /path/to/apache_detect.py
  0 3 * * * /usr/bin/python3 /path/to/nginx_detect.py
  0 3 * * * /usr/bin/python3 /path/to/tomcat_detect.py
  ```

---

## Troubleshooting
- **Script errors**:
  - Verify Python 3 is installed and the script has execute permissions (`chmod +x script_name.py`).
- **Incorrect file paths**:
  - Adjust file paths in the script to match your server’s directory structure.



