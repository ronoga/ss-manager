# ss-manager - Shadowsocks Service Manager Script

## English Description

`ss-manager` is a powerful Bash script designed to help system administrators and Shadowsocks server operators to manage, monitor, and troubleshoot Shadowsocks services on Linux servers easily.  
It provides functionalities like port availability checks, DNS resolution testing, firewall rule verification and addition, connection tests using multiple methods (netcat, curl, socket), and Shadowsocks service status checks.

### Features

- Check if a port is free or in use locally (for localhost IPs).  
- DNS resolution tests using multiple public DNS servers (Google, Cloudflare, Quad9).  
- Firewall rule detection and automatic temporary rule insertion if missing.  
- Connection tests to the target host and port with retries and timeouts.  
- Verify if Shadowsocks service is running on the specified port.  
- Automatic fixing of common issues including restarting the service and adding firewall rules.  
- Interactive menu for real-time traffic monitoring, log management, configuration handling, and script installation.  
- Requires root privileges and can auto-escalate with `sudo` if not run as root.

### Use the interactive menu to:
- Monitor active connections and traffic per port
- Create, list, and delete Shadowsocks configurations
- View and clear script and service logs
- Install the script system-wide for easier access


### Usage

Run the script with root permission:  
```bash
sudo ./ss-manager.sh

