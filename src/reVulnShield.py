import subprocess
import platform
import csv
import time
import os
import re

def check_nmap_version():
    try:
        result = subprocess.run(["nmap", "-V"], capture_output=True, text=True)
        if result.returncode == 0:
            print("Nmap version:", result.stdout.strip())
            return True
        else:
            print("Nmap not found or error occurred.")
    except FileNotFoundError:
        print("Nmap not found. Please install Nmap.\nsudo apt install nmap -y")
    return False


def run_nmap_scan(target_ip):
    # Run nmap scan to find open ports and operating system
    result = subprocess.run(["sudo", "nmap", "-O", "-p-", target_ip], capture_output=True, text=True)
    return result.stdout


def parse_nmap_port_state_info(nmap_output):
    ports_info = []
    # Extract open ports, protocol, state, and service information
    port_pattern = re.compile(r"(\d{1,5})/(tcp|udp)\s+(\w+)\s+([\w-]+)")
    for match in port_pattern.finditer(nmap_output):
        port, protocol, state, service = match.groups()
        ports_info.append({
            "port": port, 
            "protocol": protocol, 
            "state": state, 
            "service": service
        })
    return ports_info


def parse_nmap_os_info(nmap_output):
    os_name = "Unknown"
    os_version = "Unknown"    
    # Extract OS details (name and version if available)
    os_pattern = re.compile(r"OS details: ([^,]+),? (.+)?")
    os_match = os_pattern.search(nmap_output)
    
    if os_match:
        os_name = os_match.group(1).strip()
        os_version = os_match.group(2).strip() if os_match.group(2) else "Unknown"
    else:
        # Extract aggressive OS guess if no exact OS details are available
        aggressive_os_pattern = re.compile(r"Aggressive OS guesses: ([^,]+)")
        aggressive_os_match = aggressive_os_pattern.search(nmap_output)
        if aggressive_os_match:
            os_name = aggressive_os_match.group(1).strip()
            os_version = "Approximate"

    return os_name, os_version


def write_to_csv(target_ip, ports_info, os_name, os_version, filename="nmap_results.csv"):
    with open(filename, mode="w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["Target IP", "Port", "State", "Service", "OS Name", "OS Version"])
        
        # Write each port's information along with OS details
        for port_info in ports_info:
            writer.writerow([
                target_ip, 
                port_info["port"],
                port_info["protocol"],
                port_info["state"], 
                port_info["service"], 
                os_name, 
                os_version
            ])


if __name__ == "__main__":
    print("[" + __file__ + "]'s last modified: %s" % time.ctime(os.path.getmtime(__file__)))
    # Get the kernel version
    kernel_version = platform.release()
    print("Kernel Version:", kernel_version)
    if not check_nmap_version():
        exit(0)
    target_ip = input("Enter the IP address: ")
    nmap_output = run_nmap_scan(target_ip)
    ports_info = parse_nmap_port_state_info(nmap_output)
    os_name, os_version = parse_nmap_os_info(nmap_output)
    write_to_csv(target_ip, ports_info, os_name, os_version)