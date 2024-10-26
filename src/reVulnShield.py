import subprocess
import platform
import csv
import time
import os

def scan_host(ip_address):
    try:
        result = subprocess.run(["sudo", "nmap", "-O", "-p-", ip_address], capture_output=True, text=True)
        output = result.stdout
        print(output)
        open_ports = []
        for line in output.splitlines():
            if "open" in line:
                port, state, service = line.split()[:3]
                open_ports.append((port, state, service))
            elif "OS detection" in line or "Aggressive OS guesses" in line:
                os_info = line.split(":")[1].strip()
                os_name, os_version = os_info.split(" ")
                for port_info in open_ports:
                    port_info += (os_name, os_version)

        return open_ports

    except subprocess.CalledProcessError as e:
        print(f"Error scanning {ip_address}: {e}")
        return []

def save_to_csv(results, filename="scan_results.csv"):
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['Port', 'State', 'Service', 'OS Name', 'OS Version']
        writer = csv.writer(csvfile)
        writer.writerow(fieldnames)
        writer.writerows(results)

if __name__ == "__main__":
    print("[" + __file__ + "]'s last modified: %s" % time.ctime(os.path.getmtime(__file__)))
    # Get the kernel version
    kernel_version = platform.release()
    print("Kernel Version:", kernel_version)

    ip_address = input("Enter the IP address: ")
    scan_results = scan_host(ip_address)
    save_to_csv(scan_results)
