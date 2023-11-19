import subprocess
import time
import requests
import os
from scapy.all import sniff, IP
import hashlib
import tkinter as tk
from tkinter import messagebox
import socket


API_KEY = 'ADD API HERE'  # Replace with your VirusTotal API key


def check_system_updates():
    print("Opening Windows Update settings...")
    subprocess.run("start ms-settings:windowsupdate", shell=True)
    input("Press any key to continue...")


def check_firewall_status():
    print("Checking firewall status...")
    subprocess.run(["powershell", "-Command", "Get-NetFirewallProfile"])
    input("Press any key to continue...")


def check_antivirus_status():
    print("Checking antivirus status...")
    subprocess.run(["powershell", "-Command", "Get-MpComputerStatus"])
    input("Press any key to continue...")


def list_installed_programs():
    print("Listing installed programs...")
    subprocess.run(["powershell", "-Command", "Get-WmiObject -Class Win32_Product | Select-Object -Property Name"])
    input("Press any key to continue...")


def check_network_status():
    print("Checking network status...")
    subprocess.run(["powershell", "-Command", "Get-NetAdapter | Select-Object -Property Name, Status"])
    input("Press any key to continue...")


def view_system_info():
    print("Viewing system information...")
    subprocess.run(["systeminfo"])
    input("Press any key to continue...")


def view_running_processes():
    print("Viewing running processes...")
    subprocess.run(["tasklist"])
    input("Press any key to continue...")


def check_disk_usage():
    print("Checking disk usage...")
    subprocess.run(["powershell", "-Command", "Get-PSDrive C | Select-Object -Property Used, Free"])
    input("Press any key to continue...")


def view_system_logs():
    print("Viewing system logs...")
    subprocess.run(["powershell", "-Command", "Get-EventLog -LogName System -Newest 10"])
    input("Press any key to continue...")


def check_network_connections():
    print("Checking network connections...")
    subprocess.run(["netstat", "-an"])
    input("Press any key to continue...")


def check_other_users():
    main_user = input("Enter the main user's name: ")
    print("Checking for other users on the PC...")


    result = subprocess.run(["powershell", "-Command", "Get-LocalUser | Select-Object -Property Name"], capture_output=True, text=True)
    users = result.stdout.split('\r\n')
    
    other_users = [user for user in users if user.strip() and user.strip().lower() != main_user.lower()]
    
    if other_users:
        print("Other users found on the PC:")
        for user in other_users:
            print(user)
            input("Press any key to continue...")
    else:
        print("No other users found on the PC.")
        input("Press any key to continue...")

def resolve_ip_to_hostname(ip):
    try:
        # Attempt to resolve the IP to a hostname
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        # If the hostname could not be resolved, return the IP
        return ip

def monitor_network_traffic():
    def process_packet(packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Resolve IPs to hostnames
            src_hostname = resolve_ip_to_hostname(src_ip)
            dst_hostname = resolve_ip_to_hostname(dst_ip)

            # Output the packet information including the resolved hostnames
            print(f"Ether / IP / TCP {src_ip} ({src_hostname}) > {dst_ip} ({dst_hostname}) {packet.summary()}")

    print("Monitoring network traffic (press Ctrl+C to stop)...")
    try:
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\nStopped network monitoring.")
    finally:
        input("Press any key to continue...") 

def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def scan_file_virustotal(file_path):
    # First, get the hash of the file and check if it has already been scanned
    file_hash = get_file_hash(file_path)
    params = {'apikey': API_KEY, 'resource': file_hash}
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "gzip,  My Python requests library example client or username"
    }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)


    # If the file has not been scanned before, submit it for scanning
    if response.status_code != 200 or response.json().get('response_code') == 0:
        files = {'file': (os.path.basename(file_path), open(file_path, 'rb'))}
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
        if response.status_code == 200:
            print(f"File {file_path} submitted successfully. Waiting for report...")
            # Wait for a moment to allow VirusTotal to process the file
            time.sleep(15)
            # Recheck the report after submission
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)


    # Check the report for scan results
    if response.status_code == 200:
        report = response.json()
        if report.get('response_code') == 1:
            if report.get('positives', 0) > 0:
                # The file is detected by at least one antivirus engine
                print(f"File {file_path} is detected as potentially malicious.")
                print(f"Detection ratio: {report.get('positives')}/{report.get('total')}")
                print(f"VirusTotal link: {report.get('permalink')}")
                return True
    else:
        print(f"Could not retrieve report for file {file_path}.")
    return False

def scan_directories():
    user_input = input("Enter the directories to scan, separated by a comma (e.g., C:\\, D:\\, E:\\): ")
    directories = [dir.strip() for dir in user_input.split(',')]
    detected_files = []
    
    for directory in directories:
        print(f"Scanning directory: {directory}")
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if scan_file_virustotal(file_path):
                    detected_files.append(file_path)
                # Sleep to avoid hitting the API rate limit
                time.sleep(15)
    
    if detected_files:
        print("\nPotentially malicious files detected:")
        for file_path in detected_files:
            print(file_path)
    else:
        print("\nNo potentially malicious files detected.")
    input("Press any key to continue...")

def scan_url_virustotal(url):
    url_scan_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': API_KEY, 'url': url}
    
    response = requests.post(url_scan_url, data=params)
    if response.status_code == 200:
        print(f"URL {url} submitted successfully. Waiting for report...")
        # Wait for a moment to allow VirusTotal to process the URL
        time.sleep(15)
        # Check the report
        url_report_url = 'https://www.virustotal.com/vtapi/v2/url/report'
        report_params = {'apikey': API_KEY, 'resource': url}
        report_response = requests.get(url_report_url, params=report_params)
        if report_response.status_code == 200:
            report = report_response.json()
            if report.get('positives', 0) > 0:
                print(f"URL {url} is detected as potentially malicious.")
                print(f"Detection ratio: {report.get('positives')}/{report.get('total')}")
                print(f"VirusTotal link: {report.get('permalink')}")
                return True
    else:
        print(f"Error submitting URL {url} for scanning.")
    return False

def scan_urls_from_user_input():
    user_input = input("Enter the URLs to scan, separated by a comma (e.g., http://example.com, http://example.org): ")
    urls = [url.strip() for url in user_input.split(',')]
    detected_urls = []
    
    for url in urls:
        if scan_url_virustotal(url):
            detected_urls.append(url)
    
    if detected_urls:
        print("\nPotentially malicious URLs detected:")
        for url in detected_urls:
            print(url)
    else:
        print("\nNo potentially malicious URLs detected.")
    input("Press any key to continue...")

def scan_single_file():
    file_path = input("Enter the full path of the file to scan: ").strip()
    if os.path.isfile(file_path):
        if scan_file_virustotal(file_path):
            print(f"The file {file_path} is potentially malicious.")
        else:
            print(f"The file {file_path} is safe.")
    else:
        print("The specified file does not exist.")
    input("Press any key to continue...")

def main_menu():
    options = {
        "1": check_system_updates,
        "2": check_firewall_status,
        "3": check_antivirus_status,
        "4": list_installed_programs,
        "5": check_network_status,
        "6": view_system_info,
        "7": view_running_processes,
        "8": check_disk_usage,
        "9": view_system_logs,
        "10": check_network_connections,
        "11": check_other_users,
        "12": monitor_network_traffic,
        "13": scan_directories,
        "14": scan_single_file
    }

    while True:
        print("\nChoose an option:")
        print("1: Check System Updates")
        print("2: Check Firewall Status")
        print("3: Check Antivirus Status")
        print("4: List Installed Programs")
        print("5: Check Network Status")
        print("6: View System Information")
        print("7: View Running Processes")
        print("8: Check Disk Usage")
        print("9: View System Logs")
        print("10: Check Network Connections")
        print("11: Check for Other Users on the PC")
        print("12: Monitor Real-Time Network Traffic")
        print("13: Scan a Directory with VirusTotal")
        print("14: Scan a Single file with VirusTotal")
        print("0: Exit")

        choice = input("Enter your choice: ")
        if choice == "0":
            break
        elif choice in options:
            options[choice]()
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main_menu()
