#!/usr/bin/env python3
"""
Ollama Instance Scanner

This script uses masscan to perform a streaming scan over the entire IPv4 space (with configurable exclusions)
and then queries discovered hosts to determine if they are running an Ollama instance.
It checks the `/api/ps` endpoint (and optionally `/api/system` if a valid model is detected) to identify running instances.
Valid results are logged to a CSV file for further analysis.

WARNING: Scanning the entire IPv4 space can be disruptive and may be illegal without proper authorization.
"""

import subprocess
import requests
import json
import csv
import os
import time
import threading
from queue import Queue
from requests.exceptions import RequestException

from ips import get_ips_from_file

# -------------------------------------------------------------------
# Exclusion Subnets: Government and Private Networks
# -------------------------------------------------------------------
IP_FILE_NAME = "IP2LOCATION-LITE-DB1.NEW.CSV"
COMMON_GOVERNMENT_SUBNETS = get_ips_from_file(IP_FILE_NAME)

# -------------------------------------------------------------------
# Configurable Parameters
# -------------------------------------------------------------------
NUM_WORKER_THREADS = 500         # Number of concurrent threads for HTTP queries
HTTP_TIMEOUT = 2                 # Timeout in seconds for each HTTP request to Ollama endpoints
MASSCAN_RATE = 500000            # Transmission rate for masscan (packets per second)
TARGET_RANGE = "0.0.0.0/0"         # Target range (entire IPv4 space) -- use with caution!
PORTS_TO_SCAN = [11434]          # Ports to scan (default Ollama port)
CSV_FILENAME = f"ollama_scan_results_{int(time.time())}.csv"  # CSV file name based on current timestamp

# -------------------------------------------------------------------
# CSV Writer Setup: Thread-Safe CSV Writing
# -------------------------------------------------------------------
csv_lock = threading.Lock()

def get_csv_writer():
    """
    Prepares a CSV writer for appending scan results.
    Returns:
        tuple: (file_handle, csv.DictWriter) for the output CSV file.
    """
    file_exists = os.path.isfile(CSV_FILENAME)
    csv_file = open(CSV_FILENAME, "a", newline="", encoding="utf-8")
    fieldnames = ["ip", "port", "ps_url", "reachable", "valid_ollama", "ps_data", "system_data", "error"]
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
    if not file_exists:
        writer.writeheader()
    return csv_file, writer

csv_file_handle, csv_writer = get_csv_writer()

# -------------------------------------------------------------------
# Function: query_ollama_endpoints
# -------------------------------------------------------------------
def query_ollama_endpoints(ip, port):
    """
    Query the given host for an Ollama endpoint by accessing `/api/ps`
    and, if a valid model is detected, optionally `/api/system`.

    Args:
        ip (str): The IP address of the target host.
        port (int): The port number to query.

    Returns:
        dict: A dictionary containing the scan results with keys:
            - ip, port, reachable, valid_ollama, ps_data, system_data, error.
    """
    base_url = f"http://{ip}:{port}"
    data_collected = {
        "ip": ip,
        "port": port,
        "reachable": False,
        "valid_ollama": False,
        "ps_data": None,
        "system_data": None,
        "error": None
    }

    # Query the /api/ps endpoint to check for available models.
    try:
        ps_url = f"{base_url}/api/ps"
        response = requests.get(ps_url, timeout=HTTP_TIMEOUT)
        if response.status_code == 200:
            data_collected["reachable"] = True
            try:
                ps_json = response.json()
                data_collected["ps_data"] = ps_json
                # Check if the response contains a non-empty "models" key.
                if isinstance(ps_json, dict) and "models" in ps_json:
                    models = ps_json["models"]
                    if isinstance(models, list) and len(models) > 0:
                        data_collected["valid_ollama"] = True
            except ValueError:
                # Failed to parse JSON.
                pass
    except RequestException as e:
        data_collected["error"] = str(e)

    # If a valid Ollama instance is detected, try to fetch /api/system details.
    if data_collected["valid_ollama"]:
        try:
            sys_url = f"{base_url}/api/system"
            sys_response = requests.get(sys_url, timeout=HTTP_TIMEOUT)
            if sys_response.status_code == 200:
                try:
                    data_collected["system_data"] = sys_response.json()
                except ValueError:
                    pass
        except RequestException:
            # Failure to query /api/system is non-critical.
            pass

    return data_collected

# -------------------------------------------------------------------
# Function: worker_thread
# -------------------------------------------------------------------
def worker_thread(queue):
    """
    Worker thread that continuously retrieves (ip, port) tasks from the queue,
    queries the target for an Ollama endpoint, and writes valid results to CSV.
    
    Args:
        queue (Queue): The thread-safe queue with (ip, port) tuples.
    """
    while True:
        task = queue.get()
        if task is None:
            # Sentinel value indicating shutdown.
            queue.task_done()
            break

        ip, port = task
        result = query_ollama_endpoints(ip, port)
        if result["valid_ollama"]:
            row = {
                "ip": result["ip"],
                "port": result["port"],
                "ps_url": f"http://{ip}:{port}/api/ps",
                "reachable": result["reachable"],
                "valid_ollama": result["valid_ollama"],
                "ps_data": json.dumps(result["ps_data"]),
                "system_data": json.dumps(result["system_data"]),
                "error": result["error"]
            }
            with csv_lock:
                csv_writer.writerow(row)
                csv_file_handle.flush()
            print(f"[+] Found model(s)! Valid Ollama at: {ip}:{port}")
        queue.task_done()

# -------------------------------------------------------------------
# Function: masscan_streaming_scan
# -------------------------------------------------------------------
def masscan_streaming_scan():
    """
    Runs masscan with specified parameters and streams JSON output.
    Enqueues each discovered (ip, port) for further validation by worker threads.
    """
    ports_str = ",".join(map(str, PORTS_TO_SCAN))
    cmd = [
        "masscan",
        "-p", ports_str,
        TARGET_RANGE,
        "--rate", str(MASSCAN_RATE),
        "--wait", "5",
        "-oJ", "-"
    ]
    # Append exclusion subnets to the command.
    for subnet in COMMON_GOVERNMENT_SUBNETS:
        cmd += ["--exclude", subnet]

    print(f"[+] Starting masscan with: {' '.join(cmd)}")
    print(f"[+] Worker threads: {NUM_WORKER_THREADS}")
    print(f"[+] Saving valid hosts (with models) to: {CSV_FILENAME}")

    # Create a Queue and launch worker threads.
    q = Queue()
    threads = []
    for _ in range(NUM_WORKER_THREADS):
        t = threading.Thread(target=worker_thread, args=(q,), daemon=True)
        t.start()
        threads.append(t)

    # Execute masscan and process its JSON output line by line.
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as proc:
        for line in proc.stdout:
            line = line.strip()
            if not line or line in ["[", "]", ","]:
                continue
            # Remove trailing commas.
            if line.endswith(","):
                line = line[:-1].strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ip = obj.get("ip")
                ports_info = obj.get("ports", [])
                if not ip or not ports_info:
                    continue
                # Enqueue each discovered port.
                for pinfo in ports_info:
                    port = pinfo.get("port")
                    if port:
                        q.put((ip, port))
        # Process any error output from masscan.
        _, err_output = proc.communicate()
        if err_output:
            print("[!] masscan stderr:", err_output)

    # Send a sentinel (None) to each worker thread to signal termination.
    for _ in range(NUM_WORKER_THREADS):
        q.put(None)
    q.join()
    for t in threads:
        t.join()

    print("[+] Scanning & processing complete.")

# -------------------------------------------------------------------
# Main function
# -------------------------------------------------------------------
def main():
    """
    Main entry point for the scanner. Initiates the masscan streaming scan.
    """
    masscan_streaming_scan()

if __name__ == "__main__":
    main()
    # Close the CSV file after scanning is complete.
    csv_file_handle.close()
