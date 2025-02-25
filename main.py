#!/usr/bin/env python3
"""
Ollama Instance Scanner with Progress Display
Optimized script to scan the IPv4 space for Ollama instances with a progress bar.
Uses asyncio and aiohttp for improved concurrency in HTTP requests.
"""

import asyncio
import json
import csv
import os
import time
import aiohttp
import asyncio.subprocess as aiosubprocess
from aiohttp import ClientSession, ClientTimeout
from ips import get_ips_from_file
from tqdm.asyncio import tqdm

# -------------------------------------------------------------------
# Exclusion Subnets: Government and Private Networks
# -------------------------------------------------------------------
COMMON_GOVERNMENT_SUBNETS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
]
IPS_FILE = "IP2LOCATION-LITE-DB1.NEW.CSV"
TARGET_RANGE_LIST = get_ips_from_file(IPS_FILE)

# -------------------------------------------------------------------
# Configurable Parameters
# -------------------------------------------------------------------
NUM_WORKER_THREADS = 500
HTTP_TIMEOUT = 2
MASSCAN_RATE = 500000
TARGET_RANGE = "0.0.0.0/0"
PORTS_TO_SCAN = [11434]
CSV_FILENAME = f"ollama_scan_results_{int(time.time())}.csv"

# -------------------------------------------------------------------
# CSV Writer Setup: Thread-Safe CSV Writing
# -------------------------------------------------------------------
csv_lock = asyncio.Lock()

def get_csv_writer():
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
async def query_ollama_endpoints(session: ClientSession, ip: str, port: int):
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

    try:
        ps_url = f"{base_url}/api/ps"
        async with session.get(ps_url, timeout=HTTP_TIMEOUT) as response:
            if response.status == 200:
                data_collected["reachable"] = True
                try:
                    ps_json = await response.json()
                    data_collected["ps_data"] = ps_json
                    if "models" in ps_json and isinstance(ps_json["models"], list) and ps_json["models"]:
                        data_collected["valid_ollama"] = True
                except ValueError:
                    pass
    except Exception as e:
        data_collected["error"] = str(e)

    if data_collected["valid_ollama"]:
        try:
            sys_url = f"{base_url}/api/system"
            async with session.get(sys_url, timeout=HTTP_TIMEOUT) as sys_response:
                if sys_response.status == 200:
                    try:
                        data_collected["system_data"] = await sys_response.json()
                    except ValueError:
                        pass
        except Exception:
            pass

    return data_collected

# -------------------------------------------------------------------
# Function: masscan_streaming_scan
# -------------------------------------------------------------------
async def masscan_streaming_scan(target_range, progress_bar):
    ports_str = ",".join(map(str, PORTS_TO_SCAN))
    cmd = [
        "masscan",
        "-p", ports_str,
        target_range,
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

    process = await aiosubprocess.create_subprocess_exec(
        *cmd, stdout=aiosubprocess.PIPE, stderr=aiosubprocess.PIPE
    )

    count = 0  # Initialize IP counter for progress tracking
    async for line in process.stdout:
        line = line.decode().strip()
        if line and line.startswith("{") and line.endswith("}"):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = obj.get("ip")
            ports_info = obj.get("ports", [])
            if ip and ports_info:
                for pinfo in ports_info:
                    port = pinfo.get("port")
                    if port:
                        await process_task(ip, port)
            count += 1
            progress_bar.update(1)  # Update progress bar for each processed IP

    _, err_output = await process.communicate()
    if err_output:
        print("[!] masscan stderr:", err_output)

    print("[+] Scanning & processing complete.")

# -------------------------------------------------------------------
# Function: process_task
# -------------------------------------------------------------------
async def process_task(ip, port):
    async with ClientSession(timeout=ClientTimeout(total=HTTP_TIMEOUT)) as session:
        result = await query_ollama_endpoints(session, ip, port)
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
            async with csv_lock:
                csv_writer.writerow(row)
                csv_file_handle.flush()
            print(f"[+] Found model(s)! Valid Ollama at: {ip}:{port}")

# -------------------------------------------------------------------
# Main function with Progress Bar
# -------------------------------------------------------------------
async def main():
    total_ranges = len(TARGET_RANGE_LIST)
    # Create the progress bar for scanning IP ranges
    async with tqdm(total=total_ranges, desc="Scanning IP Ranges") as progress_bar:
        for target_range in TARGET_RANGE_LIST:
            await masscan_streaming_scan(target_range, progress_bar)

if __name__ == "__main__":
    asyncio.run(main())
    csv_file_handle.close()
