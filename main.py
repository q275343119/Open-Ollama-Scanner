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
from sqlalchemy import select

import asyncio.subprocess as aiosubprocess
from aiohttp import ClientSession, ClientTimeout
from tqdm import tqdm

from database import FreeOllama, get_db
from ips import get_ips_from_file

# -------------------------------------------------------------------
# Exclusion Subnets: Government and Private Networks
# -------------------------------------------------------------------
COMMON_GOVERNMENT_SUBNETS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
]
IPS_FILE = "IP2LOCATION-LITE-DB1.NEW.CSV"
TARGET_RANGE_LIST = list(get_ips_from_file(IPS_FILE))  # Load all IPs into memory
# TARGET_RANGE_LIST = ['1.68.0.0/14']
# -------------------------------------------------------------------
# Configurable Parameters
# -------------------------------------------------------------------
NUM_WORKER_THREADS = 500
HTTP_TIMEOUT = 5
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


# -------------------------------------------------------------------
# Function: extract_model_ids
# -------------------------------------------------------------------
def extract_model_ids(data_dict):
    """
    提取字典中 'data' 列表中的所有 'id' 值。

    Args:
        data_dict (dict): 包含 'data' 列表的字典。

    Returns:
        list: 包含所有 'id' 的列表。
    """
    ids = []
    if 'data' in data_dict and isinstance(data_dict['data'], list):
        for item in data_dict['data']:
            if isinstance(item, dict) and 'id' in item:
                ids.append(item['id'])
    return ids


# -------------------------------------------------------------------
# Function: query_ollama_endpoints
# -------------------------------------------------------------------
async def query_ollama_endpoints(session: ClientSession, ip: str, port: int):
    base_url = f"http://{ip}:{port}"
    try:
        ps_url = f"{base_url}/v1/models"
        async with session.get(ps_url, headers={"User-Agent": "PostmanRuntime-ApipostRuntime/1.1.0"},
                               timeout=HTTP_TIMEOUT) as response:

            if response.status == 200:
                data = await response.json()
                model_list = extract_model_ids(data)
                if model_list:
                    models = ";".join(model_list)
                    return FreeOllama(ip=ip, models=models)

    except Exception as e:
        print(e)
        return None
    return None


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
        "--wait", "2",
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
        pass
    # print("[!] masscan stderr:", err_output)

    print("[+] Scanning & processing complete.")


# -------------------------------------------------------------------
# Function: process_task
# -------------------------------------------------------------------
async def process_task(ip, port):
    print("process_task")
    async with ClientSession(timeout=ClientTimeout(total=HTTP_TIMEOUT)) as session:
        po = await query_ollama_endpoints(session, ip, port)
        if po:
            async for session in get_db():
                try:
                    # 更新已存在的记录
                    stmt = select(FreeOllama).where(FreeOllama.ip == po.ip)
                    result = await session.execute(stmt)
                    existing_po = result.scalar_one()
                    if len(existing_po) > 0:
                        existing_po.models = po.models  # 只更新models字段
                    else:
                        po.active = 1  # 新记录默认为活跃状态
                        session.add(po)
                    await session.commit()
                except Exception as e:
                    raise e

            print(f"[+] Found model(s)! Valid Ollama at: {ip}:{port}")


# -------------------------------------------------------------------
# Main function with Progress Bar
# -------------------------------------------------------------------
async def main():
    total_ranges = len(TARGET_RANGE_LIST)  # Calculate the total number of IP ranges
    progress_bar = tqdm(total=total_ranges, desc="Scanning IP Ranges")
    async with asyncio.TaskGroup() as tg:
        for target_range in TARGET_RANGE_LIST:
            tg.create_task(masscan_streaming_scan(target_range, progress_bar))
    progress_bar.close()


if __name__ == "__main__":
    asyncio.run(main())
