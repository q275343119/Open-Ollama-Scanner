#!/usr/bin/env python3
"""
Ollama Instance Scanner with Progress Display
Optimized script to scan the IPv4 space for Ollama instances with a progress bar.
Uses asyncio and aiohttp for improved concurrency in HTTP requests.
"""

import asyncio
import json
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

MAX_CONCURRENT_TASKS = 10
# -------------------------------------------------------------------
# Configurable Parameters
# -------------------------------------------------------------------
NUM_WORKER_THREADS = 500
HTTP_TIMEOUT = 5
MASSCAN_RATE = 500000
TARGET_RANGE = "0.0.0.0/0"
PORTS_TO_SCAN = [11434]

# -------------------------------------------------------------------
# CSV Writer Setup: Thread-Safe CSV Writing
# -------------------------------------------------------------------
# csv_lock = asyncio.Lock()


# -------------------------------------------------------------------
# Function: extract_model_ids
# -------------------------------------------------------------------
def extract_model_ids(data_dict):
    """
    提取字典中 'data' 列表中的所有 'id' 值。
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
                    return FreeOllama(ip=f"{ip}:{port}", models=models)

    except Exception as e:
        return None
    return None


# -------------------------------------------------------------------
# Function: masscan_streaming_scan
# -------------------------------------------------------------------
async def masscan_streaming_scan(target_range, progress_bar,semaphore):
    async with semaphore:
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

        process = await aiosubprocess.create_subprocess_exec(
            *cmd, stdout=aiosubprocess.PIPE, stderr=aiosubprocess.PIPE
        )

        # Initialize IP counter for progress tracking
        tasks = []  # Collect tasks here
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
                            # Gather all process_task functions to execute concurrently
                            tasks.append(process_task(ip, port))


        # Run all tasks concurrently
        if tasks:
            await asyncio.gather(*tasks)

        _, err_output = await process.communicate()
        if err_output:
            pass
        # print("[!] masscan stderr:", err_output)

        progress_bar.update(1)


# -------------------------------------------------------------------
# Function: process_task
# -------------------------------------------------------------------
async def process_task(ip, port):
    async with ClientSession(timeout=ClientTimeout(total=HTTP_TIMEOUT)) as session:
        po = await query_ollama_endpoints(session, ip, port)
        if po:
            async for session in get_db():
                try:
                    # 更新已存在的记录
                    stmt = select(FreeOllama).where(FreeOllama.ip == po.ip)
                    result = await session.execute(stmt)
                    existing_po = result.one_or_none()
                    if existing_po:
                        existing_po[0].models = po.models  # 只更新models字段
                        existing_po[0].active = 1
                    else:
                        po.active = 1  # 新记录默认为活跃状态
                        session.add(po)
                    await session.commit()
                except Exception as e:
                    return None

            print(f"[+] Found model(s)! Valid Ollama at: {ip}:{port}")


# -------------------------------------------------------------------
# Main function with Progress Bar
# -------------------------------------------------------------------
async def main():
    total_ranges = len(TARGET_RANGE_LIST)  # Calculate the total number of IP ranges
    progress_bar = tqdm(total=total_ranges, desc="Scanning IP Ranges")

    # Create a semaphore to limit concurrent tasks
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_TASKS)

    tasks = []
    for idx,target_range in enumerate(TARGET_RANGE_LIST):

        tasks.append(masscan_streaming_scan(target_range, progress_bar,semaphore))
        if idx % 100 == 0:
            if tasks:
                await asyncio.gather(*tasks)
                tasks.clear()
    else:
        if tasks:
            await asyncio.gather(*tasks)
    progress_bar.close()


if __name__ == "__main__":
    asyncio.run(main())

