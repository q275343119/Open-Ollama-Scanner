# Ollama Instance Scanner

This Python script leverages [masscan](https://github.com/robertdavidgraham/masscan) to perform a streaming scan of the entire IPv4 address space (with exclusions) and then queries discovered hosts to determine if they are running an [Ollama](https://ollama.com/) endpoint. Ollama is a tool for running local AI models, and this scanner specifically checks for active Ollama instances by accessing the `/api/ps` endpoint (and optionally `/api/system` if models are detected).

Upon using this script, over 600 running Ollama instances have been discovered—including those hosting the latest AI models (e.g., DeepSeek’s latest, largest model) running on high-end (likely company) hardware. These models are completely insecure and a huge cause for concern in my personal opinion. I'm hoping that by releasing this companies will begin securing their Ollama instances instead of leaving them open like this.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Output](#output)
- [Disclaimer](#disclaimer)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **Internet-Scale Scanning:** Uses masscan to scan the entire IPv4 space (with configurable exclusions).
- **Ollama Endpoint Detection:** For each discovered host and port, the script sends HTTP GET requests to `/api/ps` and, if valid, optionally to `/api/system`.
- **Multi-Threaded Processing:** Employs 500 worker threads (configurable) to handle concurrent HTTP queries.
- **Thread-Safe CSV Logging:** Saves details of valid Ollama instances (reachable status, JSON responses, errors) to a CSV file.
- **Customizable Parameters:** Easily configurable scanning parameters, target ranges, ports, HTTP timeout, and masscan rate.
- **Exclusion Lists:** Automatically excludes common government subnets and private RFC1918 ranges from scans.

---

## Requirements

- **Python 3.x**  
- **Masscan** (must be installed and accessible via the command line)  
- Python libraries:
  - `requests`
  - `json`
  - `csv`
  - `subprocess`
  - `os`
  - `time`
  - `threading`
  - `queue`

---

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/maxmoodycyber/Open-Ollama-Scanner.git
   cd Open-Ollama-Scanner
   ```

2. **(Optional) Create a Virtual Environment:**

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Python Dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

   *(If a `requirements.txt` is not provided, ensure you have the `requests` package installed via `pip install requests`.)*

4. **Install masscan:**

   Follow the instructions on the [masscan GitHub page](https://github.com/robertdavidgraham/masscan) for your operating system. Ensure masscan is in your system’s PATH.

---

## Configuration

The script’s configurable parameters are defined at the top of the file. You can adjust these to suit your needs:

- **Common Government & Private Subnets:**  
  The script excludes specified subnets (e.g., US DoD ranges, RFC1918 private networks) to prevent scanning sensitive or non-public ranges. I have added these as a base but I highly recommend configuring to your needs.

- **Worker Threads:**  
  `NUM_WORKER_THREADS = 500`  
  Adjust the number of concurrent threads handling HTTP queries.

- **HTTP Timeout:**  
  `HTTP_TIMEOUT = 2` (seconds)  
  Sets the timeout for each Ollama query.

- **Masscan Rate:**  
  `MASSCAN_RATE = 500000` (packets per second)  
  Tweak based on your network and hardware capabilities.

- **Target Range:**  
  `TARGET_RANGE = "0.0.0.0/0"`  
  Defines the IPv4 address range to scan. **Warning:** Scanning the entire IPv4 space is extensive and may be subject to legal restrictions.

- **Ports to Scan:**  
  `PORTS_TO_SCAN = [11434]`  
  By default, scans Ollama’s default port. Add more ports if necessary.

- **CSV Filename:**  
  Automatically generated based on the current timestamp (e.g., `ollama_scan_results_<timestamp>.csv`).

---

## Usage

Simply run the script from the command line:

```bash
python3 ollama_scanner.py
```

The script will:

1. Invoke masscan with the defined parameters.
2. Stream JSON output from masscan.
3. For each discovered IP:port, enqueue a task to query the Ollama endpoints.
4. Check if the `/api/ps` endpoint returns a valid JSON with at least one model (i.e., a valid Ollama instance).
5. Optionally query `/api/system` if the instance is valid.
6. Write results to a CSV file and print discovered instances to the console.

---

## Output

- **CSV File:**  
  Valid Ollama instances are logged in a CSV file (e.g., `ollama_scan_results_<timestamp>.csv`) containing:
  - IP address
  - Port number
  - URL of the `/api/ps` endpoint
  - Reachability status
  - Validity flag (whether a valid Ollama model is detected)
  - JSON response from `/api/ps`
  - JSON response from `/api/system`
  - Any error messages

- **Console Logging:**  
  The script prints a message to the console when a valid Ollama instance is discovered, e.g.,  
  `[+] Found model(s)! Valid Ollama at: 192.168.1.100:11434`

---

## Disclaimer

**Warning:**  
This tool is intended for use on networks for which you have explicit permission to scan. Unauthorized scanning of networks or systems may be illegal and subject to severe penalties. Use responsibly and ethically.

---

## Contributing

Contributions, bug reports, and feature requests are welcome. Please open an issue or submit a pull request on GitHub.

---

*Developed with inspiration from the masscan project and Ollama’s innovative approach to local AI model management. Credit to AI models for filling in my knowledge gaps which there are lots of.*
