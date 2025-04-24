# PMAPD: A Passive-enhanced Multi-level Aliased Prefix Detection Approach for IPv6 Scanning
This project implements a PMAPD demo for detecting IPv6 aliased prefixes. Aliasing occurs when multiple addresses appear to belong to the same host or shared infrastructure, hindering accurate network mapping. This tool aims to identify such prefixes using a combination of passive analysis of scan results and active probing.

## Features
*   **Multi-level Aliased Prefix Detection:** Performs alias detection across multiple IPv6 prefix lengths (plens). The method conceptually checks prefixes from a potential BGP prefix length up to /112 bits, in steps of 4 bits. *Note: In the demo, the implementation simplifies the initial 'BGP prefix length' lookup and performs detection across the fixed range of /32 to /112 bits.*
*   **Passive Aliased Prefix Detection:** Analyzes collected scan data (host reachability, port fingerprints, SSH keys) to statistically identify prefixes that show characteristics inconsistent with typical single hosts.
*   **Active Aliased Prefix Detection:** Probes random addresses within "uncertain" prefixes to gather further evidence and make a final determination on whether a prefix is aliased.
*   **Online Filtering:** Skips scanning targets whose prefixes are already known to be aliased, reducing unnecessary network traffic.
*   **Offline Filtering:** Processes the final set of alive hosts to filter out duplicates arising from aliases, providing a list of potentially unique hosts and representative IPs for aliased prefixes.
*   **Integration with Standard Tools:** Leverages `masscan` for fast host and port scanning, and `ssh-keyscan` for collecting SSH host keys.
*   **Redis Integration:** Uses a Redis database to store scan results and identified aliased/non-aliased prefixes efficiently.

## Requirements

*   Python 3.x
*   Redis Server (running and accessible on `localhost:6379` by default)
*   `masscan` (installed and configured, potentially requiring root privileges or capabilities)
*   `ssh-keyscan` (part of OpenSSH, usually available on Linux/macOS)
*   Required Python Libraries:
    *   `redis` (`pip install redis`)
*   A network interface configured with a specific MAC address, as required by `masscan` for sending packets (configured via `MAC_ADDR` and `INT_NAME` in `scanner.py`).

## Installation & Setup

1.  **Clone the repository:** (Assuming this code will be in a repository)
    ```bash
    git clone <repository_url>
    cd pmapd
    ```
2.  **Install Python dependencies:**
    ```bash
    pip install redis
    ```
3.  **Install external tools:**
    *   Install `masscan`: Follow instructions for your OS (e.g., `sudo apt-get install masscan` on Debian/Ubuntu). Ensure it's configured correctly and you have the necessary privileges to run it.
    *   Install Redis Server: Follow instructions for your OS (e.g., `sudo apt-get install redis-server`).
4.  **Start Redis Server:** Ensure the Redis server is running.
    ```bash
    redis-server
    ```
    (Or use your system's service manager, e.g., `sudo systemctl start redis-server`).
5.  **Configure `scanner.py`:** **This is crucial.** Edit `scanner.py` and update `MAC_ADDR` and `INT_NAME` variables to match your network interface and desired source MAC address for scanning.
    ```python
    MAC_ADDR = "your:interface:mac:address" # e.g., "00:1A:2B:3C:4D:5E"
    INT_NAME = "your_interface_name"      # e.g., "eth0", "enp179s0f1"
    ```
    *Note: Running `masscan --ping` requires root privileges.*

## Usage

The `example.py` script provides a demonstration of how to use the `pmapd` and `scanner` modules.

1.  **Targets:** The `example.py` script expects input target lists in files named `tga[1-2]/rnd{i}_targets10k.txt` for `i` from 0 to 5.
2.  **Run the example script:**
    ```bash
    sudo python example.py
    ```

The script will:
*   Load targets in rounds.
*   Filter targets online based on already detected aliases.
*   Perform host scans (`scan` with `task_type='host'`) on the filtered targets.
*   Perform Aliased Prefix Detection (`alias_detect`) based on the scan results, potentially triggering active probes.
*   Collect alive IPs.
*   After all rounds, perform offline filtering on the collected alive IPs to distinguish unique hosts from aliases.
*   Print the detected aliased and non-aliased prefixes.
*   Print the results of the offline filtering (dealiased IPs and aliased prefixes matched).

You can also integrate the `scan`, `alias_detect`, `filter_online`, and `filter_offline` functions with your own target generation algorithms (TGAs).

## Code Structure

*   `scanner.py`: Handles the interaction with external scanning tools (`masscan`, `ssh-keyscan`) and stores raw scan results in Redis.
*   `pmapd.py`: Contains the core logic for passive and active Aliased Prefix Detection, prefix management, and online/offline filtering. It reads data from Redis.
*   `example.py`: A sample script demonstrating how to use the `scanner` and `pmapd` modules together.

## dataset
A dataset of discovered aliased prefixes `dataset/aliased_prefix.txt` is included in this repository. This file contains a list of IPv6 prefixes that were identified as aliased during a large-scale IPv6 address scanning process conducted in October 2024.