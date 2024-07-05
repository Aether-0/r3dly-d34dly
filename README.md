# REDLY-DEADLY

## Overview

**REDLY-DEADLY** is an IP scanner tool powered by Shodan, designed to fetch and display detailed information about IP addresses, including vulnerabilities and exploits related to CVEs. This tool is written in Python and utilizes several libraries, including `aiohttp` for asynchronous HTTP requests, `tenacity` for retry strategies, and `rich` for beautiful console output.

## Features

- Fetch IP data from Shodan and IPInfo.
- Display CVE details along with related exploits from GitHub and Exploit DB.
- Retry strategy for robust data fetching.
- Beautifully formatted output using the `rich` library.

## Installation

1. **Clone the repository**:
    ```sh
    git clone https://github.com/Aether-0/r3dly-d34dly.git
    cd r3dly-d34dly/
    ```

2. **Install dependencies**:
    ```sh
    pip install -r requirements.txt
    ```

3. **Set up IPInfo API Key** (optional):
    If you have an IPInfo API key, save it in a file named `.ipinfo.api` in the root directory.

## Usage

### Command-line Arguments

- `-i`, `--ip`: Single IP address to scan.
- `-l`, `--list`: Comma-separated list of IP addresses to scan.
- `-f`, `--file`: File containing a list of IP addresses to scan.
- `--retry-attempts`: Number of retry attempts for fetching data (default: 5).
- `--retry-wait`: Wait time between retry attempts in seconds (default: 2).

### Examples

1. **Scan a single IP address**:
    ```sh
   ./redly -i 8.8.8.8
    ```

2. **Scan multiple IP addresses**:
    ```sh
    ./redly -l 8.8.8.8,1.1.1.1
    ```

3. **Scan IP addresses from a file**:
    ```sh
    ./redly -f ip_list.txt
    ```

## Output

The output is beautifully formatted using the `rich` library, displaying the following details:

- IP address details including open ports, hostnames, organization, location, etc.
- CVE details including summary, ranking, published time, and related exploits from GitHub and Exploit DB.

## Banner

Upon execution, the tool displays a banner with the tool name, author information, and links to the author's Telegram and GitHub.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Author

- **Aether**
    - **Telegram**: [@a37h3r](https://t.me/a37h3r)
    - **GitHub**: [Aether-0](https://github.com/Aether-0)

---

Enjoy using REDLY-DEADLY! If you have any questions or feedback, feel free to reach out via Telegram or GitHub.
