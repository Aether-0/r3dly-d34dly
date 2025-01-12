# R3DLY-D34DLY - Fast Passive IP Scanner Tool

![R3DLY-D34DLY Logo](logo.png)  
*Logo: A sleek, futuristic design with glowing text "R3DLY-D34DLY" and a radar-like animation.*

R3DLY-D34DLY is a powerful and efficient Go-based tool designed for passive scanning of IP addresses and domains. It leverages Shodan and IPInfo APIs to gather detailed information about IPs, including hostnames, geolocation, open ports, and vulnerabilities. The tool is ideal for security researchers, network administrators, and anyone interested in IP intelligence.

---

## Features

- **IP Scanning**: Scan single IPs, lists of IPs, or IPs from a file.
- **Domain Resolution**: Resolve domains and scan associated IPs.
- **API Integration**: Fetch data from Shodan and IPInfo APIs.
- **Concurrency**: Limit concurrent scans for efficient resource usage.
- **Retry Mechanism**: Automatically retry failed API requests.
- **Private IP Filtering**: Exclude private IP addresses from results.
- **User-Agent Randomization**: Randomize User-Agent headers to avoid detection.
- **Formatted Output**: Display results in a clean, color-coded table.
- **Output to File**: Save results to a file for later analysis.

---

## Installation

1. **Install Go**: Ensure you have Go installed on your system. You can download it from [here](https://golang.org/dl/).

2. **Clone the Repository**:
   ```bash
   git clone https://github.com/Aether-0/r3dly-d34dly.git
   cd r3dly-d34dly
   ```

3. **Build the Tool**:
   ```bash
   go build -o r3dly-d34dly
   ```

4. **Run the Tool**:
   ```bash
   ./r3dly-d34dly -ip 8.8.8.8
   ```

---

## Usage

### Command-Line Arguments

| Argument           | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| `-ip`              | Scan a single IP address (e.g., `8.8.8.8`).                                |
| `-list`            | Scan a comma-separated list of IPs (e.g., `8.8.8.8,1.1.1.1`).              |
| `-file`            | Scan IPs from a file (e.g., `ips.txt`).                                    |
| `-domain`          | Resolve a domain and scan associated IPs (e.g., `example.com`).            |
| `-output`          | Save results to a file (e.g., `results.txt`).                              |
| `-retry-attempts`  | Set the number of retry attempts for failed requests (default: `5`).       |
| `-retry-wait`      | Set the wait time between retry attempts (default: `2s`).                  |
| `-concurrency`     | Set the number of concurrent scans (default: `10`).                        |

### Examples

1. **Scan a Single IP**:
   ```bash
   ./r3dly-d34dly -ip 8.8.8.8
   ```

2. **Scan a List of IPs**:
   ```bash
   ./r3dly-d34dly -list "8.8.8.8,1.1.1.1"
   ```

3. **Scan IPs from a File**:
   ```bash
   ./r3dly-d34dly -file ips.txt
   ```

4. **Scan IPs Associated with a Domain**:
   ```bash
   ./r3dly-d34dly -domain example.com
   ```

5. **Save Results to a File**:
   ```bash
   ./r3dly-d34dly -ip 8.8.8.8 -output results.txt
   ```

---

## Configuration

### IPInfo API Key
To use the IPInfo API, you need an API key. Save your key in a file at `/opt/.ipinfo.api`:
```bash
echo "your_api_key_here" > /opt/.ipinfo.api
```

---

## Output Example

*Example output showing IP details in a formatted table.*

```
               ____        __            ____    
   _______ ___/ / /_ _____/ /__ ___ ____/ / /_ __
  / __/ -/) _  / / // / _  / -/) _ `/ _  / / // /
 /_/  \__/\_,_/_/\_, /\\_,_/\\__/\\_,_/\\_,_/_/\\_, / 
                /___/                     /___/   
      R3DLY-D34DLY - Fast Passive IP Scanner Tool
      Author : Aether

[!] WARNING: This data is from Shodan and IPInfo. Vulnerabilities listed are not confirmed.

IP Details: 8.8.8.8
==================================================
Hostnames       : dns.google
City            : Mountain View
Region          : California
Country         : US
Org             : Google LLC
Ports           : 53, 443
Vulns           : CVE-2021-1234, CVE-2021-5678
==================================================
```

---

## Contributing

Contributions are welcome! If you have any suggestions, bug reports, or feature requests, feel free to open an issue or submit a pull request.

---

## License

This project is licensed under the **MTFK CPC (Mother Fucker Copy Cat)** License.  
Basically, do whatever the fuck you want, but don't be a copycat.  

---

## Contact

For questions or feedback, reach out to me on Telegram: [@k4b00m3](https://t.me/k4b00m3).

---

Happy Scanning! 🚀
