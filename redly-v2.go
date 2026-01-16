package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ANSI color codes for styling output
const (
	ResetColor   = "\033[0m"
	RedColor     = "\033[31m"
	GreenColor   = "\033[32m"
	BlueColor    = "\033[34m"
	CyanColor    = "\033[36m"
	YellowColor  = "\033[33m"
	MagentaColor = "\033[35m"
)

var (
	retryAttempts = 5
	retryWait     = 2 * time.Second
	ipinfoAPIKey  string
	client        = &http.Client{Timeout: 5 * time.Second}
	outputFile    string
	concurrency   = 10
)

// User Agents for randomization
var userAgents = []string{
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/122.0",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) Firefox/122.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15) Firefox/122.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0.2210.133",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Edge/120.0.2210.133",
	"Mozilla/5.0 (X11; Linux x86_64) Edge/120.0.2210.133",
}

func init() {
	// Load API key for IP info (optional)
	if data, err := os.ReadFile("/opt/.ipinfo.api"); err == nil {
		ipinfoAPIKey = strings.TrimSpace(string(data))
	}
}

// Fetch data from a URL with retries
func fetchData(ctx context.Context, url string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Randomize User-Agent
	req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])

	// Retry mechanism
	for i := 0; i < retryAttempts; i++ {
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			data, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read response body: %w", err)
			}
			return data, nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(retryWait):
		}
	}
	return nil, fmt.Errorf("failed to fetch data from %s after %d attempts", url, retryAttempts)
}

// Fetch IP data from Shodan and IPInfo APIs
func fetchIPData(ctx context.Context, ip string) (map[string]interface{}, error) {
	shodanURL := fmt.Sprintf("https://internetdb.shodan.io/%s", ip)
	ipinfoURL := fmt.Sprintf("https://ipinfo.io/%s/json", ip)

	var result = make(map[string]interface{})
	if shodanData, err := fetchData(ctx, shodanURL, nil); err == nil {
		if err := json.Unmarshal(shodanData, &result); err != nil {
			log.Printf("Failed to unmarshal Shodan data for %s: %v", ip, err)
		}
	}

	headers := make(map[string]string)
	if ipinfoAPIKey != "" {
		headers["Authorization"] = "Bearer " + ipinfoAPIKey
	}

	if ipinfoData, err := fetchData(ctx, ipinfoURL, headers); err == nil {
		var ipInfo map[string]interface{}
		if err := json.Unmarshal(ipinfoData, &ipInfo); err != nil {
			log.Printf("Failed to unmarshal IPInfo data for %s: %v", ip, err)
		} else {
			for k, v := range ipInfo {
				result[k] = v
			}
		}
	}

	return result, nil
}

// Fetch IPs associated with a domain using Shodan search
func fetchIPsFromDomainSearch(ctx context.Context, domain string) ([]string, error) {
	encodedQuery := url.QueryEscape(fmt.Sprintf("Ssl.cert.subject.CN:'%s' 200", domain))
	shodanURL := fmt.Sprintf("https://www.shodan.io/search/facet?query=%s&facet=ip", encodedQuery)

	data, err := fetchData(ctx, shodanURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch IPs from Shodan search: %w", err)
	}

	// Extract IP addresses from the response
	ipRegex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ips := ipRegex.FindAllString(string(data), -1)

	// Filter out private IPs
	var validIPs []string
	for _, ip := range ips {
		if !isPrivateIP(ip) {
			validIPs = append(validIPs, ip)
		}
	}

	return validIPs, nil
}

// Fetch IPs associated with a domain using Shodan geoping API
func fetchIPsFromGeoping(ctx context.Context, domain string) ([]string, error) {
	geopingURL := fmt.Sprintf("https://geonet.shodan.io/api/geoping/%s", domain)
	data, err := fetchData(ctx, geopingURL, map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch IPs from geoping API: %w", err)
	}

	var geopingData []struct {
		IP      string                 `json:"ip"`
		IsAlive bool                   `json:"is_alive"`
		FromLoc map[string]interface{} `json:"from_loc"`
	}
	if err := json.Unmarshal(data, &geopingData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal geoping data: %w", err)
	}

	var validIPs []string
	for _, entry := range geopingData {
		if entry.IsAlive && !isPrivateIP(entry.IP) {
			validIPs = append(validIPs, entry.IP)
		}
	}

	return validIPs, nil
}

// Fetch IPs associated with a domain, trying search first then geoping
func fetchIPsFromDomain(ctx context.Context, domain string) ([]string, error) {
	ips, err := fetchIPsFromDomainSearch(ctx, domain)
	if err != nil || len(ips) == 0 {
		log.Printf("No IPs found via Shodan search for %s, trying geoping API", domain)
		geopingIPs, err2 := fetchIPsFromGeoping(ctx, domain)
		if err2 != nil {
			return nil, fmt.Errorf("failed to fetch IPs: search error (%v), geoping error (%v)", err, err2)
		}
		return geopingIPs, nil
	}
	return ips, nil
}

// Fetch IPs from a custom Shodan query
func fetchIPsFromCustomQuery(ctx context.Context, query string) ([]string, error) {
	encodedQuery := url.QueryEscape(query)
	shodanURL := fmt.Sprintf("https://www.shodan.io/search/facet?query=%s&facet=ip", encodedQuery)

	data, err := fetchData(ctx, shodanURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch IPs from custom Shodan query: %w", err)
	}

	// Extract IP addresses from the response
	ipRegex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ips := ipRegex.FindAllString(string(data), -1)

	// Filter out private IPs
	var validIPs []string
	for _, ip := range ips {
		if !isPrivateIP(ip) {
			validIPs = append(validIPs, ip)
		}
	}

	return validIPs, nil
}

// Check if an IP is private
func isPrivateIP(ip string) bool {
	privateIPBlocks := []string{
		"0.", "127.", "169.254.", "172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
		"172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
		"192.168.", "10.", "224.", "240.",
	}
	for _, block := range privateIPBlocks {
		if strings.HasPrefix(ip, block) {
			return true
		}
	}
	return false
}

// Display the custom banner for the tool
func displayBanner() {
	fmt.Printf("%s", RedColor)
	fmt.Printf(` 
 ____  ____  ____  __    _  _     ____  ____   __   ____  __    _  _ 
(  _ \(  __)(    \(  )  ( \/ )___(    \(  __) / _\ (    \(  )  ( \/ )
 )   / ) _)  ) D (/ (_/\ )  /(___)) D ( ) _) /    \ ) D (/ (_/\ )  / 
(__\_)(____)(____/\____/(__/     (____/(____)\_/\_/(____/\____/(__/  
`)
	fmt.Printf("%s    \nR3DLY-D34DLY - Fast Passive IP Scanner Tool\n", CyanColor)
	fmt.Printf("GitHub  : github.com/Aether-0\n")
	fmt.Printf("Version : 2.0\n")
	fmt.Printf("Author  : Aether\n%s\n", ResetColor)
	fmt.Println(strings.Repeat("═", 91))
	fmt.Printf("%s[!] WARNING: This data is from Shodan and IPInfo. Vulnerabilities listed are not confirmed.%s\n", YellowColor, ResetColor)
	fmt.Println(strings.Repeat("═", 91))
}

// Display a formatted table for IP or CVE data
func displayTable(title string, data map[string]interface{}, writer io.Writer) {
	fmt.Fprintf(writer, "\n%s%s%s\n", BlueColor, title, ResetColor)
	fmt.Fprintf(writer, "%s\n", strings.Repeat("═", 50))

	formatList := func(items []string) string {
		return strings.Join(items, ", ")
	}

	for k, v := range data {
		switch value := v.(type) {
		case string:
			fmt.Fprintf(writer, "%s%-15s%s : %s\n", CyanColor, k, ResetColor, value)
		case []string:
			fmt.Fprintf(writer, "%s%-15s%s : %s\n", CyanColor, k, ResetColor, formatList(value))
		case []interface{}:
			var strValues []string
			for _, item := range value {
				strValues = append(strValues, fmt.Sprintf("%v", item))
			}
			fmt.Fprintf(writer, "%s%-15s%s : %s\n", CyanColor, k, ResetColor, formatList(strValues))
		default:
			fmt.Fprintf(writer, "%s%-15s%s : %v\n", CyanColor, k, ResetColor, value)
		}
	}
	fmt.Fprintf(writer, "%s\n", strings.Repeat("═", 50))
}

// Scan a single IP address
func scanIP(ctx context.Context, ip string, results chan<- string, wg *sync.WaitGroup, sem chan struct{}) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	if ipData, err := fetchIPData(ctx, ip); err == nil {
		var sb strings.Builder
		displayTable(fmt.Sprintf("IP Details: %s", ip), ipData, &sb)
		results <- sb.String()
	} else {
		log.Printf("Failed to fetch IP data for %s: %v", ip, err)
	}
}

// Main function to initialize scanning and parsing arguments
func main() {
	displayBanner()

	// Parse command-line arguments
	ip := flag.String("ip", "", "Single IP address to scan")
	ipList := flag.String("list", "", "Comma-separated list of IP addresses to scan")
	ipFile := flag.String("file", "", "File containing list of IP addresses to scan")
	domain := flag.String("domain", "", "Domain to resolve and scan associated IPs")
	inputQuery := flag.String("query", "", "Custom Shodan query to fetch IPs (e.g., 'port:80 os:Windows')")
	ipOnly := flag.Bool("ip-only", false, "With --query, print only IPs and exit")
	flag.StringVar(&outputFile, "output", "", "Output file to write results to")
	flag.IntVar(&retryAttempts, "retry-attempts", 5, "Number of retry attempts for fetching data")
	flag.DurationVar(&retryWait, "retry-wait", 2*time.Second, "Wait time between retry attempts")
	flag.IntVar(&concurrency, "concurrency", 10, "Number of concurrent scans")
	flag.Parse()

	// Context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// If ip-only is used with query, handle specially (including output file)
	if *inputQuery != "" {
		log.Printf("Fetching IPs for custom query: %s", *inputQuery)
		queryIPs, err := fetchIPsFromCustomQuery(ctx, *inputQuery)
		if err != nil {
			log.Fatalf("Failed to fetch IPs for custom query '%s': %v", *inputQuery, err)
		}
		if len(queryIPs) == 0 {
			log.Fatalf("No valid IPs found for custom query '%s'", *inputQuery)
		}

		if *ipOnly {
			var file *os.File
			if outputFile != "" {
				file, err = os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
				if err != nil {
					log.Fatalf("Failed to open output file: %v", err)
				}
				defer file.Close()
			}

			for _, ipAddr := range queryIPs {
				if !isPrivateIP(ipAddr) {
					fmt.Println(ipAddr)
					if file != nil {
						if _, err := file.WriteString(ipAddr + "\n"); err != nil {
							log.Printf("Failed to write to output file: %v", err)
						}
					}
				}
			}
			return
		}

		// fall through to normal scanning path with full data
		runScanner(ctx, queryIPs)
		return
	}

	// Normal modes (ip, list, file, domain)
	var ips []string

	if *ip != "" {
		ips = []string{*ip}
	} else if *ipList != "" {
		ips = strings.Split(*ipList, ",")
	} else if *ipFile != "" {
		file, err := os.Open(*ipFile)
		if err != nil {
			log.Fatalf("Failed to open file: %v", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				ips = append(ips, line)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading file: %v", err)
		}
	} else if *domain != "" {
		domainIPs, err := fetchIPsFromDomain(ctx, *domain)
		if err != nil {
			log.Fatalf("Failed to fetch IPs for domain %s: %v", *domain, err)
		}
		if len(domainIPs) == 0 {
			log.Fatalf("No valid IPs found for domain %s", *domain)
		}
		ips = domainIPs
	} else {
		log.Println("Please provide either an IP address, a list of IPs, a file with IPs, a domain, or a custom query.")
		return
	}

	runScanner(ctx, ips)
}

// runScanner handles concurrent scanning and writing results (normal modes)
func runScanner(ctx context.Context, ips []string) {
	// Create a channel to collect results
	results := make(chan string, len(ips))

	// Semaphore to control concurrency
	sem := make(chan struct{}, concurrency)

	// Scan IPs concurrently
	var wg sync.WaitGroup
	for _, ipAddr := range ips {
		if !isPrivateIP(ipAddr) {
			wg.Add(1)
			go scanIP(ctx, ipAddr, results, &wg, sem)
		}
	}

	// Close the channel once all scans are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Write results to output file and display to terminal
	var file *os.File
	var err error
	if outputFile != "" {
		file, err = os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			log.Fatalf("Failed to open output file: %v", err)
		}
		defer file.Close()
	}

	for result := range results {
		fmt.Print(result)
		if file != nil {
			if _, err := file.WriteString(result); err != nil {
				log.Printf("Failed to write to output file: %v", err)
			}
		}
	}
}
