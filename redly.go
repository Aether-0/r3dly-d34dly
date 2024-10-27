package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
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
)

var (
	retryAttempts = 5
	retryWait     = 2 * time.Second
	ipinfoAPIKey  string
	client        = &http.Client{Timeout: 5 * time.Second} // Reduced timeout for faster response
	outputFile    string
)

func init() {
	// Load API key for IP info (optional)
	if data, err := os.ReadFile(".ipinfo.api"); err == nil {
		ipinfoAPIKey = strings.TrimSpace(string(data))
	}
}

// Fetch data from a URL with retries
func fetchData(url string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Retry mechanism
	for i := 0; i < retryAttempts; i++ {
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			// Read and return the response body as bytes
			data, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
			return data, nil
		}
		time.Sleep(retryWait)
	}
	return nil, fmt.Errorf("failed to fetch data from %s", url)
}

// Fetch IP data from Shodan and IPInfo APIs
func fetchIPData(ip string) (map[string]interface{}, error) {
	shodanURL := fmt.Sprintf("https://internetdb.shodan.io/%s", ip)
	ipinfoURL := fmt.Sprintf("https://ipinfo.io/%s/json", ip)

	var result = make(map[string]interface{})
	if shodanData, err := fetchData(shodanURL, nil); err == nil {
		json.Unmarshal(shodanData, &result)
	}

	headers := make(map[string]string)
	if ipinfoAPIKey != "" {
		headers["Authorization"] = "Bearer " + ipinfoAPIKey
	}

	if ipinfoData, err := fetchData(ipinfoURL, headers); err == nil {
		var ipInfo map[string]interface{}
		json.Unmarshal(ipinfoData, &ipInfo)
		for k, v := range ipInfo {
			result[k] = v
		}
	}

	return result, nil
}

// Display the custom banner for the tool
func displayBanner() {
	fmt.Printf("%s", RedColor)
	fmt.Println("               ____        __            ____    ")
	fmt.Println("   _______ ___/ / /_ _____/ /__ ___ ____/ / /_ __")
	fmt.Println("  / __/ -/) _  / / // / _  / -/) _ `/ _  / / // /")
	fmt.Println(" /_/  \\__/\\_,_/_/\\_, /\\_,_/\\__/\\_,_/\\_,_/_/\\_, / ")
	fmt.Println("                /___/                     /___/   ")
	fmt.Printf("%s      R3DLY-D34DLY - Fast Passive IP Scanner Tool\n", CyanColor)
	fmt.Printf("      Author : Aether\n%s\n", ResetColor)

	// Display warning message
	fmt.Println(strings.Repeat("-", 91))
	fmt.Printf("%s[!] WARNING: This data is from Shodan and IPInfo. Vulnerabilities listed are not confirmed.%s\n", YellowColor, ResetColor)
	fmt.Println(strings.Repeat("-", 91))
}

// Display a formatted table for IP or CVE data
func displayTable(title string, data map[string]interface{}, writer io.Writer) {
	fmt.Fprintf(writer, "\n%s%s%s\n", BlueColor, title, ResetColor)
	fmt.Fprintln(writer, strings.Repeat("=", 50))

	for k, v := range data {
		fmt.Fprintf(writer, "%s%-15s%s : %v\n", CyanColor, k, ResetColor, v)
	}
	fmt.Fprintln(writer, strings.Repeat("=", 50))
}

// Scan a single IP address
func scanIP(ip string, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	if ipData, err := fetchIPData(ip); err == nil {
		// Prepare output
		var sb strings.Builder
		displayTable(fmt.Sprintf("IP Details: %s", ip), ipData, &sb)
		results <- sb.String() // Send result to channel
	} else {
		log.Printf("Failed to fetch IP data for %s: %v\n", ip, err)
	}
}

// Main function to initialize scanning and parsing arguments
func main() {
	displayBanner()

	// Parse command-line arguments
	ip := flag.String("ip", "", "Single IP address to scan")
	ipList := flag.String("list", "", "Comma-separated list of IP addresses to scan")
	ipFile := flag.String("file", "", "File containing list of IP addresses to scan")
	flag.StringVar(&outputFile, "output", "", "Output file to write results to")
	flag.IntVar(&retryAttempts, "retry-attempts", 5, "Number of retry attempts for fetching data")
	flag.DurationVar(&retryWait, "retry-wait", 2*time.Second, "Wait time between retry attempts")
	flag.Parse()

	// Prepare IPs from arguments
	var ips []string
	if *ip != "" {
		ips = []string{*ip}
	} else if *ipList != "" {
		ips = strings.Split(*ipList, ",")
	} else if *ipFile != "" {
		file, err := os.Open(*ipFile)
		if err != nil {
			log.Fatalf("Failed to open file: %v\n", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			ips = append(ips, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading file: %v\n", err)
		}
	} else {
		log.Println("Please provide either an IP address, a list of IPs, or a file with IPs.")
		return
	}

	// Create a channel to collect results
	results := make(chan string, len(ips))

	// Scan IPs concurrently
	var wg sync.WaitGroup
	for _, ip := range ips {
		wg.Add(1)
		go scanIP(ip, results, &wg)
	}

	// Close the channel once all scans are done
	go func() {
		wg.Wait()
		close(results)
	}()

	// Write results to output file and display to terminal
	if outputFile != "" {
		file, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			log.Fatalf("Failed to open output file: %v\n", err)
		}
		defer file.Close()

		for result := range results {
			fmt.Print(result)        // Print to terminal
			file.WriteString(result) // Write to file
		}
	} else {
		for result := range results {
			fmt.Print(result) // Print to terminal
		}
	}
}
