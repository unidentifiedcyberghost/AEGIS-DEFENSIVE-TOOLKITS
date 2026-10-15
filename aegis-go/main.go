package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type HeaderCheck struct {
	Header      string `json:"header"`
	Present     bool   `json:"present"`
	Value       string `json:"value"`
	Severity    string `json:"severity"`
	Remediation string `json:"remediation"`
}

type PortResult struct {
	Port   int    `json:"port"`
	Open   bool   `json:"open"`
	Banner string `json:"banner,omitempty"`
}

type AttackerHit struct {
	IP          string   `json:"ip"`
	Threat      string   `json:"threat"`
	Hits        int      `json:"hits"`
	AttackTypes []string `json:"attack_types"`
}

type AuditReport struct {
	Target      string        `json:"target"`
	StatusCode  int           `json:"status_code"`
	LatencyMs   int64         `json:"latency_ms"`
	Score       int           `json:"score"`
	Grade       string        `json:"grade"`
	Headers     []HeaderCheck `json:"headers"`
	ExposedDots []string      `json:"exposed_files"`
}

var (
	targetFlag  = flag.String("target", "", "Target URL for defensive web audit")
	portsFlag   = flag.Bool("ports", false, "Fast concurrent localhost port check")
	logPathFlag = flag.String("log", "", "Path to web server access log for attack analysis")
	jsonFlag    = flag.Bool("json", false, "Output results in JSON format")
)

var secHeaders = map[string]string{
	"Content-Security-Policy":   "default-src 'self';",
	"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	"X-Frame-Options":           "SAMEORIGIN",
	"X-Content-Type-Options":    "nosniff",
	"Referrer-Policy":           "strict-origin-when-cross-origin",
	"Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
}

func main() {
	flag.Parse()

	if *portsFlag {
		scanLocalhostPorts(*jsonFlag)
		return
	}

	if *logPathFlag != "" {
		analyzeLogFile(*logPathFlag, *jsonFlag)
		return
	}

	if *targetFlag != "" {
		auditTarget(*targetFlag, *jsonFlag)
		return
	}

	fmt.Println("Aegis Core Go Engine // High-Speed Defensive Micro-Service")
	fmt.Println("Usage:")
	fmt.Println("  aegis-core -target http://localhost:8080 [-json]")
	fmt.Println("  aegis-core -ports [-json]")
	fmt.Println("  aegis-core -log /path/to/access.log [-json]")
}

func auditTarget(rawURL string, asJSON bool) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "http://" + rawURL
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
	}

	start := time.Now()
	resp, err := client.Get(rawURL)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		if asJSON {
			fmt.Printf(`{"error": "failed to connect: %s"}`+"\n", err.Error())
		} else {
			fmt.Printf("[-] Failed to connect to %s: %v\n", rawURL, err)
		}
		return
	}
	defer resp.Body.Close()

	score := 100
	var checks []HeaderCheck

	for h, rec := range secHeaders {
		val := resp.Header.Get(h)
		if val != "" {
			checks = append(checks, HeaderCheck{
				Header:      h,
				Present:     true,
				Value:       val,
				Severity:    "Pass",
				Remediation: "Properly configured.",
			})
		} else {
			score -= 10
			checks = append(checks, HeaderCheck{
				Header:      h,
				Present:     false,
				Value:       "",
				Severity:    "High",
				Remediation: fmt.Sprintf("Add '%s: %s' to web server response headers.", h, rec),
			})
		}
	}

	// Check sensitive files concurrently
	sensitiveFiles := []string{"/.env", "/.git/HEAD", "/docker-compose.yml"}
	var exposed []string
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, sf := range sensitiveFiles {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			testURL := strings.TrimRight(rawURL, "/") + path
			r, e := client.Get(testURL)
			if e == nil {
				defer r.Body.Close()
				if r.StatusCode == 200 {
					mu.Lock()
					exposed = append(exposed, path)
					score -= 25
					mu.Unlock()
				}
			}
		}(sf)
	}
	wg.Wait()

	if score < 0 {
		score = 0
	}
	grade := "A"
	if score < 60 {
		grade = "F"
	} else if score < 75 {
		grade = "C"
	} else if score < 90 {
		grade = "B"
	}

	report := AuditReport{
		Target:      rawURL,
		StatusCode:  resp.StatusCode,
		LatencyMs:   latency,
		Score:       score,
		Grade:       grade,
		Headers:     checks,
		ExposedDots: exposed,
	}

	if asJSON {
		b, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Printf("[+] Target: %s (Status: %d, Latency: %dms)\n", rawURL, resp.StatusCode, latency)
		fmt.Printf("[+] Defensive Score: %d/100 (Grade: %s)\n", score, grade)
		for _, c := range checks {
			if c.Present {
				fmt.Printf("    [PASS] %s: %s\n", c.Header, c.Value)
			} else {
				fmt.Printf("    [MISSING] %s -> Fix: %s\n", c.Header, c.Remediation)
			}
		}
		if len(exposed) > 0 {
			fmt.Printf("    [CRITICAL] Exposed files detected: %v\n", exposed)
		}
	}
}

func scanLocalhostPorts(asJSON bool) {
	ports := []int{80, 443, 3000, 3306, 5000, 5432, 6379, 8000, 8080, 8443, 27017, 5173}
	var results []PortResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, p := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			addr := fmt.Sprintf("127.0.0.1:%d", port)
			conn, err := net.DialTimeout("tcp", addr, 400*time.Millisecond)
			if err == nil {
				conn.Close()
				mu.Lock()
				results = append(results, PortResult{Port: port, Open: true})
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()

	if asJSON {
		b, _ := json.MarshalIndent(results, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Println("[+] Active Localhost (127.0.0.1) Listening Ports:")
		for _, r := range results {
			fmt.Printf("    - Port %d: OPEN / ACTIVE\n", r.Port)
		}
	}
}

func analyzeLogFile(path string, asJSON bool) {
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("[-] Failed to open log file: %v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	attackRegex := regexp.MustCompile(`(\.\./|\.env|\.git/|union\s+select|' OR|information_schema|<script)`)

	attackerHits := make(map[string]int)

	for scanner.Scan() {
		line := scanner.Text()
		if attackRegex.MatchString(line) {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				ip := fields[0]
				attackerHits[ip]++
			}
		}
	}

	if asJSON {
		b, _ := json.MarshalIndent(attackerHits, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Println("[+] Detected Malicious Attacker IPs:")
		for ip, count := range attackerHits {
			fmt.Printf("    * IP: %s (Probes: %d) -> Block: sudo ufw deny from %s\n", ip, count, ip)
		}
	}
}
