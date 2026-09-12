// test
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

type ScanJob struct {
	IP   string
	Port int
}

type ScanResult struct {
	IP         string
	Port       int
	IsOpen     bool
	HTTPStatus string
}

func worker(ctx context.Context, jobs <-chan ScanJob, results chan<- ScanResult, wg *sync.WaitGroup) {
	defer wg.Done()

	httpClient := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for job := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
		}
		target := fmt.Sprintf("%s:%d", job.IP, job.Port)

		// fast check tcp
		dialer := net.Dialer{Timeout: 1 * time.Second}
		conn, err := dialer.DialContext(ctx, "tcp", target)

		if err != nil {
			continue
		}
		conn.Close() // port is open

		result := ScanResult{
			IP:     job.IP,
			Port:   job.Port,
			IsOpen: true,
		}
		if job.Port == 80 || job.Port == 443 || job.Port == 8080 {
			protocol := "http"
			if job.Port == 443 {
				protocol = "https"
			}

			resp, err := httpClient.Get(fmt.Sprintf("%s://%s", protocol, target))
			if err == nil {
				result.HTTPStatus = resp.Status
				resp.Body.Close()
			} else {
				result.HTTPStatus = "Not an HTTP server"
			}
		}

		results <- result
	}
}

func main() {
	targetIP := "127.0.0.1"
	portsToScan := []int{21, 22, 25, 53, 80, 110, 443, 3306, 8080}

	numWorkers := 50

	jobs := make(chan ScanJob, len(portsToScan))
	results := make(chan ScanResult, len(portsToScan))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(ctx, jobs, results, &wg)
	}

	for _, port := range portsToScan {
		jobs <- ScanJob{IP: targetIP, Port: port}
	}
	close(jobs)

	// add results in gorutinre
	go func() {
		wg.Wait()
		close(results)
	}()

	fmt.Printf("Сканирование %s запущенно с %d воркерами...\n\n", targetIP, numWorkers)
	for res := range results {
		if res.IsOpen {
			if res.HTTPStatus != "" {
				fmt.Printf("[+] Порт %d ОТКРЫТ | HTTP: %s\n", res.Port, res.HTTPStatus)
			} else {
				fmt.Printf("[+] Порт %d ОТКРЫТ\n", res.Port)
			}
		}
	}
}
