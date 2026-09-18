package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"scanny/scan"
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
	Method     string // "tcp" или "syn"
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

		dialer := net.Dialer{Timeout: 1 * time.Second}
		conn, err := dialer.DialContext(ctx, "tcp", target)

		if err != nil {
			continue
		}
		conn.Close()

		result := ScanResult{
			IP:     job.IP,
			Port:   job.Port,
			IsOpen: true,
			Method: "tcp",
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

func synWorker(ctx context.Context, jobs <-chan ScanJob, results chan<- ScanResult, wg *sync.WaitGroup, srcIP string) {
	defer wg.Done()

	for job := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		err := scan.SendSYNPacket(srcIP, job.IP, 54321, job.Port)
		if err != nil {
			fmt.Printf("[-] Ошибка отправки SYN на %s:%d: %v\n", job.IP, job.Port, err)
			continue
		}

		// in prod raw socket listener
		result := ScanResult{
			IP:     job.IP,
			Port:   job.Port,
			IsOpen: true, 
			Method: "syn",
		}
		results <- result
	}
}

func main() {
	
	fmt.Println("input target IP")
	var target string
	fmt.Scanln(&target)

	targetIP := target
	srcIP := "127.0.0.1" // IP deist for SYN packets
	
	portsToScan := []int{21, 22, 25, 53, 80, 110, 443, 3306, 8080}

	numWorkers := 50
	scanMethod := "tcp" // or "syn"

	jobs := make(chan ScanJob, len(portsToScan))
	results := make(chan ScanResult, len(portsToScan))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	if scanMethod == "syn" {
		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go synWorker(ctx, jobs, results, &wg, srcIP)
		}
		fmt.Println("Используется SYN-сканирование")
	} else {
		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go worker(ctx, jobs, results, &wg)
		}
		fmt.Println("Используется TCP-сканирование")
	}

	for _, port := range portsToScan {
		jobs <- ScanJob{IP: targetIP, Port: port}
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	fmt.Printf("\nСканирование %s запущено с %d воркерами...\n\n", targetIP, numWorkers)
	for res := range results {
		if res.IsOpen {
			methodLabel := ""
			if res.Method == "syn" {
				methodLabel = " [SYN]"
			}
			if res.HTTPStatus != "" {
				fmt.Printf("[+] Порт %d ОТКРЫТ%s | HTTP: %s\n", res.Port, methodLabel, res.HTTPStatus)
			} else {
				fmt.Printf("[+] Порт %d ОТКРЫТ%s\n", res.Port, methodLabel)
			}
		}
	}
}