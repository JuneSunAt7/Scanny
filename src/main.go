package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	"scanny/scan"
	"github.com/pterm/pterm"
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

		// Генерируем случайный порт источника для большей скрытности (опционально)
		srcPort := randomInRange(1024, 65535)
		
		err := scan.SendSYNPacket(srcIP, job.IP, srcPort, job.Port)
		if err != nil {
			// В продакшене лучше логировать в файл или stderr, чтобы не засорять вывод результатов
			fmt.Printf("[-] Ошибка отправки SYN на %s:%d: %v\n", job.IP, job.Port, err)
			continue
		}

		// ВАЖНО: Здесь отсутствует логика ожидания ответа (SYN-ACK).
		// Сейчас код просто считает порт открытым, если пакет ушел.
		result := ScanResult{
			IP:     job.IP,
			Port:   job.Port,
			IsOpen: true, 
			Method: "syn",
		}
		results <- result
	}
}

func randomInRange(min, max int) int {
	return rand.Intn(max-min+1) + min
}

func main() {
	// 1. Определение флагов
	targetIP := flag.String("i", "127.0.0.1", "Целевой IP адрес для сканирования")
	scanMethod := flag.String("m", "tcp", "Метод сканирования: 'tcp' или 'syn'")
	numWorkersFlag := flag.Int("w", 0, "Количество воркеров (0 = авто)")
	
	flag.Parse()


	pterm.FgLightRed.Println(`
 ███████  ██████  ███ ████  ██      ██   ██      ██	 ██		 ██
 ██      ██       ██    ██  ██    ████   ██    ████  ██      ██
 ███████ ██       ██ ██ ██  ██  ██  ██   ██  ██  ██  ██ ███████
      ██ ██       ██    ██  ████    ██   ████    ██  		 ██	
 ███████  ██████  ██    ██  ██		██	 ██		 ██	   ████████
	`)

	var numWorkers int
	if *numWorkersFlag > 0 {
		numWorkers = *numWorkersFlag
	} else {
		numWorkers = randomInRange(50, 200)
	}

	portsToScan := make([]int, 8096)
	for i := 0; i < 8096; i++ {
		portsToScan[i] = i + 1
	}

	jobs := make(chan ScanJob, len(portsToScan))
	results := make(chan ScanResult, len(portsToScan))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	fmt.Printf("[*] Цель: %s | Метод: %s | Воркеры: %d\n", *targetIP, *scanMethod, numWorkers)
	fmt.Println("[*] Запуск сканирования...")

	if *scanMethod == "syn" {
		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go synWorker(ctx, jobs, results, &wg, *targetIP) // Используем targetIP как srcIP для локального теста
		}
	} else {
		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go worker(ctx, jobs, results, &wg)
		}
	}

	// 4. Отправка задач
	for _, port := range portsToScan {
		jobs <- ScanJob{IP: *targetIP, Port: port}
	}
	close(jobs)

	// 5. Ожидание завершения и закрытие канала результатов
	go func() {
		wg.Wait()
		close(results)
	}()

	// 6. Вывод результатов
	foundCount := 0
	for res := range results {
		if res.IsOpen {
			foundCount++
			methodLabel := ""
			if res.Method == "syn" {
				methodLabel = " [SYN]"
			}
			
			msg := fmt.Sprintf("[+] Порт %d ОТКРЫТ%s", res.Port, methodLabel)
			if res.HTTPStatus != "" && res.HTTPStatus != "Not an HTTP server" {
				msg += fmt.Sprintf(" | HTTP: %s", res.HTTPStatus)
			}
			
			pterm.Success.Println(msg)
		}
	}
	
	pterm.Info.Printf("Сканирование завершено. Найдено открытых портов: %d\n", foundCount)
}