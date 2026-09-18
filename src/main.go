package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"scanny/scan"
	"github.com/pterm/pterm"
)

type ScanJob struct {
	IP   string
	Port int
}

// CVEEntry описывает структуру ответа от API уязвимостей
type CVEEntry struct {
	ID      string `json:"id"`
	Summary string `json:"summary"`
}

type ScanResult struct {
	IP         string
	Port       int
	IsOpen     bool
	HTTPStatus string
	Method     string     // "tcp" или "syn"
	Banner     string     // Полученная строка-приветствие сервиса
	CVEs       []CVEEntry // Список найденных уязвимостей
}

// grabBanner пытается прочитать приветственный баннер из открытого сокета
func grabBanner(ctx context.Context, ip string, port int) string {
	target := fmt.Sprintf("%s:%d", ip, port)
	dialer := net.Dialer{Timeout: 2 * time.Second}
	
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Для HTTP-портов отправляем минимальный запрос, чтобы спровоцировать ответ с баннером сервера
	if port == 80 || port == 8080 || port == 443 {
		_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	// Очищаем баннер от мусорных символов и переносов строк
	banner := string(buffer[:n])
	banner = strings.ReplaceAll(banner, "\r", "")
	banner = strings.ReplaceAll(banner, "\n", " ")
	return strings.TrimSpace(banner)
}

// checkCVE отправляет запрос к публичной базе данных CIRCL CVE API
func checkCVE(keyword string) []CVEEntry {
	if keyword == "" {
		return nil
	}

	// Поиск по ключевому слову софта (например, nginx, openssh, apache)
	url := fmt.Sprintf("https://circl.lu", strings.ToLower(keyword))
	client := &http.Client{Timeout: 4 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var results []CVEEntry
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil
	}

	return results
}

// detectSoftware пытается вычленить имя известного ПО из сырого баннера
func detectSoftware(banner string) string {
	lowBanner := strings.ToLower(banner)
	
	// Базовые маркеры для демонстрации (в идеале заменить на регулярные выражения)
	services := []string{"openssh", "nginx", "apache", "vsftpd", "tomcat", "mysql", "redis", "smb"}
	for _, service := range services {
		if strings.Contains(lowBanner, service) {
			return service
		}
	}
	return ""
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

		// [Интеграция CVE]: Собираем баннер, если сканируем по TCP
		banner := grabBanner(ctx, job.IP, job.Port)
		if banner != "" {
			result.Banner = banner
			software := detectSoftware(banner)
			if software != "" {
				result.CVEs = checkCVE(software)
			}
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

		srcPort := randomInRange(1024, 65535)
		
		err := scan.SendSYNPacket(srcIP, job.IP, srcPort, job.Port)
		if err != nil {
			fmt.Printf("[-] Ошибка отправки SYN на %s:%d: %v\n", job.IP, job.Port, err)
			continue
		}

		result := ScanResult{
			IP:     job.IP,
			Port:   job.Port,
			IsOpen: true, 
			Method: "syn",
		}

		// При SYN-сканировании полноценное соединение не устанавливается,
		// поэтому для получения баннера и CVE мы отправляем точечный TCP-запрос
		banner := grabBanner(ctx, job.IP, job.Port)
		if banner != "" {
			result.Banner = banner
			software := detectSoftware(banner)
			if software != "" {
				result.CVEs = checkCVE(software)
			}
		}

		results <- result
	}
}

func randomInRange(min, max int) int {
	return rand.Intn(max-min+1) + min
}

func main() {
	targetIP := flag.String("i", "127.0.0.1", "Целевой IP адрес для сканирования")
	scanMethod := flag.String("m", "tcp", "Метод сканирования: 'tcp' или 'syn'")
	numWorkersFlag := flag.Int("w", 0, "Количество воркеров (0 = авто)")
	
	flag.Parse()

	pterm.FgLightRed.Println(`
 ███████  ██████  ███ ████  
 ██      ██       ██    ██  
 ███████ ██       ██ ██ ██ 
      ██ ██       ██    ██  
 ███████  ██████  ██    ██ 
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
	fmt.Println("[*] Запуск сканирования с поиском CVE...")

	if *scanMethod == "syn" {
		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go synWorker(ctx, jobs, results, &wg, *targetIP) 
		}
	} else {
		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go worker(ctx, jobs, results, &wg)
		}
	}

	for _, port := range portsToScan {
		jobs <- ScanJob{IP: *targetIP, Port: port}
	}
	close(jobs)
	go func() {
		wg.Wait()
		close(results)
	}()

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
			if res.Banner != "" {
				// Отрезаем слишком длинные баннеры для красоты вывода
				displayBanner := res.Banner
				if len(displayBanner) > 60 {
					displayBanner = displayBanner[:57] + "..."
				}
				msg += fmt.Sprintf(" | ПО: %s", displayBanner)
			}
			
			pterm.Success.Println(msg)

			// Вывод найденных CVE уязвимостей
			if len(res.CVEs) > 0 {
				pterm.FgYellow.Println("   └── Найдена угроза! Свежие CVE:")
				
				// Лимитируем вывод до 3-х уязвимостей, чтобы терминал не затапливало
				limit := 3
				if len(res.CVEs) < limit {
					limit = len(res.CVEs)
				}
				for i := 0; i < limit; i++ {
					cve := res.CVEs[i]
					summary := cve.Summary
					if len(summary) > 75 {
						summary = summary[:72] + "..."
					}
					pterm.FgLightRed.Printf("       ⚠️  %-15s -> %s\n", cve.ID, summary)
				}
			}
			
		}
	}
	
	pterm.Info.Printf("Сканирование завершено. Найдено открытых портов: %d\n", foundCount)
}
