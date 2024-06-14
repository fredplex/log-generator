package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/brianvoe/gofakeit/v6"
)

var (
	apiKey   string
	endpoint string

	applicationNames = [5]string{"application1", "application2", "application3", "application4", "application5"}
	subsystemNames   = [5]string{"subsystem1", "subsystem2", "subsystem3", "subsystem4", "subsystem5"}
	podNames         = [5]string{"pod1", "pod2", "pod3", "pod4", "pod5"}
	containerNames   = [5]string{"container1", "container2", "container3", "container4", "container5"}

	httpClient = &http.Client{}
)

type LogEntry struct {
	Timestamp       int64  `json:"timestamp"`
	Severity        int    `json:"severity"`
	Text            Text   `json:"text"`
	ApplicationName string `json:"applicationName"`
	SubsystemName   string `json:"subsystemName"`
}

type Text struct {
	Pod       string `json:"process"`
	Container string `json:"container"`
	Message   string `json:"msg"`
	IP        string `json:"ip"`
}

func main() {
	if err := loadEnvVariables(); err != nil {
		log.Fatal(err)
	}

	ip, err := getIpAddress()
	if err != nil {
		log.Fatalf("Failed to get IP address: %v", err)
	}

	authenticator := &core.IamAuthenticator{
		ApiKey: apiKey,
	}

	if err := authenticator.Validate(); err != nil {
		log.Fatalf("Failed to validate IAM authenticator: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go handleShutdown(cancel)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// launch the log generator as a go routine
	go logGenerator(ctx, ticker, ip.String(), authenticator)

	// the web handling function
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("log: app-n-job got an incoming request\n")
		fmt.Fprintf(w, "Generatig logs to %s\n", endpoint)
	})

	log.Printf("Listening on port 8080 %s\n",endpoint)
	// start the web server
	http.ListenAndServe(":8080", nil)
}

func handleShutdown(cancelFunc context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	log.Println("Received shutdown signal, shutting down gracefully...")
	cancelFunc()
}

func logGenerator(ctx context.Context, ticker *time.Ticker, ip string, authenticator *core.IamAuthenticator) {
	for {
		select {
		case <-ctx.Done():
			log.Println("Context cancelled, stopping log generation")
			return
		case <-ticker.C:
			if err := sendLogs(createLogEntries(ip), authenticator); err != nil {
				log.Printf("Failed to send logs: %v", err)
			}
		}
	}
}

func loadEnvVariables() error {
	apiKey = os.Getenv("API_KEY")
	if apiKey == "" {
		return fmt.Errorf("API_KEY environment variable is not set")
	}

	endpoint = os.Getenv("ENDPOINT")
	if endpoint == "" {
		return fmt.Errorf("ENDPOINT environment variable is not set")
	}

	return nil
}

func createLogEntries(ip string) []LogEntry {
	size := rand.Intn(10) + 1
	logEntries := make([]LogEntry, size)
	for i := range logEntries {
		logEntries[i] = LogEntry{
			Timestamp: time.Now().UnixMilli(),
			Severity:  rand.Intn(6) + 1,
			Text: Text{
				Pod:       podNames[rand.Intn(len(podNames))],
				Container: containerNames[rand.Intn(len(containerNames))],
				Message:   gofakeit.HackerPhrase(),
				IP:        ip,
			},
			ApplicationName: applicationNames[rand.Intn(len(applicationNames))],
			SubsystemName:   subsystemNames[rand.Intn(len(subsystemNames))],
		}
	}
	return logEntries
}

func sendLogs(logEntries []LogEntry, authenticator *core.IamAuthenticator) error {
	b, err := json.Marshal(logEntries)
	if err != nil {
		return fmt.Errorf("failed to marshal log entries: %w", err)
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(b))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	iamToken, err := authenticator.RequestToken()
	if err != nil {
		return fmt.Errorf("failed to request IAM token: %w", err)
	}

	req.Header.Add("Authorization", "Bearer "+iamToken.AccessToken)
	req.Header.Add("Content-Type", "application/json")

	res, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-OK response: %s", res.Status)
	}

	return nil
}

func getIpAddress() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, fmt.Errorf("failed to dial UDP: %w", err)
	}
	defer conn.Close()

	localAddress := conn.LocalAddr().(*net.UDPAddr)
	return localAddress.IP, nil
}

