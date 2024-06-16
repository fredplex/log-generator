package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/gin-gonic/gin"
)

// Application-level constants
const (
	port = ":8080"
)

// Global variables
var (
	apiKey   string
	endpoint string

	applicationNames = []string{"application1", "application2", "application3", "application4", "application5"}
	subsystemNames   = []string{"subsystem1", "subsystem2", "subsystem3", "subsystem4", "subsystem5"}
	podNames         = []string{"pod1", "pod2", "pod3", "pod4", "pod5"}
	containerNames   = []string{"container1", "container2", "container3", "container4", "container5"}

	httpClient = &http.Client{}

	totalLogCounts  = make(map[string]int)
	totalByteCounts = make(map[string]int)
)

// LogEntry represents a log entry structure
type LogEntry struct {
	Timestamp       int64  `json:"timestamp"`
	Severity        int    `json:"severity"`
	Text            Text   `json:"text"`
	ApplicationName string `json:"applicationName"`
	SubsystemName   string `json:"subsystemName"`
}

// Text represents the text structure in a log entry
type Text struct {
	Pod         string `json:"process"`
	Container   string `json:"container"`
	Message     string `json:"msg"`
	IP          string `json:"ip"`
	RequestID   string `json:"requestID"`
	RequestType string `json:"requestType"`
	UserAgent   string `json:"userAgent,omitempty"`
	UserID      string `json:"userID,omitempty"`
}

// AppData represents data for an application
type AppData struct {
	Name       string
	LogLines   int
	TotalBytes int
}

// main function starts the application
func main() {
	if err := loadEnvVariables(); err != nil {
		log.Fatalf("Error loading environment variables: %v", err)
	}

	authenticator := &core.IamAuthenticator{ApiKey: apiKey}
	if err := authenticator.Validate(); err != nil {
		log.Fatalf("Failed to validate IAM authenticator: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go handleShutdown(cancel)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	go logGenerator(ctx, ticker, authenticator)

	r := gin.Default()
	r.GET("/", handleRequest)

	log.Printf("Listening on port %s\n", port)
	if err := r.Run(port); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}

// loadEnvVariables loads necessary environment variables
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

// handleRequest handles incoming HTTP requests
func handleRequest(c *gin.Context) {
	log.Println("Received an incoming request")

	tmpl := template.Must(template.New("summary").Parse(`
		<html>
		<head>
			<style>
				body {
					background-color: #f0f0f0;
					font-family: Arial, sans-serif;
				}
				h2 {
					color: #333;
				}
				table {
					border-collapse: collapse;
					width: 100%;
					margin-top: 20px;
				}
				th, td {
					border: 1px solid #999;
					padding: 10px;
					text-align: left;
				}
				th {
					background-color: #f2f2f2;
				}
				tr:nth-child(even) {
					background-color: #f2f2f2;
				}
			</style>
		</head>
		<body>
		<h2>Generating logs to {{.Endpoint}}</h2>
		<table>
			<tr><th>Application</th><th>Log Lines</th><th>Bytes</th></tr>
			{{range .Data}}
			<tr><td>{{.Name}}</td><td>{{.LogLines}}</td><td>{{.TotalBytes}}</td></tr>
			{{end}}
		</table>
		</body>
		</html>
	`))

	data := []AppData{}
	for appName, logCount := range totalLogCounts {
		byteCount := totalByteCounts[appName]
		data = append(data, AppData{Name: appName, LogLines: logCount, TotalBytes: byteCount})
	}

	c.Header("Content-Type", "text/html")
	if err := tmpl.Execute(c.Writer, struct {
		Endpoint string
		Data     []AppData
	}{
		Endpoint: endpoint,
		Data:     data,
	}); err != nil {
		c.String(http.StatusInternalServerError, "Failed to write response: %v", err)
		return
	}
}

// handleShutdown handles graceful shutdown
func handleShutdown(cancelFunc context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	log.Println("Received shutdown signal, shutting down gracefully...")
	cancelFunc()
}

// logGenerator generates logs periodically
func logGenerator(ctx context.Context, ticker *time.Ticker, authenticator *core.IamAuthenticator) {
	for {
		select {
		case <-ctx.Done():
			log.Println("Context cancelled, stopping log generation")
			return
		case <-ticker.C:
			logEntries := createLogEntries()
			if err := sendLogs(logEntries, authenticator); err != nil {
				log.Printf("Failed to send logs: %v", err)
			} else {
				printLogAndByteCounts(logEntries)
				updateTotalCounts(logEntries)
			}
		}
	}
}

// createLogEntries creates a batch of log entries
func createLogEntries() []LogEntry {
	size := rand.Intn(10) + 1
	logEntries := make([]LogEntry, size+1)
	requestID := gofakeit.UUID()
	ip := gofakeit.IPv4Address()
	appName := applicationNames[rand.Intn(len(applicationNames))]

	// Create a login log line
	logEntries[0] = LogEntry{
		Timestamp: time.Now().UnixMilli(),
		Severity:  rand.Intn(6) + 1,
		Text: Text{
			Pod:         podNames[rand.Intn(len(podNames))],
			Container:   containerNames[rand.Intn(len(containerNames))],
			Message:     "User logged in",
			IP:          ip,
			RequestID:   requestID,
			RequestType: "Login",
			UserAgent:   gofakeit.UserAgent(),
			UserID:      gofakeit.Username(),
		},
		ApplicationName: appName,
		SubsystemName:   subsystemNames[rand.Intn(len(subsystemNames))],
	}

	// Create the rest of the log entries
	for i := 1; i <= size; i++ {
		logEntries[i] = LogEntry{
			Timestamp: time.Now().UnixMilli(),
			Severity:  rand.Intn(6) + 1,
			Text: Text{
				Pod:         podNames[rand.Intn(len(podNames))],
				Container:   containerNames[rand.Intn(len(containerNames))],
				Message:     gofakeit.HackerPhrase(),
				IP:          ip,
				RequestID:   requestID,
				RequestType: gofakeit.VerbAction(),
			},
			ApplicationName: appName,
			SubsystemName:   subsystemNames[rand.Intn(len(subsystemNames))],
		}
	}
	return logEntries
}

// sendLogs sends log entries to the specified endpoint
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

	log.Printf("Successfully sent %d log entries", len(logEntries))
	return nil
}

// printLogAndByteCounts prints log and byte counts for each application
func printLogAndByteCounts(logEntries []LogEntry) {
	logCounts := make(map[string]int)
	byteCounts := make(map[string]int)
	for _, entry := range logEntries {
		logCounts[entry.ApplicationName]++
		b, _ := json.Marshal(entry)
		byteCounts[entry.ApplicationName] += len(b)
	}
	for appName, logCount := range logCounts {
		byteCount := byteCounts[appName]
		totalLogCount := totalLogCounts[appName]
		totalByteCount := totalByteCounts[appName]
		log.Printf("For application %s, sent %d log lines and %d bytes in this batch. Total sent: %d log lines and %d bytes.\n", appName, logCount, byteCount, totalLogCount, totalByteCount)
	}
}

// updateTotalCounts updates the total log and byte counts for each application
func updateTotalCounts(logEntries []LogEntry) {
	for _, entry := range logEntries {
		totalLogCounts[entry.ApplicationName]++
		b, _ := json.Marshal(entry)
		totalByteCounts[entry.ApplicationName] += len(b)
	}
}
