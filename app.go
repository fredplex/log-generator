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
	"sort"
	"syscall"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/brianvoe/gofakeit/v6"
	"github.com/gin-gonic/gin"
)

var (
	apiKey   string
	endpoint string

	applicationNames = [5]string{"application1", "application2", "application3", "application4", "application5"}
	subsystemNames   = [5]string{"subsystem1", "subsystem2", "subsystem3", "subsystem4", "subsystem5"}
	podNames         = [5]string{"pod1", "pod2", "pod3", "pod4", "pod5"}
	containerNames   = [5]string{"container1", "container2", "container3", "container4", "container5"}

	httpClient = &http.Client{}

	totalLogCounts  = make(map[string]int)
	totalByteCounts = make(map[string]int)
)

type LogEntry struct {
	Timestamp       int64  `json:"timestamp"`
	Severity        int    `json:"severity"`
	Text            Text   `json:"text"`
	ApplicationName string `json:"applicationName"`
	SubsystemName   string `json:"subsystemName"`
}

type Text struct {
	Pod         string `json:"process"`
	Container   string `json:"container"`
	Message     string `json:"msg"`
	IP          string `json:"ip"`
	SessionID   string `json:"sessionID"`
	RequestType string `json:"requestType"`
	UserAgent   string `json:"userAgent,omitempty"`
	UserID      string `json:"userID,omitempty"`
}

type AppData struct {
	Name       string
	LogLines   int
	TotalBytes int
}

func main() {
	if err := loadEnvVariables(); err != nil {
		log.Fatal(err)
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
	go logGenerator(ctx, ticker, authenticator)

	// using GIN for web handling function
	//gin.SetMode(gin.ReleaseMode)
	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.GET("/", handleRequest)

	log.Printf("Listening on port 8080 sending loglines to:  %s\n", endpoint)
	r.Run(":8080") // listen and serve on :8080
}

func handleRequest(c *gin.Context) {
	log.Println("Received an incoming request")

	tmpl := template.Must(template.New("summary").Parse(`
		<!DOCTYPE html>
		<html>
		<head>
			<style>
				body {
					background-color: #e0f7fa;
					font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
					color: #00796b;
					text-align: center;
					margin: 0;
					padding: 0;
					display: flex;
					justify-content: center;
					align-items: center;
					height: 100vh;
				}
				table {
					border-collapse: collapse;
					width: 80%;
					margin: 20px auto;
					box-shadow: 0 0 20px rgba(0, 0, 0, 0.1);
				}
				caption {
					caption-side: top;
					font-size: 1.5em;
					font-weight: bold;
					color: #004d40;
					margin-bottom: 10px;
				}
				th, td {
					border: 1px solid #004d40;
					padding: 10px 15px;
					text-align: center;
				}
				th {
					background-color: #80deea;
					color: #000000;
				}
				tr:nth-child(even) {
					background-color: #b2ebf2;
				}
				tr:hover {
					background-color: #4db6ac;
					color: #ffffff;
				}
				.total-row {
					font-weight: bold;
					background-color: #80deea;
					color: #000000;
				}
			</style>
		</head>
		<body>
			<table>
				<caption>Generating logs to {{.Endpoint}}</caption>
				<tr>
					<th>Application</th>
					<th>Log Lines</th>
					<th>Bytes</th>
				</tr>
				{{range .Data}}
				<tr>
					<td>{{.Name}}</td>
					<td>{{.LogLines}}</td>
					<td>{{.TotalBytes}}</td>
				</tr>
				{{end}}
				<tr class="total-row">
					<td>Totals</td>
					<td>{{.TotalLogLines}}</td>
					<td>{{.TotalBytes}}</td>
				</tr>
			</table>
		</body>
		</html>
	`))

	data := []AppData{}
	var totalLogLines, totalBytes int

	for appName, logCount := range totalLogCounts {
		byteCount := totalByteCounts[appName]
		data = append(data, AppData{Name: appName, LogLines: logCount, TotalBytes: byteCount})
		totalLogLines += logCount
		totalBytes += byteCount
	}

	// Sort the data slice to ensure the applications are always displayed in the same order
	sort.Slice(data, func(i, j int) bool {
		return data[i].Name < data[j].Name
	})

	c.Header("Content-Type", "text/html")
	if err := tmpl.Execute(c.Writer, struct {
		Endpoint      string
		Data          []AppData
		TotalLogLines int
		TotalBytes    int
	}{
		Endpoint:      endpoint,
		Data:          data,
		TotalLogLines: totalLogLines,
		TotalBytes:    totalBytes,
	}); err != nil {
		c.String(http.StatusInternalServerError, "Failed to write response: %v", err)
		return
	}
}

func handleShutdown(cancelFunc context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	<-sigChan
	log.Println("Received shutdown signal, shutting down gracefully...")
	cancelFunc()
}

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

func createLogEntries() []LogEntry {
	size := rand.Intn(10) + 1
	logEntries := make([]LogEntry, size+1) // One extra for the login log line
	sessionID := gofakeit.UUID()           // Generate a new UUID for each batch of log entries
	ip := gofakeit.IPv4Address()           // Generate a new random IP address for each batch of log entries
	appName := applicationNames[rand.Intn(len(applicationNames))]

	// Create a login log line
	logEntries[0] = LogEntry{
		Timestamp: time.Now().UnixMilli(),
		Severity:  3,
		Text: Text{
			Pod:         podNames[rand.Intn(len(podNames))],
			Container:   containerNames[rand.Intn(len(containerNames))],
			Message:     "User logged in",
			IP:          ip,
			SessionID:   sessionID,
			RequestType: "Login",
			UserAgent:   gofakeit.UserAgent(),
			UserID:      gofakeit.Username(),
		},
		ApplicationName: appName,
		SubsystemName:   subsystemNames[rand.Intn(len(subsystemNames))],
	}

	// Random pause between 400ms to 1200ms before creating additional log entries
	pauseDuration := time.Duration((rand.Intn(3)+1)*400) * time.Millisecond
	time.Sleep(pauseDuration)

	// Create the rest of the log entries with Severity = 3
	for i := 1; i <= size; i++ {
		logEntries[i] = LogEntry{
			Timestamp: time.Now().UnixMilli(),
			Severity:  3,
			Text: Text{
				Pod:         podNames[rand.Intn(len(podNames))],
				Container:   containerNames[rand.Intn(len(containerNames))],
				Message:     gofakeit.HackerPhrase(),
				IP:          ip,
				SessionID:   sessionID,
				RequestType: gofakeit.VerbAction(),
			},
			ApplicationName: appName,
			SubsystemName:   subsystemNames[rand.Intn(len(subsystemNames))],
		}
	}

	// Random pause between 300ms to 900ms before creating additional log entries
	pauseDuration = time.Duration((rand.Intn(3)+1)*300) * time.Millisecond
	time.Sleep(pauseDuration)

	// Create a random number of log entries (0 to 3) with random severity (1, 2, 4, 5, or 6)
	additionalEntries := rand.Intn(4) // random number between 0 and 3
	severities := []int{1, 2, 4, 5, 6}
	for i := 0; i < additionalEntries; i++ {
		logEntries = append(logEntries, LogEntry{
			Timestamp: time.Now().UnixMilli(),
			Severity:  severities[rand.Intn(len(severities))],
			Text: Text{
				Pod:         podNames[rand.Intn(len(podNames))],
				Container:   containerNames[rand.Intn(len(containerNames))],
				Message:     gofakeit.HackerPhrase(),
				IP:          ip,
				SessionID:   sessionID,
				RequestType: gofakeit.VerbAction(),
			},
			ApplicationName: appName,
			SubsystemName:   subsystemNames[rand.Intn(len(subsystemNames))],
		})
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

	// Print log entries to stdout
	for _, entry := range logEntries {
		log.Printf("Sent log entry: %+v\n", entry)
	}

	return nil
}

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

func updateTotalCounts(logEntries []LogEntry) {
	for _, entry := range logEntries {
		totalLogCounts[entry.ApplicationName]++
		b, _ := json.Marshal(entry)
		totalByteCounts[entry.ApplicationName] += len(b)
	}
}
