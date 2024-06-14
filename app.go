// Based on https://github.com/IBM/CodeEngine/blob/main/app-n-job/app-n-job.go 

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
  // JOB_INDEX env var is a hint about the mode (batch/application) that code engine is running in
	jobIndex := os.Getenv("JOB_INDEX")

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("log: app-n-job got an incoming request\n")
		fmt.Fprintf(w, "Hello from app-n-job! I'm a web app! - soo to be a log generator\n")
	})

	if jobIndex == "" {
		log.Printf("Listening on port 8080\n")
		http.ListenAndServe(":8080", nil)
	} else {
		log.Printf("Hello from app-n-job! I'm a batch job! Index: %s\n",
			jobIndex)
	}
}
