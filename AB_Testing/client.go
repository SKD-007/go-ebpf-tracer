package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	// "net"
	// "strconv"
	"encoding/json"
	"net/http"
	"time"
	"sync"
)

func generate_score(cohort string) int {
	if cohort == "Server2B" {
		return 15
	} else if cohort == "Server2A" {
		return 10
	}
	return 0
}

func sendScoreToCentralServer(client *http.Client, cohort string, score int) {
	payload := struct {
		Cohort string `json:"cohort"`
		Score  int    `json:"score"`
	}{
		Cohort: cohort,
		Score:  score,
	}

	jsonData, _ := json.Marshal(payload)

	// Send to Central Server (Port 9090)
	resp, err := client.Post("http://127.0.0.1:9090/api/void", "application/json", bytes.NewBuffer(jsonData))
	if err == nil {
		resp.Body.Close()
	}
}


func main() {
	// Reusing the same client is critical for connection pooling
	Client := &http.Client{
		Timeout: 5 * time.Second,
	}

	const numRequests = 2
	var wg sync.WaitGroup

	fmt.Printf("[*] Starting %d concurrent requests...\n", numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1) // Tell the WaitGroup we are starting a task

		// Launch a Goroutine (Concurrent execution)
		go func(id int) {
			defer wg.Done()

			Data := []byte("0")
			resp1, err1 := Client.Post("http://localhost:8081", "text/plain", bytes.NewBuffer(Data))
			if err1 != nil {
				log.Printf("Request %d failed: %v", id, err1)
				return
			}
			resp1.Body.Close()

			cohort_byte, _ := io.ReadAll(resp1.Body)
			cohort := string(cohort_byte)

			score := generate_score(cohort)

			sendScoreToCentralServer(Client, cohort, score)

			// resp2, err2 := Client.Post("http://localhost:9090", "text/plain", bytes.NewBuffer([]byte("not required")))
			// if err2 != nil{
			// 	log.Printf("Reqest to main failed")
			// 	return
			// }

			// resp2.Body.Close()

		}(i)
	}

	// Wait for all 100 goroutines to finish
	wg.Wait()
	// Inside your Go client main() function, after wg.Wait()
	fmt.Println("[*] Experiment done")
}