package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	// "net"
	"net/http"
	"time"
	"sync"
)

// func main(){

// 	// localAddr := &net.TCPAddr{
// 	// 	IP:   net.ParseIP("127.0.0.1"),
// 	// 	Port: 55555, // <-- This is your custom source port!
// 	// }

// 	// // 2. Create a custom network Dialer and assign your LocalAddr to it
// 	// dialer := &net.Dialer{
// 	// 	LocalAddr: localAddr,
// 	// 	Timeout:   5 * time.Second,
// 	// }

// 	// // 3. Create a custom HTTP Transport that uses your Dialer
// 	// customTransport := &http.Transport{
// 	// 	DialContext: dialer.DialContext,
// 	// }

// 	// 4. Plug the Transport into your HTTP Client
// 	Client := &http.Client{
// 		// Transport: customTransport,
// 		Timeout:   5 * time.Second,
// 	}

// 	Data := []byte("0")
	
// 	resp, err := Client.Post("http://localhost:8081", "text/plain",bytes.NewBuffer(Data))
// 	if(err != nil){
// 		log.Fatal("Failed sending from Client to Server1")
// 	}
// 	defer resp.Body.Close()

// 	finalAnswer, _ := io.ReadAll(resp.Body)

// 	fmt.Printf("Client received from Server1 : %s\n", string(finalAnswer))
// }

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
	resp, err := client.Post("http://127.0.0.1:9090/api/scores", "application/json", bytes.NewBuffer(jsonData))
	if err == nil {
		resp.Body.Close()
	}
}


func main() {
	// Reusing the same client is critical for connection pooling
	Client := &http.Client{
		Timeout: 5 * time.Second,
	}

	const numRequests = 100
	var wg sync.WaitGroup

	fmt.Printf("[*] Starting %d concurrent requests...\n", numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1) // Tell the WaitGroup we are starting a task

		// Launch a Goroutine (Concurrent execution)
		go func(id int) {
			defer wg.Done()

			Data := []byte("0")
			resp, err := Client.Post("http://localhost:8081", "text/plain", bytes.NewBuffer(Data))
			if err != nil {
				log.Printf("Request %d failed: %v", id, err)
				return
			}
			defer resp.Body.Close()

			// Read response (you can omit this if you don't need the output)
			resp, err := io.ReadAll(resp.Body)

			if(resp == "3"){
				// server2 has received the response
			}
			elseif(resp == "4"){
				// server3 has received the response
				
			}
			// fmt.Printf("Client received from Server1 (Req %d)\n", id)
		}(i)
	}

	// Wait for all 100 goroutines to finish
	wg.Wait()
	// Inside your Go client main() function, after wg.Wait()
	fmt.Println("[*] Experiment done. Fetching analysis...")
	resp, _ := http.Get("http://127.0.0.1:9090/api/analyze")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
	fmt.Println("[*] All requests completed.")
}