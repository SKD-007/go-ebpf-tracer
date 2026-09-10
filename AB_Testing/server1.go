package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"math/rand"
	// "net"
	"net/http"
	"runtime"
	"strconv"
	"time"
	// "math/rand"
)

func getGoroutineID() uint64 {
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]

	b = bytes.TrimPrefix(b, []byte("goroutine "))
	b = b[:bytes.IndexByte(b, ' ')]

	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

type Data struct {
	val int
}

type Gateway struct {
	Client *http.Client
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	// parentGoID := getGoroutineID()
	// fmt.Printf("[ServeHTTP] Handling request on Goroutine ID (start): %d\n", parentGoID)

	// To find the IPV version
	// host, _, err := net.SplitHostPort(r.RemoteAddr)
	// if err != nil {
	// 	fmt.Println("Error parsing remote address:", err)
	// }

	// // Parse the string into a net.IP object
	// clientIP := net.ParseIP(host)

	// if clientIP.To4() != nil {
	// 	fmt.Println("The client connected using IPv4")
	// } else {
	// 	fmt.Println("The client connected using IPv6")
	// }

	bodyBytes, _ := io.ReadAll(r.Body)
	num, _ := strconv.Atoi(string(bodyBytes))

	// Server1 updates the value by adding 1
	var tempnum int = num + 1
	log.Printf("Server 1 received %d, Server1 sent : %d\n", num, tempnum)

	dataToSend := []byte(strconv.Itoa(tempnum))

	// Create a channel to receive the result from our child goroutine
	type asyncResult struct {
		data []byte
		cohort string
		err  error
	}
	resultChan := make(chan asyncResult)

	go func() {
		// level1GoID := getGoroutineID()
		// fmt.Printf("[Level 1 Goroutine] Intermediate step on ID: %d (Parent was %d)\n", level1GoID, parentGoID)

		// Level 2: Launch the nested (deep) go func
		go func() {
			// level2GoID := getGoroutineID()
			// fmt.Printf("[Level 2 Goroutine] Making request to Server2 on Goroutine ID: %d (Parent was %d)\n", level2GoID, level1GoID)

			var resp *http.Response
			var err error
			var cohort string
			if rand.Float32() < 0.1 {
				// 10% of the time we are sending to server3
				cohort = "Server2B"
				resp, err = g.Client.Post("http://localhost:8083", "text/plain", bytes.NewBuffer(dataToSend))
			
			} else{
				// 90% of the time we are sending to server2
				cohort = "Server2A"
				resp, err = g.Client.Post("http://localhost:8082", "text/plain", bytes.NewBuffer(dataToSend))
			}
			
			if err != nil {
				resultChan <- asyncResult{err: err}
				return
			}	
			defer resp.Body.Close()

			finalAnswer, err := io.ReadAll(resp.Body)
			
			// Send the result directly back to the root ServeHTTP
			resultChan <- asyncResult{finalAnswer, cohort, err}
		}()
	}()
	
	// Wait here until the child goroutine sends data back through the channel
	res := <-resultChan

	if res.err != nil {
		http.Error(w, "Failed to reach Server2", http.StatusInternalServerError)
		return
	}
	w.Header().Set("AB-Cohort", res.cohort)
	w.Header().Set("Content-Type", "text/plain")
	w.Write(res.data)

}

func main() {
	fmt.Printf("[Main] Application started on Goroutine ID: %d\n", getGoroutineID())

	customTransport := &http.Transport{
        MaxIdleConns:        100,
        MaxIdleConnsPerHost: 100,
        MaxConnsPerHost:     100, // Forces all outbound traffic through exactly one socket
    }

	// Inject the custom transport into the Gateway's Client
	Gate := &Gateway{
		Client: &http.Client{
			Timeout: 3 * time.Second,
			Transport: customTransport,
		},
	}

	http.Handle("/", Gate)
	fmt.Println("Server1 Listening to Client in port 8081...")
	log.Fatal(http.ListenAndServe(":8081", nil))
}