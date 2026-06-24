package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

func main() {
	// 1. Force Go to use exactly ONE File Descriptor (TCP Connection)
	transport := &http.Transport{
		MaxConnsPerHost: 1, 
	        MaxIdleConnsPerHost: 1,
	}
	client := &http.Client{Transport: transport}

	var wg sync.WaitGroup

	fmt.Println("Firing 3 concurrent requests...")
	
	// 2. Spawn 3 concurrent Goroutines
	for i := 1; i <= 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			start := time.Now()
			
			// Send the request
			resp, err := client.Get("http://localhost:8082/")
			if err != nil {
				fmt.Println("Error:", err)
				return
			}
			resp.Body.Close()
			
			fmt.Printf("Request %d finished in %v\n", id, time.Since(start))
		}(i)
	}

	wg.Wait()
	fmt.Println("All done!")
}
