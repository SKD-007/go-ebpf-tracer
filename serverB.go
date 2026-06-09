package main

import (
	"fmt"
	"net/http"
	"time"
)

func processHandler(w http.ResponseWriter, r *http.Request) {

	fmt.Println("Server B received request")

	// Simulate slow processing
	time.Sleep(5 * time.Second)

	fmt.Println("Server B finished processing")

	fmt.Fprintf(w, "Processed by Server B\n")
}

func main() {

	http.HandleFunc("/process", processHandler)

	fmt.Println("Server B listening on :8081")

	http.ListenAndServe(":8081", nil)
}
