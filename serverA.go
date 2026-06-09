package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

func callServerB() {

	fmt.Println("Background goroutine started")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get("http://localhost:8081/process")

	if err != nil {
		fmt.Println("Error calling Server B:", err)
		return
	}

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	fmt.Println("Response from Server B:")
	fmt.Println(string(body))
}

func handler(w http.ResponseWriter, r *http.Request) {

	fmt.Println("Received client request")

	/*
	   Spawn separate goroutine
	   This runs independently
	*/
	go callServerB()

	/*
	   Immediately respond to client
	   WITHOUT waiting for Server B
	*/
	fmt.Fprintf(w, "Request accepted\n")

	fmt.Println("Handler finished immediately")
}

func main() {

	http.HandleFunc("/", handler)

	fmt.Println("Server A listening on :8080")

	http.ListenAndServe(":8080", nil)
}
