package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

func main(){

	Client := &http.Client{
		Timeout:   5 * time.Second,
	}

	Data := []byte("0")
	
	resp, err := Client.Post("http://localhost:8081", "text/plain",bytes.NewBuffer(Data))
	if(err != nil){
		log.Fatal("Failed sending from Client to Server1")
	}
	defer resp.Body.Close()

	finalAnswer, _ := io.ReadAll(resp.Body)

	fmt.Printf("Client received from Server1 : %s\n", string(finalAnswer))
}

