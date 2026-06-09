package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	// "net"
	"net/http"
	"time"
)

func main(){

	// localAddr := &net.TCPAddr{
	// 	IP:   net.ParseIP("127.0.0.1"),
	// 	Port: 55555, // <-- This is your custom source port!
	// }

	// // 2. Create a custom network Dialer and assign your LocalAddr to it
	// dialer := &net.Dialer{
	// 	LocalAddr: localAddr,
	// 	Timeout:   5 * time.Second,
	// }

	// // 3. Create a custom HTTP Transport that uses your Dialer
	// customTransport := &http.Transport{
	// 	DialContext: dialer.DialContext,
	// }

	// 4. Plug the Transport into your HTTP Client
	Client := &http.Client{
		// Transport: customTransport,
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

