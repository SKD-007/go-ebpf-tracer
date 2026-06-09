package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

type Data struct{
	val int;
}

type Gateway struct {
	Client *http.Client
}

func (g * Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	
	// To find the IPV version 
	host, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        fmt.Println("Error parsing remote address:", err)
    }

    // Parse the string into a net.IP object
    clientIP := net.ParseIP(host)

    if clientIP.To4() != nil {
        fmt.Println("The client connected using IPv4")
    } else {
        fmt.Println("The client connected using IPv6")
    }
		
	bodyBytes, _ := io.ReadAll(r.Body)
	num , _ := strconv.Atoi(string(bodyBytes))

	// Server1 updates the value by adding 1
	var tempnum int = num + 1
	log.Printf("Server 1 received %d, Server1 sent : %d\n",num,tempnum)

	dataToSend := []byte(strconv.Itoa(tempnum))

	resp, err := g.Client.Post("http://localhost:8082","text/plain",bytes.NewBuffer(dataToSend))
	if (err != nil){
		http.Error(w,"Failed to reach Server2",http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	finalAnswer, _ := io.ReadAll(resp.Body)	
	w.Header().Set("Content-Type", "text/plain")
	w.Write(finalAnswer)
	}
	
func main(){

	// // Setting Server1 outgoing port  to be 444444
	// localAddr := &net.TCPAddr{
	// 	IP:   net.ParseIP("127.0.0.1"),
	// 	Port: 44444,
	// }

	// // Create the custom dialer and transport
	// dialer := &net.Dialer{
	// 	LocalAddr: localAddr,
	// 	Timeout:   3 * time.Second,
	// }
	// customTransport := &http.Transport{
	// 	DialContext: dialer.DialContext,
	// }

	// Inject the custom transport into the Gateway's Client
	Gate := &Gateway{
		Client: &http.Client{
			// Transport: customTransport,
			Timeout:   3 * time.Second,
		},
	}	

	http.Handle("/",Gate)
	fmt.Println("Server1 Listening to Client in port 8081...")
	log.Fatal(http.ListenAndServe(":8081",nil))

}

