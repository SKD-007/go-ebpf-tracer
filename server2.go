package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
)

func Server2(w http.ResponseWriter, r *http.Request) {
	// To find the IPV version of the server2
	host, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        fmt.Println("Error parsing remote address:", err)
    }

    clientIP := net.ParseIP(host)

    if clientIP.To4() != nil {
        fmt.Println("The Server2 connected using IPv4")
    } else {
        fmt.Println("The Server2 connected using IPv6")
    }

	bodyBytes, _ := io.ReadAll(r.Body)
	num , _ := strconv.Atoi(string(bodyBytes))

	// Server2 modifies the data by adding 2
	var tempnum int = num + 2
	log.Printf("Server 2 received %d, Server2 sent : %d\n",num,tempnum)

	dataToSend := []byte(strconv.Itoa(tempnum))

	w.Header().Set("Content-Type", "text/plain")
	w.Write(dataToSend)
	}
	
func main(){
	http.HandleFunc("/",Server2)
	fmt.Println("Server2 Listening to Server1 in port 8082...")
	log.Fatal(http.ListenAndServe(":8082",nil))
}

