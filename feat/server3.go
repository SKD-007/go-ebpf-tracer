package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"math/rand"
    "time"
)

func Server3(w http.ResponseWriter, r *http.Request) {
	// To find the IPV version of the server3
	host, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        fmt.Println("Error parsing remote address:", err)
    }

    clientIP := net.ParseIP(host)

    if clientIP.To4() != nil {
        fmt.Println("The Server3 connected using IPv4")
    } else {
        fmt.Println("The Server3 connected using IPv6")
    }

	bodyBytes, _ := io.ReadAll(r.Body)
	num , _ := strconv.Atoi(string(bodyBytes))

	// Server3 modifies the data by adding 3
	var tempnum int = num + 3
	log.Printf("Server3 received %d, Server3 sent : %d\n",num,tempnum)

	dataToSend := []byte(strconv.Itoa(tempnum))

	w.Header().Set("Content-Type", "text/plain")

	// if rand.Float32() < 0.20 {
    //     time.Sleep(300 * time.Millisecond) // Inflate latency by 40ms
    // }

	w.Write(dataToSend)
	}
	
func main(){
	http.HandleFunc("/",Server3)
	fmt.Println("Server3 Listening to Server1 in port 8083...")
	log.Fatal(http.ListenAndServe(":8083",nil))
}

