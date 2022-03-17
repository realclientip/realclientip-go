package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/didip/tollbooth/v6"
	"github.com/realclientip/realclientip-go"
)

func main() {
	// Choose the right strategy for our network configuration
	clientIPStrategy, err := realclientip.RightmostNonPrivateStrategy("X-Forwarded-For")
	if err != nil {
		log.Fatal("realclientip.RightmostNonPrivateStrategy returned error (bad input)")
	}

	lmt := tollbooth.NewLimiter(1, nil)

	// We'll make a fake request
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	req.Header.Add("X-Forwarded-For", "1.1.1.1, 2.2.2.2, 3.3.3.3, 192.168.1.1")
	req.RemoteAddr = "192.168.1.2:8888"

	clientIP := clientIPStrategy(req.Header, req.RemoteAddr)
	if clientIP == "" {
		// This should probably result in the request being denied
		log.Fatal("clientIPStrategy found no IP")
	}

	// We don't want to include the zone in our limiter key
	clientIP, _ = realclientip.SplitHostZone(clientIP)

	if httpErr := tollbooth.LimitByKeys(lmt, []string{clientIP}); httpErr != nil {
		fmt.Println("We got limited!?!", httpErr)
	} else {
		fmt.Println("Request allowed")
	}
}
