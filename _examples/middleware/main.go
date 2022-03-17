package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/realclientip/realclientip-go"
)

func main() {
	// Choose the right strategy for our network configuration
	clientIPStrategy, err := realclientip.RightmostNonPrivateStrategy("X-Forwarded-For")
	if err != nil {
		log.Fatal("realclientip.RightmostNonPrivateStrategy returned error (bad input)")
	}

	// Place our middleware before the handler
	httpServer := httptest.NewServer(clientIPMiddleware(clientIPStrategy, http.HandlerFunc(handler)))
	defer httpServer.Close()

	req, _ := http.NewRequest("GET", httpServer.URL, nil)
	req.Header.Add("X-Forwarded-For", "1.1.1.1, 2.2.2.2, 3.3.3.3, 192.168.1.1")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s", b)
}

type clientIPCtxKey struct{}

// Adds the "real" client IP to the request context under the clientIPCtxKey{} key.
// If the client IP couldn't be obtained, the value will be an empty string.
func clientIPMiddleware(clientIPStrategy realclientip.Strategy, next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		clientIP := clientIPStrategy(r.Header, r.RemoteAddr)
		if clientIP == "" {
			// Write error log. Consider aborting the request depending on use.
			log.Fatal("Failed to find client IP")
		}

		r = r.WithContext(context.WithValue(r.Context(), clientIPCtxKey{}, clientIP))
		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "your IP:", r.Context().Value(clientIPCtxKey{}))
}
