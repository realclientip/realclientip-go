package realclientip_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/realclientip/realclientip-go"
)

func Example_middleware() {
	// Choose the right strategy for our network configuration
	strat, err := realclientip.NewRightmostNonPrivateStrategy("X-Forwarded-For")
	if err != nil {
		log.Fatal("realclientip.NewRightmostNonPrivateStrategy returned error (bad input)")
	}

	// Place our middleware before the handler
	handlerWithMiddleware := clientIPMiddleware(strat, http.HandlerFunc(handler))
	httpServer := httptest.NewServer(handlerWithMiddleware)
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
	// Output:
	//  your IP: 3.3.3.3
}

type clientIPCtxKey struct{}

// Adds the "real" client IP to the request context under the clientIPCtxKey{} key.
// If the client IP couldn't be obtained, the value will be an empty string.
// We could use the RightmostNonPrivateStrategy concrete type, but instead we'll pass
// around the Strategy interface, in case we decide to change our strategy in the future.
func clientIPMiddleware(strat realclientip.Strategy, next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		clientIP := strat.ClientIP(r.Header, r.RemoteAddr)
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
	clientIP := r.Context().Value(clientIPCtxKey{})
	fmt.Fprintln(w, "your IP:", clientIP)
}
