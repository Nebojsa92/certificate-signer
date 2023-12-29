package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	log "github.com/sirupsen/logrus"
)

var (
	// CA for signing
	ca *KeyPair

	// web server
	server *http.Server
	wg     sync.WaitGroup

	// prometheus collectors
	requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "response_code"},
	)
)

func init() {
	// Configure the logging format and output
	log.SetFormatter(&log.TextFormatter{})
	log.SetOutput(os.Stdout)

	// register prometheus collectors
	prometheus.MustRegister(requestsTotal)
}

func handleCSRRequest(w http.ResponseWriter, r *http.Request) {
	// Check if the request method is POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		requestsTotal.WithLabelValues(r.Method, fmt.Sprintf("%d", http.StatusMethodNotAllowed)).Inc()
		return
	}

	// Read the request body (the CSR)
	csrPEM, err := io.ReadAll(r.Body)
	if err != nil {
		log.Errorf("Failed to read request body: %v", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		requestsTotal.WithLabelValues(r.Method, fmt.Sprintf("%d", http.StatusBadRequest)).Inc()
		return
	}

	// Sign the CSR
	certPEM, err := ca.SignCSR(csrPEM)
	if err != nil {
		log.Errorf("Failed to sign CSR: %v", err)
		http.Error(w, "Failed to sign CSR", http.StatusInternalServerError)
		requestsTotal.WithLabelValues(r.Method, fmt.Sprintf("%d", http.StatusInternalServerError)).Inc()
		return
	}

	requestsTotal.WithLabelValues(r.Method, fmt.Sprintf("%d", http.StatusOK)).Inc()
	// Respond with the signed certificate
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	w.Write(certPEM)
}

func handleReady(w http.ResponseWriter, r *http.Request) {
	// Respond with a 200 OK status code
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func generateRandomSerial() *big.Int {
	// Generate a random 128-bit number (16 bytes)
	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)

	// if rand.Read fails, generate from timestamp
	if err != nil {
		return new(big.Int).SetInt64(time.Now().UnixMilli())
	}
	// Convert the random bytes to a big.Int
	return new(big.Int).SetBytes(randomBytes)
}

func getEnv(key string, defaultValue string) string {
	value, exists := os.LookupEnv(key)
	if exists {
		return value
	}
	return defaultValue
}

func main() {
	var err error

	// init KeyPair
	certFilePath := getEnv("CA_CERT_FILE", "ca-cert.pem")
	keyFilePath := getEnv("CA_KEY_FILE", "ca-key.pem")
	ca, err = InitKeypair(certFilePath, keyFilePath)
	if err != nil {
		log.Fatalf("Failed to load CA certificate: %v", err)
		return
	}

	// Start the server in a separate goroutine
	go func() {
		serverPort := getEnv("PORT", "80")
		server = &http.Server{Addr: ":" + serverPort}

		http.HandleFunc("/ready", handleReady)
		http.HandleFunc("/csr", handleCSRRequest)
		http.Handle("/metrics", promhttp.Handler())

		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Failed to start the HTTP server: %v", err)
		}
	}()

	// Create a channel to listen for OS signals
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	// Wait for a signal to gracefully shutdown the server
	<-signalCh
	log.Println("Shutting down server...")

	// Create a context with a timeout to allow active connections to finish
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Wait for active connections to finish
	wg.Wait()

	// Shutdown the server gracefully
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Failed to shutdown server: %v", err)
	}
	log.Println("Server shutdown complete")
}
