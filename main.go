package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	log "github.com/sirupsen/logrus"

	integrity "github.com/Nebojsa92/certificate-signer/integrity"
	keypair "github.com/Nebojsa92/certificate-signer/keypair"
)

var (
	// environment variables
	certFilePath             = getEnv("CA_CERT_FILE", "ca-cert.pem")
	keyFilePath              = getEnv("CA_KEY_FILE", "ca-key.pem")
	serviceAccountJSONString = getEnv("PLAY_INTEGRITY_SA", "")
	serverPort               = getEnv("PORT", "80")
	environment              = getEnv("ENVIRONMENT", "development")
	appleDevelopmentTeamID   = getEnv("APPLE_DEVELOPMENT_TEAM_ID", "VG8GH7SAR8")

	// CA for signing
	ca *keypair.KeyPair

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

	playIntegrityManager *integrity.PlayIntegrityManager
	appAttestManager     *integrity.AppAttestManager
)

type CSRRequestBody struct {
	CSR         string          `json:"csr" schema:"csr"`
	Platform    string          `json:"platform" schema:"platform"`
	PackageName string          `json:"packageName" schema:"packageName"`
	Data        json.RawMessage `json:"data" schema:"data"`
}

func init() {
	// Configure the logging format and output
	log.SetFormatter(&log.TextFormatter{})
	log.SetOutput(os.Stdout)

	// register prometheus collectors
	prometheus.MustRegister(requestsTotal)

	var err error

	// Load the CA certificate and key
	ca, err = keypair.InitKeypair(certFilePath, keyFilePath)
	if err != nil {
		log.Fatalf("Failed to load CA certificate: %v", err)
	}

	// Initialize Play Integrity Manager
	playIntegrityManager, err = integrity.NewPlayIntegrityManager(serviceAccountJSONString, environment)
	if err != nil {
		log.Fatalf("Unable to create Play Integrity Manager: %v", err)
	}
	// Initialize Attest Manager
	appAttestManager, err = integrity.NewAppAttestManager(environment, appleDevelopmentTeamID)
	if err != nil {
		log.Fatalf("Unable to create Attest Integrity Manager: %v", err)
	}

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

func handleCSR2Request(w http.ResponseWriter, r *http.Request) {
	log.Info(r.URL.RequestURI())
	defer r.Body.Close()

	// Check if the request method is POST
	if r.Method != http.MethodPost {
		log.Errorf("Method not allowed: %v", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		requestsTotal.WithLabelValues(r.Method, fmt.Sprintf("%d", http.StatusMethodNotAllowed)).Inc()
		return
	}

	// Decode the JSON request
	var csrRequest CSRRequestBody
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&csrRequest)
	if err != nil {
		log.Errorf("Failed to decode JSON data: %v", err)
		http.Error(w, "Invalid JSON data", http.StatusBadRequest)
		requestsTotal.WithLabelValues(r.Method, fmt.Sprintf("%d", http.StatusBadRequest)).Inc()
		return
	}

	// Validate required fields
	if csrRequest.CSR == "" || csrRequest.Platform == "" || csrRequest.Data == nil || csrRequest.PackageName == "" {
		log.Errorf("Missing required fields in JSON data")
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		requestsTotal.WithLabelValues(r.Method, fmt.Sprintf("%d", http.StatusBadRequest)).Inc()
		return
	}

	// Verify the integrity token
	switch csrRequest.Platform {
	case "android":
		verdict, err := playIntegrityManager.VerifyIntegrityToken(csrRequest.Data, csrRequest.PackageName)
		if err != nil {
			log.Printf("Failed to verify integrity token: %v", err)
			http.Error(w, "Failed to verify integrity token", http.StatusInternalServerError)
			return
		}
		if !verdict {
			log.Printf("Integrity token verification failed")
			http.Error(w, "Integrity token verification failed", http.StatusUnauthorized)
			return
		}

	case "ios":
		verdict, err := appAttestManager.VerifyAttestationToken(csrRequest.Data, csrRequest.PackageName)
		if err != nil {
			log.Printf("Failed to verify attestation: %v", err)
			http.Error(w, "Failed to verify attestation", http.StatusInternalServerError)
			return
		}
		if !verdict {
			log.Printf("Attestation verification failed")
			http.Error(w, "Attestation verification failed", http.StatusUnauthorized)
			return
		}
	default:
	}
	log.Printf("verified: %s - %s", csrRequest.PackageName, csrRequest.Platform)

	// Sign the CSR
	certPEM, err := ca.SignCSR([]byte(csrRequest.CSR))
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

func getEnv(key string, defaultValue string) string {
	value, exists := os.LookupEnv(key)
	if exists {
		return value
	}
	return defaultValue
}

func main() {

	// Start the server in a separate goroutine
	go func() {
		server = &http.Server{Addr: ":" + serverPort}

		http.HandleFunc("/ready", handleReady)
		http.HandleFunc("/csr", handleCSRRequest)
		http.HandleFunc("/csr2", handleCSR2Request)
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
