# Certificate Signer Server

This is a simple Go application that acts as a Certificate Signer server. It provides an HTTP endpoint for signing Certificate Signing Requests (CSRs).
## Requirements
Server won't start without cert key and cert file in PEM format.
(check the Configuration section)
## Usage
To run the server, you can use Docker or build and run it locally.
Server need to have specified 
Here are the steps:
### Docker (Recommended) [WIP: Docker not configured yet]
1. Build the Docker image:
    ```
    docker build -t my-ca-server .
    ```
2. Run the Docker container:
    ```
    docker run -p 80:80 my-certificate-signer
    ```
### Local Build
1. Clone the repository:
    ```
    git clone https://github.com/Nebojsa92/certificate-signer.git
    cd certificate-signer
    ```
2. Download dependencies and build the Go application:
    ```
    go mod download
    go build
    ```
3. Run the binary:
    ```
    ./certificateSigner
    ```

## Configuration
You can configure the CA server using environment variables:
| Environment variable | Description |
|-|-|
| ```CA_CERT_FILE``` | Path to the CA certificate file (default: ```ca-cert.pem```). |
| ```CA_KEY_FILE```  | Path to the CA private key file (default: ```ca-key.pem```).
| ```PORT``` | Port on which the server listens (default: 80). |

## Endpoints
| Endpoint | Description |
|-|-|
| ```/csr``` | HTTP endpoint for submitting Certificate Signing Requests (CSRs).|
| ```/metrics``` | Prometheus metrics endpoint for monitoring. |

## Prometheus Metrics
The server exports the following Prometheus metrics:

| Metric | Description |
|-|-|
| ```http_requests_total``` | Total number of HTTP requests with labels for HTTP method and response code.|
