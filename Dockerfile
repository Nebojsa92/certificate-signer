# Use the Go scratch image as the base image
FROM golang:1.21 AS builder

# Set the working directory
WORKDIR /app

# Copy the Go application source code
COPY . .

# Build the Go binary
# do I need to add go mod download???
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o certificateSigner .
RUN echo $CA_CERT | base64 -d > ca-cert.pem
RUN echo $CA_KEY | base64 -d > ca-key.pem

# Use scratch as the final base image
FROM scratch

# Copy the compiled binary from the builder stage
COPY --from=builder /app/certificateSigner /

# Copy ca-cert.pem and ca-key.pem to the image
COPY --from=builder /app/ca-cert.pem /
COPY --from=builder /app/ca-key.pem /

# Expose a port if your Go application listens on a port
EXPOSE 80

# Define the command to run your Go application
CMD ["/certificateSigner"]
