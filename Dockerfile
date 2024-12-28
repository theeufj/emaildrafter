# Use the official Golang image as the base image
FROM golang:1.23-alpine AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Copy the .env file
COPY .env .env

# Build the Go app
RUN go build -o main .

# Start a new stage from scratch
FROM alpine:latest  

# Set the Current Working Directory inside the container
WORKDIR /root/

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/main .

# Copy the .env file from the builder stage
COPY --from=builder /app/.env .env

# Copy the templates directory
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/cert.pem  cert.pem
COPY --from=builder /app/key.pem  key.pem

# Install PostgreSQL client tools
RUN apk add --no-cache postgresql-client

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["./main"]