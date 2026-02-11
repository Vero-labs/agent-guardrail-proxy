# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY backend/ ./backend/

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o /proxy ./backend/cmd/proxy

# Runtime stage
FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy binary
COPY --from=builder /proxy .

# Copy policies
COPY backend/internal/cedar/policies.cedar ./policies.cedar

# Environment
ENV PROVIDER_URL=https://api.groq.com/openai
ENV PROVIDER_TYPE=openai
ENV POLICY_PATH=/app/policies.cedar
ENV INTENT_ANALYZER_URL=http://localhost:8001

EXPOSE 8080

CMD ["./proxy"]
