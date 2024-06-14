# Use a builder image to compile the go lang code
FROM icr.io/codeengine/golang:alpine AS builder
COPY app-n-job.go /
RUN go build -o /app-n-job /app-n-job.go

# Copy the exe into a smaller base image for runtime
FROM icr.io/codeengine/alpine
COPY --from=0 /app-n-job /app-n-job
CMD /app-n-job
