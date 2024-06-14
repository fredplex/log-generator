# Use a builder image to compile the go lang code
FROM icr.io/codeengine/golang:alpine AS builder
COPY app.go /
RUN go build -o log-generator ./app.go

# Copy the exe into a smaller base image for runtime
FROM icr.io/codeengine/alpine
COPY --from=0 log-generator /log-generator
CMD /log-generator
