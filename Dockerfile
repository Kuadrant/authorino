FROM golang:1.13 as build

ENV GO111MODULE=on

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o authorino main.go

FROM gcr.io/distroless/base
COPY --from=build /app/authorino /

EXPOSE 50051

ENTRYPOINT ["/authorino"]
