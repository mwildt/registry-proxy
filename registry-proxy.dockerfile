FROM golang:latest AS build

RUN mkdir /src
WORKDIR /src
COPY . /src

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o registryProxy ./cmd/proxy/main.go
RUN ls -la

RUN mkdir -p .empty/dir

FROM ubuntu:24.04
COPY --from=build /src/registryProxy /opt/registryProxy

WORKDIR /app

ENTRYPOINT ["/app/registryProxy"]