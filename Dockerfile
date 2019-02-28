FROM golang:1.9 as builder

RUN apt-get update \
    && apt-get install libpcap-dev net-tools iproute2 -y \
    && apt-get clean
RUN curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh

WORKDIR /go/src/github.com/letitbeat/packet-generator
COPY Gopkg.lock Gopkg.toml ./
RUN dep ensure --vendor-only

COPY . ./
#COPY ./src /go/src/nettools/src

#RUN go get -v ./...
#RUN go install -v ./...

RUN go test -v -cover ./...
RUN CGO_ENABLED=1 GOOS=linux go build -o main -v main.go

RUN chmod +x main
#CMD /bin/bash
EXPOSE 6000

CMD ["./main"]