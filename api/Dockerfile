FROM golang:1.16.2

COPY main.go /main.go

RUN mkdir /app
WORKDIR /app

COPY .. .

RUN chmod 777 /app/main.go
RUN go get github.com/gorilla/mux
RUN go build -o /to-run
RUN chmod 777 /to-run

EXPOSE 10000

CMD ["/to-run"]
