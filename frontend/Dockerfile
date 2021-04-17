FROM golang:1.16.2

COPY main.go /main.go
COPY login.go /login.go
COPY templates /templates

RUN mkdir /app
WORKDIR /app

COPY . .

RUN chmod 777 /app/main.go
RUN go get github.com/gorilla/mux
RUN go get github.com/gorilla/sessions
RUN go get github.com/nirasan/go-oauth-pkce-code-verifier
RUN go get github.com/op/go-logging
RUN go build -o /to-run
RUN chmod 777 /to-run

EXPOSE 8080

CMD ["/to-run"]
