
// main.go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gorilla/sessions"
	"github.com/op/go-logging"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
)

type Article struct {
	Id      string `json:"Id"`
	Title   string `json:"Title"`
	Desc    string `json:"desc"`
	Content string `json:"content"`
}

type State struct {
	ClientID string
	ClientSecret string
	BackendURL string
	Issuer string
}

var log = logging.MustGetLogger("frontend-app")
var ApplicationState State
var tpl *template.Template
var sessionStore = sessions.NewCookieStore([]byte("session-key"))

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
}

func main() {
	parseEnvironmentVariables()
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/getArticles", getArticles)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/authorization-code/callback", AuthCodeCallbackHandler)

	log.Info("server starting at localhost:8080 ... ")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Errorf("the HTTP server failed to start: %s", err)
		os.Exit(1)
	}
}

// a function that gets the articles from the backend and visualizes them with some fancy format
func getArticles(w http.ResponseWriter, r *http.Request) {
	// checking the authorization header of the request
	log.Debugf("request header: %s\n", r.Header)
	//authorizationHeader := r.Header.Get("Authorization")

	if !isAuthenticated(r) {
		log.Debug("Not authenticated")
		return
	}
	session, _ := sessionStore.Get(r, "session-key")
	authorizationHeader := fmt.Sprintf("Bearer %s", session.Values["access_token"])

	// it should call the API on port 10000
	// after getting the Access token
	// The application should make sure that it has the access token, otherwise the API will just reject whatever request comes in
	// req, err := http.NewRequest("GET", "http://127.0.0.1:10000/articles", bytes.NewReader([]byte("")))
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/articles", ApplicationState.BackendURL), bytes.NewReader([]byte("")))
	if err != nil {
		log.Errorf("retrieving articles failed: %s", err)
	}
	req.Header.Set("Authorization", authorizationHeader)
	h := req.Header
	fmt.Printf("header: %s\n", h)

	client := http.Client{}
	response, err := client.Do(req)
	if err != nil {
		log.Errorf("Request failed: %s\n", err)
	}

	log.Debugf("response: %s\n", response)

	log.Debugf("response header: %s\n", response.Header)
	log.Debugf("Status code: %d\n", response.StatusCode)
	if response.StatusCode >= 400 {
		http.Error(w, response.Status, response.StatusCode)
		return
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Debugf("Error in the response: %s", fmt.Errorf(err.Error()))
		return
	}
	defer response.Body.Close()

	// maybe a data structure needs to be populated here (in the frontend) and reported properly
	// but this data should be stored only in the browser! it makes no sense to store this in the whole application
	// or maybe a session specific to the user?
	fmt.Printf("all the articles fetched from the backend: %s\n", body)

	var articles []Article
	json.Unmarshal(body, &articles)
	log.Debugf("articles: %+v", articles)

	type CustomData struct {
		IsAuthenticated bool
		Articles []Article
	}

	data := CustomData{
		IsAuthenticated: isAuthenticated(r),
		Articles: articles,
	}

	log.Debugf("data (getArticles): %+v", data)
	tpl.ExecuteTemplate(w, "showarticles.gohtml", data)
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	log.Debug("handleHome")
	log.Debugf("%+v", ApplicationState)

	type CustomData struct {
		IsAuthenticated bool
	}

	data := CustomData{
		IsAuthenticated: isAuthenticated(r),
	}

	log.Debugf("data: %+v", data)
	tpl.ExecuteTemplate(w, "home.gohtml", data)
}

func parseEnvironmentVariables() {
	clientId := os.Getenv("CLIENT_ID")
	if clientId == "" {
		log.Debugf("Could not resolve a CLIENT_ID environment variable.")
		os.Exit(1)
	}

	clientSecret := os.Getenv("CLIENT_SECRET")
	if clientSecret == "" {
		log.Debugf("Could not resolve a CLIENT_SECRET environment variable.")
		os.Exit(1)
	}

	backendUrl := os.Getenv("BACKEND_URL")
	if backendUrl == "" {
		log.Debugf("Could not resolve a BACKEND_URL environment variable.")
		os.Exit(1)
	}

	issuer := os.Getenv("ISSUER")
	if issuer == "" {
		log.Debugf("Could not resolve a ISSUER environment variable.")
		os.Exit(1)
	}

	ApplicationState = State{
		ClientID: clientId,
		ClientSecret: clientSecret,
		BackendURL: backendUrl,
		Issuer: issuer,
	}
}
