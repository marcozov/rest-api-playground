package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"time"
)

type Exchange struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	AccessToken      string `json:"access_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
	IdToken          string `json:"id_token,omitempty"`
}

const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
var src = rand.NewSource(time.Now().UnixNano())
var randomState string
var codeVerifier string

func RandStringBytesMaskImprSrc(n int) string {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

func isAuthenticated(r *http.Request) bool {
	session, err := sessionStore.Get(r, "session-key")
	log.Debugf("session (is authenticated): %+v", session)
	if err != nil {
		log.Errorf("Error in retrieving the session: %s", err)
		return false
	}

	return session.Values["access_token"] != nil && session.Values["access_token"] != ""
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	//codeVerifier, err  := cv.CreateCodeVerifier()
	//if err != nil {
	//	log.Errorf("Error in creating the code verifier: %s", err)
	//	return
	//}
	// TODO: replace these hardcoded values with randomly generated ones
	codeVerifier = "3d18645a2f21effd9268ebf4f3c9438cce4d874491714e34f239ffd6"
	codeChallenge := "k5XSTSbC1AXVWBtxKuNA3VZQZUyxDFbMMuTdTjWIIgk"
	log.Debugf("Code verifier: %s", codeVerifier)
	//codeChallenge := codeVerifier.CodeChallengeS256()
	log.Debugf("Code challenge: %s", codeChallenge)

	q := r.URL.Query()
	q.Add("client_id", ApplicationState.ClientID)
	q.Add("response_type", "code")
	q.Add("scope", "openid profile email")
	q.Add("code_challenge", codeChallenge)
	q.Add("code_challenge_method", "S256")
	state := RandStringBytesMaskImprSrc(16)
	q.Add("state", state)
	randomState = state
	q.Add("redirect_uri", "http://localhost:8080/authorization-code/callback")

	redirectPath := fmt.Sprintf("%s/v1/authorize?%s", ApplicationState.Issuer, q.Encode())
	http.Redirect(w, r, redirectPath, http.StatusFound)
}

func AuthCodeCallbackHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	log.Infof("query: %s", q)

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if state != randomState {
		log.Errorf("State mismatch")
		return
	}

	values := url.Values{
		"grant_type": []string{ "authorization_code" },
		"redirect_uri": []string{ "http://localhost:8080/authorization-code/callback" },
		"client_id": []string{ ApplicationState.ClientID },
		"client_secret": []string{ ApplicationState.ClientSecret },
		"code_verifier": []string{ codeVerifier },
		"code": []string{ code },
	}

	tokenUrl := fmt.Sprintf("%s/v1/token", ApplicationState.Issuer)

	response, err := http.PostForm(tokenUrl, values)
	if err != nil {
		log.Errorf("Error in sending the POST request: %s", err)
		return
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Errorf("error reading the response body: %+v", err.Error())
		return
	}

	defer response.Body.Close()
	var exchange Exchange

	json.Unmarshal(body, &exchange)

	session, err := sessionStore.Get(r, "session-key")
	if err != nil {
		log.Errorf("Error in retrieving the session: %s", err)
	}

	log.Debugf("exchange: %+v", exchange)
	session.Values["access_token"] = exchange.AccessToken
	log.Debugf("session (auth code callback): %+v", session)
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	log.Debug("LogoutHandler")
	session, err := sessionStore.Get(r, "access_token")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	// deleting the session state (i.e., the saved tokens)
	delete(session.Values, "id_token")
	delete(session.Values, "access_token")

	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}
