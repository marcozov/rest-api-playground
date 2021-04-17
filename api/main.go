
// main.go
package main

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "github.com/dgrijalva/jwt-go"
    "github.com/gorilla/mux"
    "github.com/lestrrat-go/jwx/jwk"
    jwtverifier "github.com/okta/okta-jwt-verifier-golang"
    "github.com/op/go-logging"
    "io/ioutil"
    "net/http"
    "os"
    "strings"
    "time"
)

// Article - Our struct for all articles
type Article struct {
    Id      string `json:"Id"`
    Title   string `json:"Title"`
    Desc    string `json:"desc"`
    Content string `json:"content"`
}

type State struct {
    Issuer string
    JwksUri string
    Audience string
}

var ApplicationState State
var Articles []Article
var log = logging.MustGetLogger("api-app")

func homePage(w http.ResponseWriter, r *http.Request) {
    log.Info(w, "Welcome to the HomePage!")
    log.Info("Endpoint Hit: homePage")
}

func returnAllArticles(w http.ResponseWriter, r *http.Request) {
    log.Info("Endpoint Hit: returnAllArticles")
    if !validateJWT(w, r) {
        // json.NewEncoder(w).Encode(http.StatusUnauthorized)
        http.Error(w, "Not authorized", http.StatusUnauthorized)
        return
    }

    json.NewEncoder(w).Encode(Articles)
}

func returnSingleArticle(w http.ResponseWriter, r *http.Request) {
    log.Info("Endpoint Hit: returnSingleArticle")
    //validateJWT(w, r)
    vars := mux.Vars(r)
    key := vars["id"]

    for _, article := range Articles {
        if article.Id == key {
            json.NewEncoder(w).Encode(article)
        }
    }
}


func createNewArticle(w http.ResponseWriter, r *http.Request) {
    log.Info("Endpoint Hit: createNewArticle")
    //validateJWT(w, r)
    // get the body of our POST request
    // unmarshal this into a new Article struct
    // append this to our Articles array.    
    reqBody, _ := ioutil.ReadAll(r.Body)
    var article Article 
    json.Unmarshal(reqBody, &article)
    // update our global Articles array to include
    // our new Article
    Articles = append(Articles, article)

    json.NewEncoder(w).Encode(article)
}

func deleteArticle(w http.ResponseWriter, r *http.Request) {
    log.Debug("Endpoint Hit: deleteArticle")
    //validateJWT(w, r)
    vars := mux.Vars(r)
    id := vars["id"]

    for index, article := range Articles {
        if article.Id == id {
            Articles = append(Articles[:index], Articles[index+1:]...)
        }
    }
}

func validateJWT(w http.ResponseWriter, r *http.Request) bool {
	authorizationHeader  := r.Header.Get("Authorization")
    log.Debug("Validating JWT..")
	if authorizationHeader == "" {
        log.Debug("Authorization header not found.")
	    return false
    }
    bearerToken := strings.Split(authorizationHeader, "Bearer ")[1]

	// use some library to validate JWT
	// run some curl introspect --> but it requires an okta application for doing so.
	// check https://speakerdeck.com/aaronpk/securing-your-apis-with-oauth-2-dot-0?slide=72
    log.Debugf("bearer token: %s", bearerToken)

	// validating access token with okta library: https://developer.okta.com/docs/guides/validate-access-tokens/go/overview/
	toValidate := map[string]string{}
    toValidate["aud"] = "api://default"
    jwtVerifierSetup := jwtverifier.JwtVerifier{
       Issuer: "https://dev-01793070.okta.com/oauth2/default",
       ClaimsToValidate: toValidate,
    }
    _, err := jwtVerifierSetup.New().VerifyAccessToken(bearerToken)

    if err != nil {
        log.Debugf("Error in verifying access token: %+v", err)
        return false
    }

    // Using a generic library
    // need to verify the token signature --> keys needed?
    // need to verify the claims
    // useful links: https://stackoverflow.com/questions/41077953/go-language-and-verify-jwt
    keyFunc := func(token *jwt.Token) (interface{}, error) {
        // checking signing method
        if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }

        // claims verification
        log.Debugf("token claims: %+v", token.Claims)
        claims, ok := token.Claims.(jwt.MapClaims)
        if !ok {
            return nil, errors.New("couldn't parse claims")
        }
        log.Debug("JWT claims:\n")
        for key, value := range claims {
            log.Debugf("%s\t%v\n", key, value)
        }

        // audience verification
        //if !claims.VerifyAudience("api://default", true) {
        if !claims.VerifyAudience(ApplicationState.Audience, true) {
        	audience, ok := claims["aud"]
        	if !ok {
                return nil, errors.New("audience could not be retrieved")
            }
            return nil, errors.New(fmt.Sprintf("the audience does not correspond to the expected one. Desired: %s, actual: %s\n", ApplicationState.Audience, audience))
        }

        // expiration time verification
        if !claims.VerifyExpiresAt(time.Now().UTC().Unix(), true) {
            exp, ok := claims["exp"]
            if !ok {
                return nil, errors.New("expiration time could not be retrieved")
            }
            return nil, errors.New(fmt.Sprintf("the token is already expired: %s", exp))
        }

        // issuer verification
        //if !claims.VerifyIssuer("https://dev-01793070.okta.com/oauth2/default", true) {
        if !claims.VerifyIssuer(ApplicationState.Issuer, true) {
            issuer, ok := claims["iss"]
            if !ok {
                return nil, errors.New("issuer time could not be retrieved")
            }
            return nil, errors.New(fmt.Sprintf("the issuer is not the expected one: %s", issuer))
        }

        // introspect endpoint to verify the token directly with the authorization server
        // introspectionEndpoint := "https://dev-01793070.okta.com/oauth2/default/v1/introspect"
        // token, clientID, clientSecret? Yes, the api must be backed up by another application.. it's still a client from the point of view of okta

        jwk, err := jwk.Fetch(context.Background(), ApplicationState.JwksUri)
        if err != nil {
            log.Debugf("Error in fetching JWKs: %+v", err)
        }
        keyID, ok := token.Header["kid"].(string)
        if !ok {
            return nil, errors.New("expecting JWT header to have string kid")
        }
        log.Debugf("keyID: %s", keyID)

        key, ok := jwk.LookupKeyID(keyID)
        if !ok {
            return nil, errors.New("error retrieving the key")
        }
        var pubkey interface{}
        err = key.Raw(&pubkey)
        log.Debugf("key: %s", pubkey)

        return pubkey, nil
    }

    // parsing the JWT and validating the signature
    // keyFunc will automatically verify the signature with the keys retrieved via jwksUri
    // I can add any custom check in this function
    token, err := jwt.Parse(bearerToken, keyFunc)
    if err != nil {
       log.Debugf("Error while parsing the JWT : %+v", err)
       return false
    }
    log.Debugf("retrieved token: %s", token)

	return true
}

func handleRequests() {
    myRouter := mux.NewRouter().StrictSlash(true)
    myRouter.HandleFunc("/", homePage)
    myRouter.HandleFunc("/articles", returnAllArticles)
    myRouter.HandleFunc("/article", createNewArticle).Methods("POST")
    myRouter.HandleFunc("/article/{id}", deleteArticle).Methods("DELETE")
    myRouter.HandleFunc("/article/{id}", returnSingleArticle)
    log.Debug("server starting at localhost:10000 ... ")
    log.Fatal(http.ListenAndServe(":10000", myRouter))
}

func main() {
    parseEnvironmentVariables()
    log.Debugf("Current state: %+v", ApplicationState)
    Articles = []Article{
        Article{Id: "1", Title: "Hello", Desc: "Article Description", Content: "Article Content"},
        Article{Id: "2", Title: "Hello 2", Desc: "Article Description", Content: "Article Content"},
    }
    handleRequests()
}

func parseEnvironmentVariables() {
    issuer := os.Getenv("ISSUER")
    if issuer == "" {
        log.Debugf("Could not resolve a ISSUER environment variable.")
        os.Exit(1)
    }

    jwksUri := os.Getenv("JWKS_URI")
    if jwksUri == "" {
        log.Debugf("Could not resolve a JWKS_URI environment variable.")
        os.Exit(1)
    }

    audience := os.Getenv("AUDIENCE")
    if audience == "" {
        log.Debugf("Could not resolve a AUDIENCE environment variable.")
        os.Exit(1)
    }

    ApplicationState = State{
        Issuer: issuer,
        JwksUri: jwksUri,
        Audience: audience,
    }
}
