package main

import (
  "github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
  "net/http"
  "html/template"
  "encoding/json"
  "encoding/base64"
	"encoding/gob"
  "fmt"
  "strings"
  "os"
  "io/ioutil"
)

var (
  store = sessions.NewCookieStore([]byte("klsdjflweoijfwelkjfwlefjoweijfkwjf0923jf23j09lwekldnlsknw"))
  sessionName = "go-outh-starter"
  CLIENTID string
	CLIENTSECRET string
  OauthURLParams string
  OauthDomain string
  DBURL string
  BASEURL = "http://localhost"
  LOCALBASEURL string // used for testing purposes
  LoginCfg *oauth2.Config

  startPageTemplate = template.Must(template.ParseFiles("tmpl/start.tmpl")) // root page
  notAuthenticatedTemplate = template.Must(template.ParseFiles("tmpl/noPermission.tmpl")) // login failure
)



/*
	this is the standard error struct sent back to the frontend in case of internal errors
*/
type statusResponse struct {
	Status string `json:"errmessage"`
}

/*
	Build the statusResponse struct and return marshalled version of struct
*/
func (sr *statusResponse) getJson(s string) []byte {
	sr.Status = s
	jsr, _ := json.Marshal(sr)
	return jsr
}


/*
	Root handler first checks if user is logged in.  If not logged in then authenticate
	useing oauth2.  The return of the AuthCodeURL will be https://accounts.google.com/o/oauth2/auth

	If user is logged in then we just load the start page

	Authentication Logic
	- access_type=offline means request access token with offline access
	  access token expires after 1 hour so if user is logging in for the first time Google will prompt user
	  to grant permission for offline access.  Upon accepting offline access google returns access token with refresh token

	- Once refresh toekn is aquired for the first time we insert it into the database for future retrevial

	- We use customers access token to send a gmail and store this access token a browser cookie along with user name
      if the access token expires then email will be sent using the refresh token
    - After 12 hours the users cookie will expire and they will need to travel through the roothandler again for login

*/
func rootHandler(w http.ResponseWriter, r *http.Request) {

	if !verifyLogin(r) {
		url := LoginCfg.AuthCodeURL("")
		url = url + OauthURLParams
		// this will preseve the casenumber in the URI path during Oauth2 redirect
		params := r.URL.Query()
		paramkeys := make([]string, 0)
		for k := range params {
			for i := range params[k] {
				paramkeys = append(paramkeys, k+"="+params[k][i])
			}
		}
		if len(paramkeys) > 0 {
			url = url + "&state=" + base64.StdEncoding.EncodeToString([]byte(strings.Join(paramkeys, "?")))
		}

		http.Redirect(w, r, url, http.StatusFound)
		return
	}

	// if user is not using https then redirect them
	if ( r.Header.Get("x-forwarded-proto") != "https" && BASEURL != LOCALBASEURL) {
		fmt.Printf("TLS handshake is https=false x-forwarded-proto=%s\n", r.Header.Get("x-forwarded-proto"))
		http.Redirect(w, r, BASEURL, http.StatusFound)
		return
	}

  startPageTemplate.Execute(w, "")
}

/*
	This is the oauth2 callback which will authenticate the user and get the tokent
	A token will last for 3600 seconds and can be used to access the users gmail services.
	We drop the token in the LoginCfg.Exchange return because we don't need for intial login

	Once user is authenticated then create a new session and set maxage to 24 hours. This means
	user will be logged in for 24 hours
*/
func logincallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	tok, err := LoginCfg.Exchange(oauth2.NoContext, code)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		notAuthenticatedTemplate.Execute(w, err.Error())
		return
	}

  // get the users name from google
CLIENT := LoginCfg.Client(oauth2.NoContext, tok)
resp, ee := CLIENT.Get("https://www.googleapis.com/plus/v1/people/me")
if ee != nil {
  fmt.Fprintf(w, "Fetching profile err: %s", ee)
  return
}
defer resp.Body.Close()
body, _ := ioutil.ReadAll(resp.Body)
var p ProfileBlob
json.Unmarshal(body, &p)

/*
  There is a case where user has an expired ticket
  rootHandler Calls verifyLogin which returns false because of expired cookie error.
  So the user now has to relogin.  So trash the cookie if it exists and start fresh
*/
session, _ := store.Get(r, sessionName)
session.Values["LoggedIn"] = "no"
session.Save(r, w)

session, err = store.Get(r, sessionName)
if err != nil {
  w.WriteHeader(http.StatusUnauthorized)
  notAuthenticatedTemplate.Execute(w, template.HTML(err.Error()))
  return
}

for i := range p.Emails {
		if strings.Contains(p.Emails[i].Value, OauthDomain) {
			session.Values["Email"] = p.Emails[i].Value
			break
		}
	}

	/*
		Check if refresh token was return by google
		- if no refresh token then check to see if we have one in the database.  If its not in the databse then send the user
		  back to google with approval_prompt=force to ensure we get a new refresh token
		- If refresh token is supplied then update the database with the new token
	*/
	tp := new(TokenTuple)
	if tok.RefreshToken == "" {
		tp, err = GetToken(session.Values["Email"].(string))
		if err != nil {
			// so in this case user did get a access token it came with no refresh token. Since the database does not have the
			// refresh token we must force the user to login again
			http.Redirect(w, r, LoginCfg.AuthCodeURL("") + OauthURLParams + "&approval_prompt=force", http.StatusFound)
			return
		}
	} else {
		// we have a refresh token so update databse
		tp = &TokenTuple{0, session.Values["Email"].(string), tok.RefreshToken}
		err = tp.UpdateToken()
		if err != nil {
			fmt.Printf("Token Database Update Error: %s", err) // can't get to specific as it could lean to security issue
			w.WriteHeader(http.StatusUnauthorized)
			notAuthenticatedTemplate.Execute(w, template.HTML(err.Error()))
			return
		}
	}

  /*
		Some notes about the access token.
		http://stackoverflow.com/questions/10827920/google-oauth-refresh-token-is-not-being-received

		Basically we need to request offline access to the users google applications so we get a refresh token
		When we attempt to make a google api call we need a access token.  the access token only lasts for 1 hour
		but we allow a users session to last for 24 hours.  So we need google to give us the refresh token.  to force
		the refresh token we need to add &access_type=offline&approval_prompt=force to the auth URL as per above
	*/
  session.Values["LoggedIn"] = "yes"
	session.Values["username"] = p.DisplayName
	session.Values["GCODE"] = code
	session.Values["AuthToken"] = tok
	session.Options = &sessions.Options{
		Path:   "/",
		MaxAge: 43200, // 12 hours even though user can refresh token up to 24 hours.
	}
	session.Save(r, w)

	url := ""
	if r.FormValue("state") != "" {
		url = BASEURL + "/index.html?state=" + r.FormValue("state")
	} else {
		url = BASEURL + "/index.html"
	}

	/*
		We redirect to index.html so we can clean up the users URL info and drop logincallback.
		This will prevent errors should user attemmpt to refresh the page
		We do not want to send the user back to parent because because it could cause an infinite Oauth2 loop
	*/
	http.Redirect(w, r, url, http.StatusFound)

}

/*
	After a successful new login this function will serve the main page
	If user logs in with cookie then roothangler will take of this.
	The only flow i see here is if the user decides to book mark index.html.
	Bookmarking index.html will never allow the user to loging.
	So in error we offer hints on how to login again

*/
func LoginStart(w http.ResponseWriter, r *http.Request) {
	if !verifyLogin(r) {
		http.Redirect(w, r, BASEURL, http.StatusFound)
		return
	}

	// if user is not using https then redirect them
	if ( r.Header.Get("x-forwarded-proto") != "https" && BASEURL != LOCALBASEURL) {
		fmt.Printf("TLS handshake is https=false x-forwarded-proto=%s\n", r.Header.Get("x-forwarded-proto"))
		http.Redirect(w, r, BASEURL, http.StatusFound)
		return
	}

	startPageTemplate.Execute(w, "")
}

/*
	Set the users session cookie key "LoggedIn" to no and redirect user back to
	root page for re-authentication
*/
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, sessionName)
	session.Values["LoggedIn"] = "no"
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

/*
	Grabs the users session cookie and verifies login
	return true if logged in and false if not
*/
func verifyLogin(r *http.Request) bool {
	session, err := store.Get(r, sessionName)
	if err != nil {
		fmt.Printf("Failed to get session: %s", err)
		return false
	}
	if session.Values["LoggedIn"] != "yes" {
		return false
	}
	return true
}



/*
	unmarshal ENV variable VCAP_APPLICATION and set the BASEURL string
	default baseurl to http://localhost:8080 for testing
*/
func ParseServiceCred() {
	VCAP_ENV := os.Getenv("VCAP_APPLICATION")
	LOCALBASEURL = BASEURL + ":" + os.Getenv("PORT")
	if VCAP_ENV == "" {
		fmt.Println("VCAP_APPLICATION ENV variable not found")
		BASEURL += ":" + os.Getenv("PORT")
		fmt.Printf("Using url %s for callback\n", BASEURL)
		return
	}
	fmt.Printf("%v\n", VCAP_ENV)

	type VCAP_APP struct {
		URIs []string `json:"uris"`
	}
	MyApp := new(VCAP_APP)

	err := json.Unmarshal([]byte(VCAP_ENV), &MyApp)
	if err != nil {
		fmt.Printf("Failed to decode VCAP_APP: %s\n", err)
		return
	}

	for i := range MyApp.URIs {
		BASEURL = "https://" + MyApp.URIs[i]
		break
	}
	fmt.Printf("Using url %s for callback\n", BASEURL)
}

func main() {
  gob.Register(&oauth2.Token{})
  ParseServiceCred()


  CLIENTID = os.Getenv("CLIENTID")
	CLIENTSECRET = os.Getenv("CLIENTSECRET")
  OauthURLParams = os.Getenv("OAUTHURLPARAMS")
  OauthDomain = os.Getenv("OAUTHDOMAIN")
  DBURL = os.Getenv("DBURL")

  LoginCfg = &oauth2.Config{
		ClientID:     CLIENTID,
		ClientSecret: CLIENTSECRET,
		RedirectURL:  BASEURL + "/logincallback",
		Scopes:       []string{"profile", "email", "https://www.googleapis.com/auth/gmail.compose"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/auth",
			TokenURL: "https://accounts.google.com/o/oauth2/token",
		},
	}

  fmt.Printf("Going to use port %s\n", os.Getenv("PORT"))
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/index.html", LoginStart)
	http.HandleFunc("/logincallback", logincallbackHandler)
	http.HandleFunc("/logout/", logoutHandler)

  // File serving handlers
	http.Handle("/img/", http.FileServer(http.Dir("")))
  http.Handle("/fonts/", http.FileServer(http.Dir("")))
	http.Handle("/js/", http.FileServer(http.Dir("")))
	http.Handle("/css/", http.FileServer(http.Dir("")))
	err := http.ListenAndServe(":"+os.Getenv("PORT"), context.ClearHandler(http.DefaultServeMux))
	if err != nil {
		fmt.Printf("Failed to start http server: %s\n", err)
	}
	return
}
