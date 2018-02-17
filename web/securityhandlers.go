package web

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/demisto/demistobot/conf"
	"github.com/demisto/demistobot/domain"
	"github.com/demisto/demistobot/util"
	"github.com/demisto/slack"
	"github.com/wayn3h0/go-uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	slackOAuthEndpoint = "https://slack.com/oauth/authorize"
	slackOAuthExchange = "https://slack.com/api/oauth.access"
)

func (ac *AppContext) initiateOAuth(w http.ResponseWriter, r *http.Request) {
	// First - check that you are not from a banned country
	if isBanned(r.RemoteAddr) {
		http.Redirect(w, r, "/banned", http.StatusFound)
		return
	}
	// Now, generate a random state
	uu, err := uuid.NewRandom()
	if err != nil {
		panic(err)
	}
	scopes := []string{"bot", "groups:write", "channels:write"}
	oconf := &oauth2.Config{
		ClientID:     conf.Options.Slack.ClientID,
		ClientSecret: conf.Options.Slack.ClientSecret,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  slackOAuthEndpoint,
			TokenURL: slackOAuthExchange,
		},
	}
	ac.addState(uu.String(), scopes)
	url := oconf.AuthCodeURL(uu.String())
	logrus.Debugf("Redirecting to URL - %s", url)
	http.Redirect(w, r, url, http.StatusFound)
}

func (ac *AppContext) loginOAuth(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	code := r.FormValue("code")
	errStr := r.FormValue("error")
	if errStr != "" {
		WriteError(w, &Error{"oauth_err", 401, "Slack OAuth Error", errStr})
		logrus.Warnf("Got an error from Slack - %s", errStr)
		return
	}
	if state == "" || code == "" {
		WriteError(w, ErrMissingPartRequest)
		return
	}
	_, ok := ac.state(state)
	if !ok {
		WriteError(w, ErrBadRequest)
		return
	}
	ac.removeState(state)
	token, err := slack.OAuthAccess(conf.Options.Slack.ClientID,
		conf.Options.Slack.ClientSecret, code, "")
	if err != nil {
		WriteError(w, &Error{"oauth_err", 401, "Slack OAuth Error", err.Error()})
		logrus.Warnf("Got an error exchanging code for token - %v", err)
		return
	}
	logrus.Debugln("OAuth successful, creating Slack client")
	s, err := slack.New(
		slack.SetToken(token.Bot.BotAccessToken),
		slack.SetErrorLog(log.New(conf.LogWriter, "", log.Lshortfile)),
	)
	if err != nil {
		panic(err)
	}
	if logrus.GetLevel() == logrus.DebugLevel {
		slack.SetTraceLog(log.New(conf.LogWriter, "", log.Lshortfile))(s)
	}
	logrus.Debugln("Slack client created")
	// Get our own user id
	test, err := s.AuthTest()
	if err != nil {
		panic(err)
	}
	team, err := s.TeamInfo()
	if err != nil {
		panic(err)
	}
	user, err := s.UserInfo(test.UserID)
	if err != nil {
		panic(err)
	}
	logrus.Debugln("Got all details about myself from Slack")
	o := &domain.OAuth{User: user.User.Name, Email: user.User.Profile.Email, Team: team.Team.Name, Domain: team.Team.Domain, EmailDomain: team.Team.EmailDomain, Created: time.Now()}
	err = ac.r.SaveOAuth(o)
	if err != nil {
		logrus.WithError(err).Warnf("Unable to save history for team [%s], domain [%s], email [%s]", o.Team, o.Domain, o.Email)
	}
	logrus.Infof("User team [%s], domain [%s], email [%s] logged in\n", o.Team, o.Domain, o.Email)
	http.Redirect(w, r, fmt.Sprintf("/slack-details?b=%s&t=%s", token.Bot.BotAccessToken, token.AccessToken), http.StatusFound)
}

const googleRedirectURL = "https://demistobot.demisto.com/g"

func (ac *AppContext) googleOAuth(w http.ResponseWriter, r *http.Request) {
	// First - check that you are not from a banned country
	if isBanned(r.RemoteAddr) {
		http.Redirect(w, r, "/banned", http.StatusFound)
		return
	}
	// Now, generate a random state
	uu, err := uuid.NewRandom()
	if err != nil {
		panic(err)
	}
	scopes := strings.Split(r.FormValue("scopes"), ",")
	if len(scopes) == 0 {
		WriteError(w, ErrBadRequest)
		return
	}
	oconf := &oauth2.Config{
		ClientID:     conf.Options.Google.ClientID,
		ClientSecret: conf.Options.Google.ClientSecret,
		Scopes:       scopes,
		Endpoint:     google.Endpoint,
		RedirectURL:  googleRedirectURL,
	}
	ac.addState(uu.String(), scopes)
	url := oconf.AuthCodeURL(uu.String())
	logrus.Debugf("Generating Google URL - %s", url)
	writeJSON(w, map[string]string{"url": url})
}

func (ac *AppContext) googleLogin(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	code := r.FormValue("code")
	errStr := r.FormValue("error")
	if errStr != "" {
		WriteError(w, &Error{"oauth_err", 401, "Google OAuth Error", errStr})
		logrus.Warnf("Got an error from Google - %s", errStr)
		return
	}
	if state == "" || code == "" {
		WriteError(w, ErrMissingPartRequest)
		return
	}
	s, ok := ac.state(state)
	if !ok {
		WriteError(w, ErrBadRequest)
		return
	}
	ac.removeState(state)
	ctx := context.Background()
	oconf := &oauth2.Config{
		ClientID:     conf.Options.Google.ClientID,
		ClientSecret: conf.Options.Google.ClientSecret,
		Scopes:       s.scopes,
		Endpoint:     google.Endpoint,
		RedirectURL:  googleRedirectURL,
	}
	token, err := oconf.Exchange(ctx, code)
	if err != nil {
		WriteError(w, &Error{"oauth_err", 401, "Google OAuth Error", err.Error()})
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/google-details?a=%s&r=%s&e=%v", token.AccessToken, token.RefreshToken, token.Expiry.Unix()), http.StatusFound)
}

func (ac *AppContext) alexaLogin(w http.ResponseWriter, r *http.Request) {
	if isBanned(r.RemoteAddr) {
		http.Redirect(w, r, "/banned", http.StatusFound)
		return
	}

	clientID := r.FormValue("client_id")
	responseType := r.FormValue("response_type")
	errStr := r.FormValue("error")
	state := r.FormValue("state")
	redirectURI := r.FormValue("redirect_uri")
	scope := r.FormValue("scope")

	if errStr != "" {
		WriteError(w, &Error{"oauth_err", 401, "Alexa OAuth Error", errStr})
		logrus.Warnf("Got an error from Google - %v", errStr)
		return
	}

	if scope == "" || clientID == "" || state == "" || responseType == "" || redirectURI == "" {
		WriteError(w, ErrMissingPartRequest)
		return
	}

	if clientID != conf.Options.Alexa.ClientID || !strings.HasPrefix(redirectURI, "https://pitangui.amazon.com") || responseType != "token" || scope != "demisto_alexa_skill" {
		WriteError(w, ErrAuth)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/alexa-details?redirect_uri=%s&state=%s", redirectURI, state), http.StatusFound)
}

func (ac *AppContext) alexaRedirect(w http.ResponseWriter, r *http.Request) {
	if isBanned(r.RemoteAddr) {
		http.Redirect(w, r, "/banned", http.StatusFound)
		return
	}

	err := r.ParseForm()
	if err != nil {
		logrus.WithError(err).Error("Failed to parse alexa form body")
		WriteError(w, ErrBadRequest)
		return
	}

	state := r.FormValue("state")
	redirectURI := r.FormValue("redirectUrl")
	serverURL := r.FormValue("serverUrl")
	username := r.FormValue("username")
	password := r.FormValue("password")

	if state == "" || redirectURI == "" || serverURL == "" || username == "" || password == "" {
		WriteError(w, ErrMissingPartRequest)
		return
	}

	if !strings.HasPrefix(redirectURI, "https://pitangui.amazon.com") {
		WriteError(w, ErrMissingPartRequest)
		return
	}

	// Generate API key
	uu, err := uuid.NewRandom()
	if err != nil {
		logrus.WithError(err).Error("Failed generating api key")
		WriteError(w, ErrBadRequest)
		return
	}
	apiName := fmt.Sprintf("alexa_%s", time.Now().Format(time.RFC822))
	apiName = apiName[0:int(math.Min(float64(len(apiName)), 30))]
	apiKey := uu.String()

	// Create API key in the provided demisto server
	statusCode, _ := demisto.DoRequest(serverURL, username, password, "apikeys", "POST", fmt.Sprintf(`{"name":"%s","key":"%s"}`, apiName, apiKey))

	if statusCode != http.StatusOK {
		logrus.Errorf("Failed creating API Key in Demisto, status code: %v", statusCode)
		WriteError(w, ErrBadRequest)
		return
	}

	// Redirect back to alexa with the demisto URL and API Key as the token (base64 encoded)
	accessToken := fmt.Sprintf("%s|||%s", serverURL, apiKey)
	encodedAccessToken := base64.StdEncoding.EncodeToString([]byte(accessToken))
	http.Redirect(w, r, fmt.Sprintf("%s#state=%s&access_token=%s&token_type=Bearer", redirectURI, state, encodedAccessToken), http.StatusSeeOther)
}
