package web

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/demisto/demistobot/conf"
	"github.com/demisto/demistobot/domain"
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
	http.Redirect(w, r, fmt.Sprintf("/details?b=%s&t=%s", token.Bot.BotAccessToken, token.AccessToken), http.StatusFound)
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
