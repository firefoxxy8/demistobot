package web

import (
	"net/http"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/demisto/demistobot/conf"
	"github.com/go-errors/errors"
)

func recoverHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.WithField("error", err).Warn("Recovered from error")
				log.Error(errors.Wrap(err, 2).ErrorStack())
				WriteError(w, ErrInternalServer)
			}
		}()

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (l *loggingResponseWriter) WriteHeader(status int) {
	l.status = status
	l.ResponseWriter.WriteHeader(status)
}

func loggingHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		lw := &loggingResponseWriter{w, 200}
		t1 := time.Now()
		next.ServeHTTP(lw, r)
		t2 := time.Now()
		log.Infof("[%s] %q %v %v", r.Method, r.URL.String(), lw.status, t2.Sub(t1))
	}

	return http.HandlerFunc(fn)
}

func acceptHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept"), "application/json") {
			log.Warn("Request without accept header received")
			WriteError(w, ErrNotAcceptable)
			return
		}

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

const (
	// xFrameOptionsHeader is the name of the x frame header
	xFrameOptionsHeader = `X-Frame-Options`
)

// Handle Clickjacking protection
func clickjackingHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(xFrameOptionsHeader, "DENY")
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func (ac *AppContext) authHandler(next http.Handler) http.Handler {
	fn := func(writer http.ResponseWriter, request *http.Request) {
		u, p, ok := request.BasicAuth()
		if !ok {
			WriteError(writer, ErrAuth)
			return
		}
		if u != conf.Options.User.Username || p != conf.Options.User.Password {
			WriteError(writer, ErrAuth)
			return
		}
		log.Debugf("User %v in request", u)
		next.ServeHTTP(writer, request)
	}
	return http.HandlerFunc(fn)
}
