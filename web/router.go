package web

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/demisto/demistobot/conf"
	"github.com/gorilla/context"
	"github.com/julienschmidt/httprouter"
	"github.com/justinas/alice"
)

// Main handlers
var public string

// ServeGzipFiles ...
func (r *Router) ServeGzipFiles(path string, root http.FileSystem) {
	if len(path) < 10 || path[len(path)-10:] != "/*filepath" {
		panic("path must end with /*filepath in path '" + path + "'")
	}

	r.GET(path, func(w http.ResponseWriter, req *http.Request, ps httprouter.Params) {
		req.URL.Path = ps.ByName("filepath")
		if strings.Contains(req.Header.Get("Accept-Encoding"), "gzip") &&
			(strings.HasSuffix(req.URL.Path, ".js") ||
				strings.HasSuffix(req.URL.Path, ".html") ||
				strings.HasSuffix(req.URL.Path, ".css")) {
			w.Header().Set("Content-Encoding", "gzip")
		}

		fileServer := http.FileServer(root)
		fileServer.ServeHTTP(w, req)
	})
}

func pageHandler(file string) func(w http.ResponseWriter, r *http.Request) {
	m := func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, public+file)
	}

	return m
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// Router

// Router handles the web requests routing
type Router struct {
	*httprouter.Router
	staticHandlers alice.Chain
	commonHandlers alice.Chain
	authHandlers   alice.Chain
	appContext     *AppContext
}

// Get handles GET requests
func (r *Router) Get(path string, handler http.Handler) {
	r.GET(path, wrapHandler(handler))
}

// Post handles POST requests
func (r *Router) Post(path string, handler http.Handler) {
	r.POST(path, wrapHandler(handler))
}

// Put handles PUT requests
func (r *Router) Put(path string, handler http.Handler) {
	r.PUT(path, wrapHandler(handler))
}

// Delete handles DELETE requests
func (r *Router) Delete(path string, handler http.Handler) {
	r.DELETE(path, wrapHandler(handler))
}

func handlePublicPath(pubPath string) {
	switch {
	// absolute path
	case len(pubPath) > 1 && (pubPath[0] == '/' || pubPath[0] == '\\'):
		public = pubPath
	// absolute path win
	case len(pubPath) > 2 && pubPath[1] == ':':
		public = pubPath
	// relative
	case len(pubPath) > 1 && pubPath[0] == '.':
		public = pubPath
	default:
		public = "./" + pubPath
	}
	if public[len(public)-1] != '/' && public[len(public)-1] != '\\' {
		public = fmt.Sprintf("%s%c", public, os.PathSeparator)
	}
	log.Infof("Using public path %v", public)
}

// New creates a new router
func New(appC *AppContext, pubPath string) *Router {
	handlePublicPath(pubPath)
	r := &Router{Router: httprouter.New()}
	r.appContext = appC
	r.staticHandlers = alice.New(context.ClearHandler, loggingHandler, recoverHandler, clickjackingHandler)
	r.commonHandlers = r.staticHandlers.Append(acceptHandler)
	r.authHandlers = r.commonHandlers.Append(appC.authHandler)
	r.registerStaticHandlers()
	r.registerApplicationHandlers()
	return r
}

// Static handlers
func (r *Router) registerStaticHandlers() {
	// 404 not found handler
	r.NotFound = r.staticHandlers.ThenFunc(notFoundHandler)

	// Static
	r.Get("/", r.staticHandlers.ThenFunc(pageHandler("index.html")))
	r.Get("/favicon.ico", r.staticHandlers.ThenFunc(pageHandler("favicon.ico")))
	r.Get("/style.css", r.staticHandlers.ThenFunc(pageHandler("style.css")))
	r.Get("/404", r.staticHandlers.ThenFunc(pageHandler("404.html")))
	r.Get("/banned", r.staticHandlers.ThenFunc(pageHandler("banned.html")))
	r.Get("/details", r.staticHandlers.ThenFunc(pageHandler("details.html")))
	r.ServeGzipFiles("/assets/*filepath", http.Dir(public+"assets"))
}

// handlers that are available just in stand alone mode and not in proxy mode
func (r *Router) registerApplicationHandlers() {
	// Security
	r.Get("/add", r.staticHandlers.ThenFunc(r.appContext.initiateOAuth))
	r.Get("/auth", r.staticHandlers.ThenFunc(r.appContext.loginOAuth))
	// Log
	r.Get("/log", r.authHandlers.ThenFunc(r.appContext.logHandler))
}

func wrapHandler(h http.Handler) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		context.Set(r, "params", ps)
		h.ServeHTTP(w, r)
	}
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}

func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, conf.Options.ExternalAddress+r.RequestURI, http.StatusMovedPermanently)
}

// Serve - creates the relevant listeners
func (r *Router) Serve() {
	var err error
	if conf.Options.SSL.Cert != "" {
		// First, listen on the HTTP address with redirect
		go func() {
			err := http.ListenAndServe(conf.Options.HTTPAddress, http.HandlerFunc(redirectToHTTPS))
			if err != nil {
				log.Fatal(err)
			}
		}()
		addr := conf.Options.Address
		if addr == "" {
			addr = ":https"
		}
		server := &http.Server{Addr: conf.Options.Address, Handler: r}
		config, err := GetTLSConfig()
		if err != nil {
			log.Fatal(err)
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatal(err)
		}
		tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, config)
		err = server.Serve(tlsListener)
	} else {
		err = http.ListenAndServe(conf.Options.Address, r)
	}
	if err != nil {
		log.Fatal(err)
	}
}

// 404 not found handler
func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/404", http.StatusSeeOther)
}

// GetTLSConfig ...
func GetTLSConfig() (config *tls.Config, err error) {
	certs := make([]tls.Certificate, 1)
	certs[0], err = tls.X509KeyPair([]byte(conf.Options.SSL.Cert), []byte(conf.Options.SSL.Key))
	if err != nil {
		return nil, err
	}
	config = &tls.Config{
		NextProtos:               []string{"http/1.1"},
		MinVersion:               tls.VersionTLS12,
		Certificates:             certs,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
	}
	return
}
