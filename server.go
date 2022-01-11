package wt

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "expvar"         // to be used for monitoring, see https://github.com/divan/expvarmon
	_ "net/http/pprof" // profiler, see https://golang.org/pkg/net/http/pprof/

	"github.com/gorilla/csrf"
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
	"golang.org/x/crypto/acme/autocert"
)

// ServerRouter represents pointer to http Handler
type ServerRouter *http.Handler

// ServerConfiguration stores server configuration parameters
type ServerConfiguration struct {
	Port          int      `json:"port"`         // server port number
	Base          string   `json:"base"`         // base URL
	Verbose       int      `json:"verbose"`      // verbose output
	ServerCrt     string   `json:"serverCrt"`    // path to server crt file
	ServerKey     string   `json:"serverKey"`    // path to server key file
	RootCA        string   `json:"rootCA"`       // RootCA file
	CSRFKey       string   `json:"csrfKey"`      // CSRF 32-byte-long-auth-key
	Production    bool     `json:"production"`   // production server or not
	LimiterPeriod string   `json:"rate"`         // limiter rate value
	LogFile       string   `json:"log_file"`     // server log file
	LetsEncrypt   bool     `json:"lets_encrypt"` // start LetsEncrypt HTTPs server
	DomainNames   []string `json:"domain_names"` // list of domain names to use
	StaticDir     string   `json:"static"`       // location of static files
	Templates     string   `json:"templates"`    // location of server templates
}

// NewServerConfig creates new ServerConfigruation with some
// default parameters
func NewServerConfig() ServerConfiguration {
	config := ServerConfiguration{
		LimiterPeriod: "100-S",
		Port:          8888,
	}
	return config
}

// ParseServerConfig parses server configuration
func ParseServerConfig(configFile string) (ServerConfiguration, error) {
	var config ServerConfiguration

	path, err := os.Getwd()
	if err != nil {
		log.Println("unable to get current directory", err)
		path = "."
	}
	config.StaticDir = fmt.Sprintf("%s/static", path)
	config.Templates = fmt.Sprintf("%s/static/tmpl", path)

	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Println("Unable to read", err)
		return config, err
	}
	err = json.Unmarshal(data, &config)
	if err != nil {
		log.Println("Unable to parse", err)
		return config, err
	}
	if config.LimiterPeriod == "" {
		config.LimiterPeriod = "100-S"
	}
	if config.Port == 0 {
		config.Port = 8888
	}
	return config, nil
}

// BasePath provides proper base path for a given api
func BasePath(base, api string) string {
	if base != "" {
		if strings.HasPrefix(api, "/") {
			api = strings.Replace(api, "/", "", 1)
		}
		if strings.HasPrefix(base, "/") {
			return fmt.Sprintf("%s/%s", base, api)
		}
		return fmt.Sprintf("/%s/%s", base, api)
	}
	return api
}

// placeholder function for AuthMiddleware
func authnAuthz(h http.Header) error {
	return nil
}

// placeholder function for ValidateMiddleware
func validator(h http.Header) error {
	return nil
}

// http server implementation
func server(serverConfig ServerConfiguration, handler http.Handler) {

	// define server hand	// dynamic handlers
	if serverConfig.CSRFKey != "" {
		CSRF := csrf.Protect(
			[]byte(serverConfig.CSRFKey),
			csrf.RequestHeader("Authenticity-Token"),
			csrf.FieldName("authenticity_token"),
			csrf.Secure(serverConfig.Production),
			csrf.ErrorHandler(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					log.Printf("### CSRF error handler: %+v\n", r)
					w.WriteHeader(http.StatusForbidden)
				},
			)),
		)

		http.Handle("/", CSRF(handler))
	} else {
		http.Handle("/", handler)
	}

	// define location of Templates
	TmplDir = serverConfig.Templates

	// define our HTTP server
	srv := GetServer(serverConfig)

	// make extra channel for graceful shutdown
	// https://medium.com/honestbee-tw-engineer/gracefully-shutdown-in-go-http-server-5f5e6b83da5a
	httpDone := make(chan os.Signal, 1)
	signal.Notify(httpDone, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		var err error
		if serverConfig.ServerCrt != "" && serverConfig.ServerKey != "" {
			if _, err := os.Stat(serverConfig.ServerCrt); err != nil {
				log.Fatal("Unable to obtain file stat for", serverConfig.ServerCrt, err)
			}
			if _, err := os.Stat(serverConfig.ServerKey); err != nil {
				log.Fatal("Unable to obtain file stat for", serverConfig.ServerKey, err)
			}
			//start HTTPS server
			log.Printf("Starting HTTPs server :%d", serverConfig.Port)
			err = srv.ListenAndServeTLS(serverConfig.ServerCrt, serverConfig.ServerKey)
		} else if serverConfig.LetsEncrypt {
			//start LetsEncrypt HTTPS server
			log.Printf("Starting LetsEncrypt HTTPs server :%d", serverConfig.Port)
			err = srv.ListenAndServeTLS("", "")
		} else {
			// Start server without user certificates
			log.Printf("Starting HTTP server :%d", serverConfig.Port)
			err = srv.ListenAndServe()
		}
		if err != nil {
			log.Printf("Fail to start server %v", err)
		}
	}()

	// properly stop our HTTP and Migration Servers
	<-httpDone
	log.Print("HTTP server stopped")

	// add extra timeout for shutdown service stuff
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		cancel()
	}()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server Shutdown Failed:%+v", err)
	}
	log.Print("HTTP server exited properly")
}

// StartServer starts web server with given http handler
func StartServer(serverConfig ServerConfiguration, handler http.Handler) {
	log.SetFlags(0)
	if serverConfig.Verbose > 0 {
		log.SetFlags(log.Llongfile)
	}
	log.SetOutput(new(LogWriter))
	if serverConfig.LogFile != "" {
		rl, err := rotatelogs.New(serverConfig.LogFile + "-%Y%m%d")
		if err == nil {
			rotlogs := RotateLogWriter{RotateLogs: rl}
			log.SetOutput(rotlogs)
		}
	}

	InitLimiter(serverConfig.LimiterPeriod)
	server(serverConfig, handler)
}

// GetServer returns http.Server object for different configurations
func GetServer(serverConfig ServerConfiguration) *http.Server {
	srvCrt := serverConfig.ServerCrt
	srvKey := serverConfig.ServerKey
	port := serverConfig.Port
	verbose := serverConfig.Verbose
	rootCAs := serverConfig.RootCA
	var srv *http.Server
	if srvCrt != "" && srvKey != "" {
		srv = TlsServer(srvCrt, srvKey, rootCAs, port, verbose)
	} else if serverConfig.LetsEncrypt {
		srv = LetsEncryptServer(serverConfig.DomainNames...)
	} else {
		addr := fmt.Sprintf(":%d", port)
		srv = &http.Server{
			Addr: addr,
		}
	}
	return srv
}

// LetsEncryptServer provides HTTPs server with Let's encrypt for
// given domain names (hosts)
func LetsEncryptServer(hosts ...string) *http.Server {
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(hosts...),
		Cache:      autocert.DirCache("certs"),
	}

	server := &http.Server{
		Addr: ":https",
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
		},
	}
	// start cert Manager goroutine
	go http.ListenAndServe(":http", certManager.HTTPHandler(nil))
	return server
}

// TlsServer returns TLS enabled HTTP server
func TlsServer(serverCrt, serverKey, rootCAs string, port, verbose int) *http.Server {
	var certPool *x509.CertPool
	if rootCAs != "" {
		certPool := x509.NewCertPool()
		files, err := ioutil.ReadDir(rootCAs)
		if err != nil {
			log.Fatal(err)
			log.Fatalf("Unable to list files in '%s', error: %v\n", rootCAs, err)
		}
		for _, finfo := range files {
			fname := fmt.Sprintf("%s/%s", rootCAs, finfo.Name())
			caCert, err := os.ReadFile(filepath.Clean(fname))
			if err != nil {
				if verbose > 1 {
					log.Printf("Unable to read %s\n", fname)
				}
			}
			if ok := certPool.AppendCertsFromPEM(caCert); !ok {
				if verbose > 1 {
					log.Printf("invalid PEM format while importing trust-chain: %q", fname)
				}
			}
		}
	}
	// if we do not require custom verification we'll load server crt/key and present to client
	cert, err := tls.LoadX509KeyPair(serverCrt, serverKey)
	if err != nil {
		log.Fatalf("server loadkeys: %s", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	if certPool != nil {
		tlsConfig.RootCAs = certPool
	}
	addr := fmt.Sprintf(":%d", port)
	server := &http.Server{
		Addr:      addr,
		TLSConfig: tlsConfig,
	}
	return server
}
