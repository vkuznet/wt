package wt

// logging module provides various logging methods
//
// Copyright (c) 2020 - Valentin Kuznetsov <vkuznet@gmail.com>
//

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
)

// PrintLogRecord controls if we'll print to stdout log record in JSON data
// format. This is useful in k8s setup when we can redirect logs to dedidcated
// file and at the same time print log record to stdout for scraping by
// monitoring/k8s systems
var PrintLogRecord bool

// RotateLogWriter represents rorate log writer
type RotateLogWriter struct {
	RotateLogs *rotatelogs.RotateLogs
}

// Write method of our rotate log writer
func (w RotateLogWriter) Write(data []byte) (int, error) {
	return w.RotateLogs.Write([]byte(data))
}

// LogWriter represents our logger
type LogWriter struct {
}

// Write method of our log writer
func (writer LogWriter) Write(data []byte) (int, error) {
	return fmt.Print(data)
}

// LogRecord represents HTTP log record
type LogRecord struct {
	Method         string  `json:"method"`           // http.Request HTTP method
	Host           string  `json:"hostname"`         // hostname of the server
	URI            string  `json:"uri"`              // http.RequestURI
	API            string  `json:"api"`              // http service API being used
	System         string  `json:"system"`           // cmsweb service name
	ClientIP       string  `json:"clientip"`         // client IP address
	BytesSend      int64   `json:"bytes_send"`       // number of bytes send with HTTP request
	BytesReceived  int64   `json:"bytes_received"`   // number of bytes received with HTTP request
	Proto          string  `json:"proto"`            // http.Request protocol
	Status         int64   `json:"status"`           // http.Request status code
	ContentLength  int64   `json:"content_length"`   // http.Request content-length
	AuthProto      string  `json:"auth_proto"`       // authentication protocol
	AuthCert       string  `json:"auth_cert"`        // auth certificate, user DN
	LoginName      string  `json:"login_name"`       // login name, user DN
	Auth           string  `json:"auth"`             // auth method
	Cipher         string  `json:"cipher"`           // TLS cipher name
	Referer        string  `json:"referer"`          // http referer
	UserAgent      string  `json:"user_agent"`       // http user-agent field
	XForwardedHost string  `json:"x_forwarded_host"` // http.Request X-Forwarded-Host
	XForwardedFor  string  `json:"x_forwarded_for"`  // http.Request X-Forwarded-For
	RemoteAddr     string  `json:"remote_addr"`      // http.Request remote address
	ResponseStatus string  `json:"response_status"`  // http.Response status
	ResponseTime   float64 `json:"response_time"`    // http response time
	RequestTime    float64 `json:"request_time"`     // http request time
	Timestamp      int64   `json:"timestamp"`        // record timestamp
	RecTimestamp   int64   `json:"rec_timestamp"`    // timestamp for backward compatibility with apache
	RecDate        string  `json:"rec_date"`         // timestamp for backward compatibility with apache
}

// UTC flag represents UTC time zone for log messages
var UTC bool

// helper function to produce UTC time prefixed output
func utcMsg(data []byte) string {
	var msg string
	if UTC {
		msg = fmt.Sprintf("[" + time.Now().UTC().String() + "] " + string(data))
	} else {
		msg = fmt.Sprintf("[" + time.Now().String() + "] " + string(data))
		//     msg = fmt.Sprintf("[" + time.Now().UTC().Format("2006-01-02T15:04:05.999Z") + " UTC] " + string(data))
	}
	return msg
}

// HTTP response data and logging response writer
type (
	// struct for holding response details
	responseData struct {
		status int   // represent status of HTTP response code
		size   int64 // represent size of HTTP response
	}

	// our http.ResponseWriter implementation
	loggingResponseWriter struct {
		http.ResponseWriter // compose original http.ResponseWriter
		responseData        *responseData
	}
)

// Write implements Write API for logging response writer
func (r *loggingResponseWriter) Write(b []byte) (int, error) {
	size, err := r.ResponseWriter.Write(b) // write response using original http.ResponseWriter
	r.responseData.size += int64(size)     // capture size
	return size, err
}

// Write implements WriteHeader API for logging response writer
func (r *loggingResponseWriter) WriteHeader(statusCode int) {
	r.ResponseWriter.WriteHeader(statusCode) // write status code using original http.ResponseWriter
	r.responseData.status = statusCode       // capture status code
}

// LoggingMiddleware provides logging middleware for HTTP requests
// https://arunvelsriram.dev/simple-golang-http-logging-middleware
func LoggingMiddleware(h http.Handler) http.Handler {
	loggingFn := func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		tstamp := int64(start.UnixNano() / 1000000) // use milliseconds for MONIT

		// initialize response data struct
		responseData := &responseData{
			status: http.StatusOK, // by default we should return http status OK
			size:   0,
		}
		lrw := loggingResponseWriter{
			ResponseWriter: w, // compose original http.ResponseWriter
			responseData:   responseData,
		}
		h.ServeHTTP(&lrw, r) // inject our implementation of http.ResponseWriter
		cauth := r.Header.Get("Cms-Authn-Method")
		if cauth == "" {
			cauth = "no-auth-method"
		}
		LogRequest(w, r, start, cauth, &responseData.status, tstamp, responseData.size)

	}
	return http.HandlerFunc(loggingFn)
}

// helper function to log every single user request, here we pass pointer to status code
// as it may change through the handler while we use defer logRequest
func LogRequest(w http.ResponseWriter, r *http.Request, start time.Time, cauth string, status *int, tstamp int64, bytesOut int64) {
	// our apache configuration
	// CustomLog "||@APACHE2_ROOT@/bin/rotatelogs -f @LOGDIR@/access_log_%Y%m%d.txt 86400" \
	//   "%t %v [client: %a] [backend: %h] \"%r\" %>s [data: %I in %O out %b body %D us ] [auth: %{SSL_PROTOCOL}x %{SSL_CIPHER}x \"%{SSL_CLIENT_S_DN}x\" \"%{cms-auth}C\" ] [ref: \"%{Referer}i\" \"%{User-Agent}i\" ]"
	//     status := http.StatusOK
	var aproto, cipher string
	var err error
	if r != nil && r.TLS != nil {
		if r.TLS.Version == tls.VersionTLS10 {
			aproto = "TLS10"
		} else if r.TLS.Version == tls.VersionTLS11 {
			aproto = "TLS11"
		} else if r.TLS.Version == tls.VersionTLS12 {
			aproto = "TLS12"
		} else if r.TLS.Version == tls.VersionTLS13 {
			aproto = "TLS13"
		} else if r.TLS.Version == tls.VersionSSL30 {
			aproto = "SSL30"
		} else {
			aproto = fmt.Sprintf("TLS-%+v", r.TLS.Version)
		}
		cipher = tls.CipherSuiteName(r.TLS.CipherSuite)
	} else {
		aproto = fmt.Sprintf("no-TLS")
		cipher = "cipher-none"
	}
	if cauth == "" {
		cauth = fmt.Sprintf("%v", r.Header.Get("Cms-Authn-Method"))
	}
	if cauth == "" {
		cauth = "no-auth-method"
	}
	authCert := r.Header.Get("Cms-Auth-Cert")
	if authCert == "" {
		authCert = "no-auth-cert"
	}
	loginName := r.Header.Get("Cms-Authn-Login")
	if loginName == "" {
		loginName = "no-auth-login"
	}
	authMsg := fmt.Sprintf("[auth: %v %v \"%v\" %v %v]", aproto, cipher, authCert, loginName, cauth)
	respHeader := w.Header()
	//     dataMsg := fmt.Sprintf("[data: %v in %v out]", r.ContentLength, respHeader.Get("Content-Length"))
	dataMsg := fmt.Sprintf("[data: %v in %v out]", r.ContentLength, bytesOut)
	referer := r.Referer()
	if referer == "" {
		referer = "-"
	}
	xff := r.Header.Get("X-Forwarded-For")
	var clientip string
	if xff != "" {
		clientip = strings.Split(xff, ":")[0]
	} else if r.RemoteAddr != "" {
		clientip = strings.Split(r.RemoteAddr, ":")[0]
	}
	addr := fmt.Sprintf("[remoteAddr: %v] [X-Forwarded-For: %v] [X-Forwarded-Host: %v]", r.RemoteAddr, xff, r.Header.Get("X-Forwarded-Host"))
	//     addr := fmt.Sprintf("[X-Forwarded-For: %v] [X-Forwarded-Host: %v] [remoteAddr: %v]", xff, r.Header.Get("X-Forwarded-Host"), r.RemoteAddr)
	ref, err := url.QueryUnescape(referer)
	if err != nil {
		ref = referer
	}
	refMsg := fmt.Sprintf("[ref: \"%v\" \"%v\"]", ref, r.Header.Get("User-Agent"))
	respTime := "0"
	if respHeader.Get("Response-Time") != "" {
		respTime = fmt.Sprintf("%sv", respHeader.Get("Response-Time"))
	}
	respMsg := fmt.Sprintf("[req: %v proxy-resp: %v]", time.Since(start), respTime)
	uri, err := url.QueryUnescape(r.URL.RequestURI())
	if err != nil {
		uri = r.RequestURI
	}
	log.Printf("%s %d %s %s %s %s %s %s %s\n", r.Proto, *status, r.Method, uri, dataMsg, addr, authMsg, refMsg, respMsg)
	//     log.Printf("%s %s %s %s %d %s %s %s %s\n", addr, r.Method, uri, r.Proto, *status, dataMsg, authMsg, refMsg, respMsg)
	rTime, _ := strconv.ParseFloat(respHeader.Get("Response-Time-Seconds"), 10)
	var bytesSend, bytesRecv int64
	bytesSend = r.ContentLength
	bytesRecv, _ = strconv.ParseInt(respHeader.Get("Content-Length"), 10, 64)
	hostname, err := os.Hostname()
	if err != nil {
		log.Println("Unable to get hostname", err)
	}
	rec := LogRecord{
		Method:         r.Method,
		URI:            uri,
		API:            getAPI(r.RequestURI),
		System:         getSystem(r.RequestURI),
		BytesSend:      bytesSend,
		BytesReceived:  bytesRecv,
		Proto:          r.Proto,
		Status:         int64(*status),
		ContentLength:  r.ContentLength,
		AuthCert:       authCert,
		LoginName:      loginName,
		Auth:           cauth,
		AuthProto:      aproto,
		Cipher:         cipher,
		Referer:        referer,
		UserAgent:      r.Header.Get("User-Agent"),
		XForwardedHost: r.Header.Get("X-Forwarded-Host"),
		XForwardedFor:  xff,
		ClientIP:       clientip,
		RemoteAddr:     r.RemoteAddr,
		ResponseStatus: respHeader.Get("Response-Status"),
		ResponseTime:   rTime,
		RequestTime:    time.Since(start).Seconds(),
		Timestamp:      tstamp,
		RecTimestamp:   int64(time.Now().Unix()),
		RecDate:        time.Now().Format(time.RFC3339),
		Host:           hostname,
	}

	// print logging record
	data, err := json.Marshal(rec)
	if err == nil {
		if PrintLogRecord {
			fmt.Println(string(data))
		}
	} else {
		log.Println("unable to produce record for MONIT, error", err)
	}
}

// helper function to extract service API from the record URI
func getAPI(uri string) string {
	// /httpgo?test=bla
	arr := strings.Split(uri, "/")
	last := arr[len(arr)-1]
	arr = strings.Split(last, "?")
	return arr[0]
}

// helper function to extract service system from the record URI
func getSystem(uri string) string {
	// /httpgo?test=bla
	arr := strings.Split(uri, "/")
	system := "base"
	if len(arr) > 0 {
		if len(arr) > 1 {
			arr = strings.Split(arr[1], "?")
		}
		system = arr[0]
	}
	if system == "" {
		system = "base"
	}
	return system
}
