package wt

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/gorilla/mux"
	limiter "github.com/ulule/limiter/v3"
	stdlib "github.com/ulule/limiter/v3/drivers/middleware/stdlib"
	memory "github.com/ulule/limiter/v3/drivers/store/memory"
)

// limiter middleware pointer
var limiterMiddleware *stdlib.Middleware

// InitLimiter initializes Limiter middleware pointer
func InitLimiter(period string) {
	log.Printf("limiter rate='%s'", period)
	// create rate limiter with 5 req/second
	rate, err := limiter.NewRateFromFormatted(period)
	if err != nil {
		panic(err)
	}
	store := memory.NewStore()
	instance := limiter.New(store, rate)
	limiterMiddleware = stdlib.NewMiddleware(instance)
}

// MiddlewareFunction defines common function to be used by mux middleware
// For examaple, we can provide Authentication or Validator functions
// to corresponding middleware
type MiddlewareFunction func(h http.Header) error

// AuthMiddleware provide auth/authz action for incoming HTTP requests.
// User should initialize it with MiddlewareFunction which accepts
// http Header and return the error
func AuthMiddleware(authFunc MiddlewareFunction) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			err := authFunc(r.Header)
			if err != nil {
				log.Printf("ERROR: fail to authenticate, HTTP headers %+v, error %v\n", r.Header, err)
				w.WriteHeader(http.StatusForbidden)
				return
			}
			// Call the next handler
			next.ServeHTTP(w, r)
		})
	}
}

// ValidateMiddleware provides validation action for incoming HTTP requests.
// User should initialize it with MiddlewareFunction which accepts
// http Header and return the error
func ValidateMiddleware(validateFunc MiddlewareFunction) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// perform validation of input parameters
			err := validateFunc(r.Header)
			if err != nil {
				uri, e := url.QueryUnescape(r.RequestURI)
				if e == nil {
					log.Printf("HTTP %s %s validation error %v\n", r.Method, uri, err)
				} else {
					log.Printf("HTTP %s %v validation error %v\n", r.Method, r.RequestURI, err)
				}
				w.WriteHeader(http.StatusBadRequest)
				if r.Header.Get("Accept") == "application/json" {
					rec := make(HTTPRecord)
					rec["error"] = fmt.Sprintf("Validation error %v", err)
					if r, e := json.Marshal(rec); e == nil {
						w.Write(r)
					}
					return
				}
			}
			// Call the next handler
			next.ServeHTTP(w, r)
		})
	}
}

// LimitMiddleware limits incoming requests
func LimitMiddleware(next http.Handler) http.Handler {
	return limiterMiddleware.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	}))
}

// Corsmiddleware provides CORS
func CorsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers:", "Origin, Content-Type, X-Auth-Token, Authorization")
			//             w.Header().Set("Content-Type", "application/json")
		}
		log.Println("call next ServeHTTP")
		next.ServeHTTP(w, r)
	})
}
