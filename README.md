### WebTools (wt)
Collection of useful set of WebTools (wt) for building Go HTTP server
applications. For example:

```
package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	wt "github.com/vkuznet/wt"
)

func main() {
	var verbose int
	flag.IntVar(&verbose, "verbose", 0, "verbosity level")
	flag.Parse()
    // create new server configuration
	config := wt.NewServerConfig()
    // set appropriate flags, see more in wt.ServerConfiguration
	config.Templates = "static/tmpl" // location of static template area
    config.Base = "/"                // our server base path
	config.Verbose = 1               // verbosity level

    // start the server
	wt.StartServer(config, srvRouter(config))
}

// AuthFunc provides authentication for incoming HTTP request
func AuthFunc(h http.Header) error {
	log.Println("authFunc")
	return nil
}

// AuthFunc provides validation for incoming HTTP request
func ValidateFunc(h http.Header) error {
	log.Println("validateFunc")
	return nil
}

// create our HTTP router
func srvRouter(serverConfig wt.ServerConfiguration) *mux.Router {
	base := serverConfig.Base
	router := mux.NewRouter()
	router.StrictSlash(true) // to allow /route and /route/ end-points
	router.HandleFunc(wt.BasePath(base, "/"), wt.HomeHandler).Methods("GET")

	// this is for displaying the QR code on /qr end point
	// and static area which holds user's images
	log.Println("server static area", serverConfig.StaticDir)
	fileServer := http.StripPrefix("/static/", http.FileServer(http.Dir(serverConfig.StaticDir)))
	router.PathPrefix(wt.BasePath(base, "/css/{file:[0-9a-zA-Z-\\.]+}")).Handler(fileServer)

    // define different middleware layers
	router.Use(wt.LoggingMiddleware)
	router.Use(wt.AuthMiddleware(AuthFunc))
	router.Use(wt.ValidateMiddleware(ValidateFunc))
	router.Use(wt.LimitMiddleware)
	router.Use(wt.CorsMiddleware)

	return router
}
```

The wt provides different middleware layers, and flexible configuration
to setup different servers, HTTP, HTTPs, HTTPs with let's encrypt, etc.
