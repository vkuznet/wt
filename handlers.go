package wt

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dchest/captcha"
)

// TopHTML represents top html content
var TopHTML string

// BottomHTML represents bottom html content
var BottomHTML string

// HTTPRecord represents HTTP response record
type HTTPRecord map[string]string

// ResponseMsg helper function to provide response to end-user
// ResponseMsg(w, r, fmt.Sprintf("%v", err), "VaultDeleteHandler", http.StatusBadRequest)
func ResponseMsg(w http.ResponseWriter, r *http.Request, msg, api string, code int) {
	rec := make(HTTPRecord)
	rec["error"] = msg
	rec["api"] = api
	rec["method"] = r.Method
	rec["exception"] = fmt.Sprintf("%d", code)
	rec["type"] = "HTTPError"
	data, _ := json.Marshal(rec)
	w.WriteHeader(code)
	w.Write(data)
}

// FaviconHandler provides favicon icon file
func FaviconHandler(w http.ResponseWriter, r *http.Request) {
	//     http.ServeFile(w, r, "relative/path/to/favicon.ico")
	w.WriteHeader(http.StatusOK)
}

// helper function to parse given template and return HTML page
func tmplPage(tmpl string, tmplData TmplRecord) string {
	if tmplData == nil {
		tmplData = make(TmplRecord)
	}
	var templates Templates
	page := templates.Tmpl(TmplDir, tmpl, tmplData)
	return TopHTML + page + BottomHTML
}

// HomeHandler handles home page requests
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	tmplData := make(TmplRecord)
	captchaStr := captcha.New()
	tmplData["CaptchaId"] = captchaStr
	page := tmplPage("index.tmpl", tmplData)
	w.Write([]byte(page))
}

// SignUpHandler handles sign-up page requests
func SignUpHandler(w http.ResponseWriter, r *http.Request) {
	tmplData := make(TmplRecord)
	captchaStr := captcha.New()
	tmplData["CaptchaId"] = captchaStr
	page := tmplPage("signup.tmpl", tmplData)
	w.Write([]byte(page))
}
