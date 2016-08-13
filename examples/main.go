package main

import (
	"html/template"
	"net/http"

	clef "github.com/dutchcoders/goclef"
)

const (
	CLEF_APP_ID     = "4f318ac177a9391c2e0d221203725ffd"
	CLEF_APP_SECRET = "2125d80f4583c52c46f8084bcc030c9b"
)

func init() {
	clef.MustInitialize(CLEF_APP_ID, CLEF_APP_SECRET)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "access_token", Value: ""})

	logoutToken := r.FormValue("logout_token")
	clef.Logout(logoutToken)

	http.Redirect(w, r, "/", http.StatusFound)
}

func oauthCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")

	if ar, err := clef.Authorize(code); err != nil {
		panic(err)
	} else {
		http.SetCookie(w, &http.Cookie{Name: "access_token", Value: ar.AccessToken})
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	bag := struct {
		Info     *clef.InfoStruct
		Error    string
		LoggedIn bool
	}{
		LoggedIn: false,
	}

	if cookie, err := r.Cookie("access_token"); err != nil {
	} else if ir, err := clef.Info(cookie.Value); err != nil {
		if clef.IsInvalidTokenError(err) {
		} else {
			bag.Error = err.Error()
		}
	} else {
		bag.Info = ir.Info
	}

	if t, err := template.ParseFiles("templates/index.html"); err != nil {
		panic(err)
	} else {
		t.Execute(w, bag)
	}
}

func main() {
	fs := http.FileServer(http.Dir("/Users/remco/Projects/goclef/gopath/src/github.com/dutchcoders/goclef/examples/static"))

	http.Handle("/static/", http.StripPrefix("/static/", fs))
	http.HandleFunc("/oauth_callback", oauthCallbackHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/", handler)
	http.ListenAndServe(":5000", nil)
}
