package clef

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	logging "github.com/op/go-logging"
)

const (
	// Version is the implemented clef interface version
	Version = "v1"
)

var log = logging.MustGetLogger("clef")

// internal API, used for direct clef.{Authorize,Info,Logout} calls
var api *API

// API contains the ClefAPI object
type API struct {
	*http.Client

	baseURL *url.URL
	id      string
	secret  string
}

// Error contains Clef Error messages
type Error struct {
	Message       string `json:"message"`
	Context       string `json:"context"`
	InternalError string `json:"error"`
}

// Error implements error interface
func (e Error) Error() string {
	return e.InternalError
}

// IsInvalidTokenError returns true if err is a invalid token error.
func IsInvalidTokenError(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.Message == "Invalid token."
	}

	return false
}

// ErrNotInitialized will be returned when the Clef API has not been
// initialized yet.
var ErrNotInitialized = errors.New("Clef API not initialized yet.")

// MustInitialize initializes the Clef API and panic if error occurs
func MustInitialize(appID, appSecret string) error {
	if err := Initialize(appID, appSecret); err != nil {
		panic(err)
	}

	return nil
}

// Initialize Clef API with application id and application secret
func Initialize(appID, appSecret string) error {
	if c, err := newAPI(appID, appSecret); err != nil {
		return err
	} else {
		api = c
		return nil
	}
}

// Authorize exchanges an OAuth code for an OAuth token
func Authorize(code string) (*AuthorizeResponse, error) {
	if api == nil {
		return nil, ErrNotInitialized
	}

	return api.Authorize(code)
}

// Logout will call Logout with the Clef API and return a LogoutResponse
func Logout(logoutToken string) (*LogoutResponse, error) {
	if api == nil {
		return nil, ErrNotInitialized
	}

	return api.Logout(logoutToken)
}

// Info will return the info about the logged in Clef user
func Info(accessToken string) (*InfoResponse, error) {
	if api == nil {
		return nil, ErrNotInitialized
	}

	return api.Info(accessToken)
}

func newAPI(id, secret string) (*API, error) {
	if baseURL, err := url.Parse("https://clef.io/api/"); err != nil {
		return nil, err
	} else {
		return &API{
			id:      id,
			secret:  secret,
			baseURL: baseURL,
			Client:  http.DefaultClient,
		}, nil
	}
}

// AuthorizeResponse contains the response of the Authorize call
type AuthorizeResponse struct {
	AccessToken string `json:"access_token"`
	Success     bool   `json:"success"`
}

// Authorize exchanges an OAuth code for an OAuth token
func (api *API) Authorize(code string) (*AuthorizeResponse, error) {
	form := url.Values{}
	form.Add("code", code)
	form.Add("app_id", api.id)
	form.Add("app_secret", api.secret)

	ar := AuthorizeResponse{}
	if request, err := api.NewRequest("POST", "authorize", form); err != nil {
		return nil, err
	} else if err := api.Do(request, &ar); err != nil {
		return nil, err
	} else {
		return &ar, nil
	}
}

// LogoutResponse contains the response of the Logout call
type LogoutResponse struct {
	ID      int  `json:"clef_id"`
	Success bool `json:"success"`
}

// Logout exchanges a logout token for a Clef ID
func (api *API) Logout(logoutToken string) (*LogoutResponse, error) {
	form := url.Values{}
	form.Add("logout_token", logoutToken)
	form.Add("app_id", api.id)
	form.Add("app_secret", api.secret)

	lr := LogoutResponse{}
	if request, err := api.NewRequest("POST", "logout", form); err != nil {
		return nil, err
	} else if err := api.Do(request, &lr); err != nil {
		return nil, err
	} else {
		return &lr, nil
	}
}

// InfoStruct contains the info about the logged in user
type InfoStruct struct {
	ID          int    `json:"id"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	PhoneNumber string `json:"phone_number"`
	Email       string `json:"email"`
}

// InfoResponse contains the response of the Info call
type InfoResponse struct {
	Info    *InfoStruct `json:"info"`
	Success bool        `json:"success"`
}

// Info will return the info about the logged in Clef user
func (api *API) Info(accessToken string) (*InfoResponse, error) {
	io := InfoResponse{}
	if request, err := api.NewRequest("GET", "info?access_token="+accessToken, nil); err != nil {
		return nil, err
	} else if err := api.Do(request, &io); err != nil {
		return nil, err
	} else {
		return &io, nil
	}
}

// SwagRequest contains the request for the Swag API call
type SwagRequest struct {
	AppID        string `json:"app_id"`
	AppSecret    string `json:"app_secret"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	AddressLine1 string `json:"address_line_1"`
	AddressLine2 string `json:"address_line_2"`
	City         string `json:"city"`
	ZipCode      string `json:"zip_code"`
	State        string `json:"state"`
	Country      string `json:"country"`
}

// SwagResponse contains the response for the Swag API call
type SwagResponse struct {
	Message bool `json:"message"`
	Success bool `json:"success"`
}

// Swag can be call to order swag items
func (api *API) Swag(req *SwagRequest) (*SwagResponse, error) {
	form := url.Values{}
	form.Add("app_id", req.AppID)
	form.Add("app_secret", req.AppSecret)
	form.Add("name", req.Name)
	form.Add("email", req.Email)
	form.Add("address_line_1", req.AddressLine1)
	form.Add("address_line_2", req.AddressLine2)
	form.Add("city", req.City)
	form.Add("zip_code", req.ZipCode)
	form.Add("state", req.State)
	form.Add("country", req.Country)

	sr := SwagResponse{}
	if request, err := api.NewRequest("POST", "swag", form); err != nil {
		return nil, err
	} else if err := api.Do(request, &sr); err != nil {
		return nil, err
	} else {
		return &sr, nil
	}
}

// NewRequest returns a raw Clef API request
func (api *API) NewRequest(method, urlStr string, form url.Values) (*http.Request, error) {
	rel, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	u := api.baseURL.ResolveReference(rel)

	req, err := http.NewRequest(method, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// Do executes a raw Clef API request
func (api *API) Do(req *http.Request, v interface{}) error {
	if dump, err := httputil.DumpRequestOut(req, true); err == nil {
		log.Debugf("Request:\n\n%s\n", string(dump))
	}

	if resp, err := api.Client.Do(req); err != nil {
		return err
	} else {
		if dump, err := httputil.DumpResponse(resp, true); err == nil {
			log.Debugf("Response:\n\n%s\n", string(dump))
		}

		defer resp.Body.Close()

		var r io.Reader = resp.Body

		if resp.StatusCode != http.StatusOK {
			err := Error{}
			json.NewDecoder(r).Decode(&err)
			return &err
		}

		if err := json.NewDecoder(r).Decode(&v); err != nil {
			return err
		}

		return nil
	}
}
