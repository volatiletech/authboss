package hconsentor

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"
)

type flow string

const (
	login             flow = "login"
	consent           flow = "consent"
	logout            flow = "logout"
	PathGetLogin           = "/oauth2/auth/requests/login"
	PathAcceptLogin        = "/oauth2/auth/requests/login/accept"
	PathRejectLogin        = "/oauth2/auth/requests/login/reject"
	PathGetConsent         = "/oauth2/auth/requests/consent"
	PathAcceptConsent      = "/oauth2/auth/requests/consent/accept"
	PathRejectConsent      = "/oauth2/auth/requests/consent/reject"
	PathGetLogout          = "/oauth2/auth/requests/logout"
	PathAcceptLogout       = "/oauth2/auth/requests/logout/accept"
	PathRejectLogout       = "/oauth2/auth/requests/logout/reject"
)

func NewClient(hydraURL string, timeout time.Duration) *Client {
	baseURL, err := url.Parse(hydraURL)
	if err != nil {
		panic(err)
	}

	client := &http.Client{
		Timeout: timeout,
	}
	out := Client{
		baseURL: baseURL,
		client:  client,
	}
	return &out
}

type Client struct {
	baseURL *url.URL
	client  *http.Client
}

func (c *Client) GetLogin(challenge string) (LoginRequest, error) {
	var res LoginRequest
	url := c.makeURL(PathGetLogin, login, challenge)
	err := c.getJSON(url, &res)
	return res, err
}

func (c *Client) AcceptLogin(challenge string, body map[string]interface{}) (RequestHandlerResponse, error) {
	var res RequestHandlerResponse
	url := c.makeURL(PathAcceptLogin, login, challenge)
	err := c.putJSON(url, body, &res)
	return res, err
}

func (c *Client) RejectLogin(challenge string, body map[string]interface{}) (RequestHandlerResponse, error) {
	var res RequestHandlerResponse
	url := c.makeURL(PathRejectLogin, login, challenge)
	err := c.putJSON(url, body, &res)

	return res, err
}

func (c *Client) GetConsent(challenge string) (ConsentRequest, error) {
	var res ConsentRequest
	url := c.makeURL(PathGetConsent, consent, challenge)
	err := c.getJSON(url, &res)

	return res, err
}

func (c *Client) AcceptConsent(challenge string, body map[string]interface{}) (RequestHandlerResponse, error) {
	var res RequestHandlerResponse
	url := c.makeURL(PathAcceptConsent, consent, challenge)
	err := c.putJSON(url, body, &res)

	return res, err
}

func (c *Client) RejectConsent(challenge string, body map[string]interface{}) (RequestHandlerResponse, error) {
	var res RequestHandlerResponse
	url := c.makeURL(PathRejectConsent, consent, challenge)
	err := c.putJSON(url, body, &res)

	return res, err
}

func (c *Client) GetLogout(challenge string) (LogoutRequest, error) {
	var res LogoutRequest
	url := c.makeURL(PathGetLogout, logout, challenge)
	err := c.getJSON(url, &res)

	return res, err
}

func (c *Client) AcceptLogout(challenge string) (RequestHandlerResponse, error) {
	var res RequestHandlerResponse
	url := c.makeURL(PathAcceptLogout, logout, challenge)
	err := c.putJSON(url, nil, &res)

	return res, err
}

func (c *Client) RejectLogout(challenge string) (RequestHandlerResponse, error) {
	var res RequestHandlerResponse
	url := c.makeURL(PathRejectLogout, logout, challenge)
	err := c.putJSON(url, nil, &res)

	return res, err
}

func (c *Client) getJSON(url string, target interface{}) error {
	res, err := c.client.Get(url)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(target)
}

func (c *Client) putJSON(url string, body interface{}, target interface{}) error {
	var b io.Reader
	if body != nil {
		jsonBody, _ := json.Marshal(body)
		b = bytes.NewBuffer(jsonBody)
	}
	req, _ := http.NewRequest(http.MethodPut, url, b)

	res, err := c.client.Do(req)
	if err != nil {
		panic(err)
	}

	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(target)
}

func (c *Client) makeURL(path string, f flow, challenge string) string {
	p, err := url.Parse(path)
	if err != nil {
		panic(err)
	}

	u := c.baseURL.ResolveReference(p)

	q := u.Query()
	q.Set(string(f)+"_challenge", challenge)
	u.RawQuery = q.Encode()

	return u.String()
}
