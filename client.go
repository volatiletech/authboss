package hconsentor

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	BASEPATH = "/oauth2/auth/requests/"
	ACCEPT   = "/accept"
	REJECT   = "/reject"
	LOGIN    = "login"
	CONSENT  = "consent"
	LOGOUT   = "logout"
)

func NewClient(hydraURL string, timeout time.Duration) *HClient {
	baseURL, err := url.Parse(hydraURL)
	if err != nil {
		panic(err)
	}

	client := &http.Client{
		Timeout: timeout,
	}
	out := HClient{
		baseURL: baseURL,
		client:  client,
	}
	return &out
}

type HClient struct {
	baseURL *url.URL
	client  *http.Client
}

func (c *HClient) GetLogin(challenge string) (LoginRequest, error) {
	var res LoginRequest
	url := c.makeURL(BASEPATH+LOGIN, LOGIN, challenge)
	err := c.getJSON(url, &res)
	return res, err
}

func (c *HClient) AcceptLogin(challenge string, body map[string]interface{}) (RequestHandlerResponse, error) {
	var res RequestHandlerResponse
	url := c.makeURL(BASEPATH+LOGIN+ACCEPT, LOGIN, challenge)
	err := c.putJSON(url, body, &res)
	return res, err
}

func (c *HClient) RejectLogin(challenge string, body map[string]interface{}) (RequestHandlerResponse, error) {
	var res RequestHandlerResponse
	url := c.makeURL(BASEPATH+LOGIN+REJECT, LOGIN, challenge)
	err := c.putJSON(url, body, &res)

	return res, err
}

func (c *HClient) GetConsent(challenge string) (ConsentRequest, error) {
	var res ConsentRequest
	url := c.makeURL(BASEPATH+CONSENT, CONSENT, challenge)
	err := c.getJSON(url, &res)

	return res, err
}

func (c *HClient) AcceptConsent(challenge string, body map[string]interface{}) (RequestHandlerResponse, error) {
	var res RequestHandlerResponse
	url := c.makeURL(BASEPATH+CONSENT+ACCEPT, CONSENT, challenge)
	err := c.putJSON(url, body, &res)

	return res, err
}

func (c *HClient) RejectConsent(challenge string, body map[string]interface{}) (RequestHandlerResponse, error) {
	var res RequestHandlerResponse
	url := c.makeURL(BASEPATH+CONSENT+REJECT, CONSENT, challenge)
	err := c.putJSON(url, body, &res)

	return res, err
}

func (c *HClient) GetLogout(challenge string) (LogoutRequest, error) {
	var res LogoutRequest
	url := c.makeURL(BASEPATH+LOGOUT, LOGOUT, challenge)
	err := c.getJSON(url, &res)

	return res, err
}

func (c *HClient) AcceptLogout(challenge string) (RequestHandlerResponse, error) {
	var res RequestHandlerResponse
	url := c.makeURL(BASEPATH+LOGOUT+ACCEPT, LOGOUT, challenge)
	err := c.putJSON(url, nil, &res)

	return res, err
}

func (c *HClient) RejectLogout(challenge string) (RequestHandlerResponse, error) {
	var res RequestHandlerResponse
	url := c.makeURL(BASEPATH+LOGOUT+REJECT, LOGOUT, challenge)
	err := c.putJSON(url, nil, &res)

	return res, err
}

func (c *HClient) getJSON(url string, target interface{}) error {
	res, err := c.client.Get(url)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return json.NewDecoder(res.Body).Decode(target)
}

func (c *HClient) putJSON(url string, body interface{}, target interface{}) error {
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

func (c *HClient) makeURL(path, flow, challenge string) string {
	p, err := url.Parse(path)
	if err != nil {
		panic(err)
	}

	u := c.baseURL.ResolveReference(p)

	q := u.Query()
	q.Set(flow+"_challenge", challenge)
	u.RawQuery = q.Encode()

	return u.String()
}
