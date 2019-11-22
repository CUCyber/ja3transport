package ja3transport

import (
	"io"
	"net/http"
	"net/url"
	"strings"

	tls "github.com/refraction-networking/utls"
)

// JA3Client contains is similar to http.Client
type JA3Client struct {
	*http.Client

	Config  *tls.Config
	Browser Browser
}

// New creates a JA3Client based on a Browser struct
func New(b Browser) (*JA3Client, error) {
	client, err := NewWithString(b.JA3)
	if err != nil {
		return nil, err
	}
	client.Browser = b
	return client, nil
}

// NewWithString creates a JA3 client with the specified JA3 string
func NewWithString(ja3 string) (*JA3Client, error) {
	tr, err := NewTransport(ja3)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Transport: tr}

	return &JA3Client{
		client,
		&tls.Config{},
		Browser{JA3: ja3},
	}, nil
}

// Do sends an HTTP request and returns an HTTP response, following policy
// (such as redirects, cookies, auth) as configured on the client.
func (c *JA3Client) Do(req *http.Request) (*http.Response, error) {
	if _, ok := req.Header["User-Agent"]; !ok && c.Browser.UserAgent != "" {
		req.Header.Set("User-Agent", c.Browser.UserAgent)
	}

	return c.Client.Do(req)
}

// Get issues a GET to the specified URL.
func (c *JA3Client) Get(targetURL string) (*http.Response, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Post issues a POST to the specified URL.
func (c *JA3Client) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}

// Head issues a HEAD to the specified URL.
func (c *JA3Client) Head(url string) (resp *http.Response, err error) {
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// PostForm issues a POST to the specified URL,
// with data's keys and values URL-encoded as the request body.
func (c *JA3Client) PostForm(url string, data url.Values) (resp *http.Response, err error) {
	return c.Post(url, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
}
