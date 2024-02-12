package ja3transport_test

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"

	tls "github.com/refraction-networking/utls"
	. "github.com/reneManqueros/ja3transport"
)

const DefaultJA3Sig string = "771,4865-4866-4867-49196-49195-49188-49187-49162-49161-52393-49200-49199-49192-49191-49172-49171-52392-157-156-61-60-53-47-49160-49170-10,65281-0-23-13-5-18-16-11-51-45-43-10-21,29-23-24-25,0"
const JA3erURL = "https://ja3er.com/json"

func ExampleNew() {
	client, _ := New(SafariAuto)
	client.Get("https://ja3er.com/json")
}

func ExampleNewWithString() {
	client, _ := NewWithString("771,4865-4866-4867-49196-49195-49188-49187-49162-49161-52393-49200-49199-49192-49191-49172-49171-52392-157-156-61-60-53-47-49160-49170-10,65281-0-23-13-5-18-16-11-51-45-43-10-21,29-23-24-25,0")
	client.Get("https://ja3er.com/json")
}

func ExampleNewTransport() {
	tr, _ := NewTransport("771-61-60-53,0-23-15,29,23,24,0")
	client := &http.Client{Transport: tr}
	client.Get("https://ja3er.com/json")
}

func ExampleNewTransportWithConfig() {
	// Must import the `github.com/refraction-networking/utls` package to create the Config object.
	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	// Pass the config object to NewTransportWithConfig
	tr, _ := NewTransportWithConfig("771-61-60-53,0-23-15,29,23,24,0", config)
	client := &http.Client{Transport: tr}
	client.Get("https://ja3er.com/json")
}

// Helpers

func ConvertBodyToSig(r io.Reader) (string, string, error) {
	result := struct {
		JA3       string `json:"ja3"`
		UserAgent string `json:"User-Agent"`
	}{}

	if err := json.NewDecoder(r).Decode(&result); err != nil {
		return "", "", err
	}

	return result.JA3, result.UserAgent, nil
}

func CheckTransport(c *http.Client) (string, error) {
	req, err := http.NewRequest("GET", JA3erURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}

	ja3, _, err := ConvertBodyToSig(resp.Body)
	if err != nil {
		return "", err
	}

	return ja3, nil
}

func CheckTransportDefault(c *http.Client, t *testing.T) {
	result, err := CheckTransport(c)
	if err != nil {
		t.Fatal(err)
	}
	if result != DefaultJA3Sig {
		t.Fail()
	}
}

// Tests
func TestNewWithString(t *testing.T) {
	client, err := NewWithString(DefaultJA3Sig)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Get(JA3erURL)
	if err != nil {
		t.Fatal(err)
	}

	ja3, _, err := ConvertBodyToSig(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if ja3 != DefaultJA3Sig {
		t.Fail()
	}
}

func TestNew_browser(t *testing.T) {
	client, err := New(SafariAuto)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Get(JA3erURL)
	if err != nil {
		t.Fatal(err)
	}

	_, ua, err := ConvertBodyToSig(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if ua != SafariAuto.UserAgent {
		t.Fail()
	}
}

func TestNew_noextension(t *testing.T) {
	target := "771,4865-4866-4867-49196-49195-49188-49187-49162-49161-52393-49200-49199-49192-49191-49172-49171-52392-157-156-61-60-53-47-49160-49170-10,65281-0-23-13-5-18-16-11-51-45-43-10-21-2,29-23-24-25,0"
	_, err := NewWithString(target)
	if _, ok := err.(ErrExtensionNotExist); !ok {
		t.Fail()
	}
}

func TestNewTransport(t *testing.T) {
	tr, err := NewTransport(DefaultJA3Sig)
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Transport: tr}
	CheckTransportDefault(client, t)
}

func TestNewTransportWithConfig(t *testing.T) {
	tr, err := NewTransport(DefaultJA3Sig)
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Transport: tr}
	CheckTransportDefault(client, t)
}
