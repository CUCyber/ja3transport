package ja3client_test

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	. "github.com/CUCyber/ja3client"
)

const JA3Sig string = "771,4865-4866-4867-49196-49195-49188-49187-49162-49161-52393-49200-49199-49192-49191-49172-49171-52392-157-156-61-60-53-47-49160-49170-10,65281-0-23-13-5-18-16-11-51-45-43-10-21,29-23-24-25,0"

func ExampleNew() {
	client, _ := New(Chrome_Auto)
	client.Get("https://ja3er.com/json")
}

func ExampleNewWithString() {
	client, _ := NewWithString("771,4865-4866-4867-49196-49195-49188-49187-49162-49161-52393-49200-49199-49192-49191-49172-49171-52392-157-156-61-60-53-47-49160-49170-10,65281-0-23-13-5-18-16-11-51-45-43-10-21,29-23-24-25,0")
	client.Get("https://ja3er.com/json")
}

func TestNew(t *testing.T) {
	client, err := NewWithString(JA3Sig)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Get("https://ja3er.com/json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	dataB, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	data := string(dataB)
	fmt.Println(data)
}

func TestNewTransport(t *testing.T) {
	tr, err := NewTransport(JA3Sig)
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://ja3er.com/json")
	if err != nil {
		t.Fatal(err)
	}
	dataB, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	data := string(dataB)
	if !strings.Contains(data, "6fa3244afc6bb6f9fad207b6b52af26b") {
		t.Fail()
	}
}
