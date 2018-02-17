package demisto

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
)

func DoRequest(serverURL, username, password, uri, method, body string) (int, *http.Response) {
	client, xsrfToken := CreateClient(serverURL, username, password)

	var b io.Reader
	if body != "" {
		var jsonStr = []byte(body)
		b = bytes.NewBuffer(jsonStr)
	}
	req, err := http.NewRequest(method, serverURL+"/"+uri, b)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-type", "application/json")
	req.Header.Add("X-XSRF-TOKEN", xsrfToken)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	return resp.StatusCode, resp
}

func CreateClient(serverURL, username, password string) (*http.Client, string) {
	cookieJar, _ := cookiejar.New(nil)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}
	client.Jar = cookieJar

	req, err := http.NewRequest("GET", serverURL, nil)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	var csrfToken string
	for _, element := range resp.Cookies() {
		if element.Name == "XSRF-TOKEN" {
			csrfToken = element.Value
		}
	}

	var jsonStr = []byte(fmt.Sprintf(`{"user":"%s", "password":"%s"}`, username, password))
	req, err = http.NewRequest("POST", serverURL+"/login", bytes.NewBuffer(jsonStr))
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-type", "application/json")
	req.Header.Add("X-XSRF-TOKEN", csrfToken)

	resp, err = client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	return client, csrfToken
}
