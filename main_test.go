package main

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
)

type MockHTTPClient struct{}

var errUnrecognizedURL = errors.New("unrecognised URL")

func (m *MockHTTPClient) Get(url2 string) (*http.Response, error) {
	u, _ := url.Parse(url2)
	p := filepath.Clean(u.Path)
	dat, _ := ioutil.ReadFile("./testdata" + p)

	response := &http.Response{
		Body: ioutil.NopCloser(bytes.NewBuffer(dat)),
	}

	return response, nil
}

func (m *MockHTTPClient) Do(r *http.Request) (*http.Response, error) {
	if r.URL.String() == "http://ocsp.digicert.com" {
		ocspResponseBytes, _ := ioutil.ReadFile("./testdata/twitter_ocsp_response_v1.der")
		response := &http.Response{
			Body: ioutil.NopCloser(bytes.NewBuffer(ocspResponseBytes)),
		}

		return response, nil
	}

	return nil, errUnrecognizedURL
}
