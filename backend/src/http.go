package main

import (
	"bytes"
	"crypto/tls"
	"io/ioutil"
	"net/http"
)

func getHTTPClient() *http.Client {
	// TODO : This should only be used in debug mode?
	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	tr := &http.Transport{TLSClientConfig: config}
	client := &http.Client{Transport: tr}
	return client
}

func post(url string, data []byte) ([]byte, error) {
	client := getHTTPClient()

	response, err := client.Post(url,
		"application/json",
		bytes.NewBuffer(data))

	if err != nil {
		return nil, err
	}

	return ioutil.ReadAll(response.Body)
}
