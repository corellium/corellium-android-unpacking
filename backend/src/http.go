package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
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

	return io.ReadAll(response.Body)
}

func get(url string, token string) ([]byte, error) {
	client := getHTTPClient()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return io.ReadAll(response.Body)
}
