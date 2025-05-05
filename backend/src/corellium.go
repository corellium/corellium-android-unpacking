package main

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Corellium struct is the base configuration for the REST api interactions
type Corellium struct {
	username, password string
	domain             string
	token              string
	instanceID         string
}

// Login will return a LoginResponse for api usage, utilizing the provided credentials
func (c *Corellium) Login() (*LoginResponse, error) {
	request := LoginRequest{
		Username: c.username,
		Password: c.password,
	}

	var jsonData []byte
	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	response, err := post(
		fmt.Sprintf("https://%s%s", c.domain, "/api/v1/tokens"),
		jsonData)

	var loginResponse = new(LoginResponse)
	err = json.Unmarshal(response, &loginResponse)
	if err != nil {
		return nil, err
	}

	c.token = loginResponse.Token

	return loginResponse, nil
}

// Instances gets available instances for Corellium server
func (c *Corellium) Instances() (*Instance, error) {
	if c.token == "" {
		return nil, errors.New("no request token to use")
	}

	response, err := get(
		fmt.Sprintf("https://%s/api/v1/instances/%s", c.domain, c.instanceID),
		c.token)
	if err != nil {
		return nil, err
	}

	var instancesResponse Instance
	if err := json.Unmarshal(response, &instancesResponse); err != nil {
		return nil, err
	}

	return &instancesResponse, nil
}
