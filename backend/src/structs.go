package main

import "time"

// UnpackTask is used for worker management
type UnpackTask struct {
	Hash        string `json:"hash"`
	Filepath    string `json:"file_path"`
	PackageName string `json:"package_name"`
	ProxyPort   int    `json:"port"`
}

// LoginRequest is a struct for posting a login
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse is a struct for parsing login response parts we want
type LoginResponse struct {
	// ResponseTime int64     `json:"time"`
	Token string `json:"token"`
	// Expiration   time.Time `json:"expiration"`
}

// InstancesRequest struct for Instances API call request
type InstancesRequest struct {
	Token string `json:"token"`
}

// InstancesResponse struct for Instances API call response
type InstancesResponse struct {
	ProjectData Projects    `json:"projects"`
	Instances   []Instances `json:"instances"`
}

// Instances struct data
type Instances struct {
	ID         string    `json:"id"`
	Project    string    `json:"project"`
	Created    time.Time `json:"created"`
	Status     string    `json:"status"`
	Name       string    `json:"name"`
	PortADB    string    `json:"port-adb"`
	ServicesIP string    `json:"services"`
}

// Projects struct data
type Projects struct {
	Domain Domain `json:"domain"`
}

// Domain struct data
type Domain struct {
	Domain  string `json:"domain"`
	Name    string `json:"name"`
	Label   string `json:"label"`
	Android bool   `json:"android"`
	// totp
	NoIOS       bool   `json:"noIOS"`
	LicenseType string `json:"licenseType"`
	Instances   int    `json:"instances"`
	Cores       int    `json:"cores"`
	RAM         int64  `json:"ram"`
}
