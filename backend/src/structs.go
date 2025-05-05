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

// Instance struct data
type Instance struct {
	ID        string    `json:"id"`
	Project   string    `json:"project"`
	Created   time.Time `json:"created"`
	State     string    `json:"state"`
	Error     *string   `json:"error"`
	Name      string    `json:"name"`
	PortADB   string    `json:"port-adb"`
	ServiceIP string    `json:"serviceIp"`
}
