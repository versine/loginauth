// Copyright 2017 David Baerg

// Package loginauth implements the SMTP LOGIN authentication mechanism compatible
// with the net/smtp package
//
// Some code adapted from: https://gist.github.com/homme/22b457eb054a07e7b2fb
// License in LICENSE-andelf
//
// Some code adapted from: https://golang.org/src/net/smtp/auth.go
// Copyright 2010 The Go Authors. All rights reserved.
// License in LICENSE-GoAuthors
package loginauth

import (
	"errors"
	"net/smtp"
)

// LoginAuth returns an Auth that implements the LOGIN authentication
// mechanism
// The returned Auth uses the given username and password to authenticate
// on TLS connections to host.
func LoginAuth(username, password, host string) smtp.Auth {
	return &loginAuth{username, password, host}
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS {
		advertised := false
		for _, mechanism := range server.Auth {
			if mechanism == "LOGIN" {
				advertised = true
				break
			}
		}
		if !advertised {
			return "", nil, errors.New("unencrypted connection")
		}
	}
	if server.Name != a.host {
		return "", nil, errors.New("wrong host name")
	}
	resp := []byte(a.username)
	return "LOGIN", resp, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case "Username:":
			return []byte(a.username), nil
		case "Password:":
			return []byte(a.password), nil
		default:
			return nil, errors.New("Unkown fromServer")
		}
	}

	return nil, nil
}

type loginAuth struct {
	username string
	password string
	host     string
}
