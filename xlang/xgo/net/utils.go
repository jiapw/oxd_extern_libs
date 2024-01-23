package net

import (
	"encoding/json"
	"net/http"
)

func MarshalHttpRequest(r *http.Request) ([]byte, error) {
	j, err := json.Marshal(struct {
		Host       string
		Method     string
		Path       string
		Proto      string
		RemoteAddr string
	}{
		Host:       r.Host,
		Method:     r.Method,
		Path:       r.URL.Path,
		Proto:      r.Proto,
		RemoteAddr: r.RemoteAddr,
	})
	if err != nil {
		return nil, err
	}
	return j, nil
}
