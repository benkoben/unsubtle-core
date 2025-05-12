package main

type response struct{
    Content string `json:"content,omitempty"`
    Status int `json:"status"`
    Error string `json:"error,omitempty"`
}

