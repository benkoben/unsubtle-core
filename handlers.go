package main

import (
	"fmt"
	"net/http"
)

func handleHelloWorld(config *Config) http.Handler {
	// This pattern gives each handler its own closure environment. You can do initialization work in this space, and the data will be available to the handlers when they are called.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := w.Write([]byte(fmt.Sprintf("Hello World, I want to connect to database %s", config.Database.ConnectionString)))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Printf("%d bytes written\n", n)
		w.WriteHeader(http.StatusOK)
	})
}
