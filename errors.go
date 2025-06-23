package main

import(
	"errors"
)

var (
	ResponseFailureError = errors.New("failed to respond to client")
	UnexpectedDbError = errors.New("failed to query database")
	MarhalResponseBodyError = errors.New("unable to marshal response body")
)
