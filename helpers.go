package main

import (
	"net/mail"
)

func validEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}
