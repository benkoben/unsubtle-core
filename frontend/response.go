package frontend

import (
	"fmt"
	"log"
	"net/http"
)

// Alert messages that can be rendered to user
const (
	// Alerts related to login
	InvalidFormDataError        HtmxResponse = `<div class="alert error">Invalid form data</div>`
	EmailAndPasswordError       HtmxResponse = `<div class="alert error">Email and password are required</div>`
	InvalidEmailOrPasswordError HtmxResponse = `<div class="alert error">Invalid email or password</div>`

	// Generic alerts
	ServerError HtmxResponse = `<div class="alert success">Server error</div>`

	// Alerts related to registration
	RegistrationSuccess   HtmxResponse = `<div class="alert success">Registration successful, Please switch to login tab</div>`
	InsecurePasswordError HtmxResponse = `<div class="alert error">Insecure password, try including more special characters or using a longer password</div>`
	DuplicateUserError    HtmxResponse = `<div class="alert error">Failed to create user, Email already exists</div>`
)

type HtmxResponse string

// DecorateSuccess wraps the HtmxResponse content with a success alert DIV element, applying relevant styling.
func (m *HtmxResponse) DecorateSuccess() {
	var newMessage HtmxResponse
	newMessage = HtmxResponse(fmt.Sprintf(`<div class="alert success">%s</div>`, *m))
	m = &newMessage
}

// DecorateError wraps the HtmxResponse content with an error alert DIV element, applying relevant styling.
func (m *HtmxResponse) DecorateError() {
	var newMessage HtmxResponse
	newMessage = HtmxResponse(fmt.Sprintf(`<div class="alert error">%s</div>`, *m))
	m = &newMessage
}

// Respond sends the HtmxResponse as an HTML response with an "OK" status and logs the process or any potential errors.
func (m *HtmxResponse) Respond(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(*m)); err != nil {
		log.Println("error writing htmx alert: ", err)
	}
}
