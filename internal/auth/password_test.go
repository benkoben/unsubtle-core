package auth

import "testing"

func TestCheckPasswordHash(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "no errors create hash",
			password: "mySecurePassword",
			wantErr:  false,
		},
		{
			name:     "hit bcrypt length limit",
			password: "This is a string with exactly seventy-seven characters to make sure it works",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		hash, err := CreateHash(tt.password)
		if err != nil && tt.wantErr == false {
			t.Errorf("%s -> HashPassword(%s) got error but none was expected", tt.name, tt.password)
		}

		if ok := IsValid(tt.password, hash); !ok && tt.wantErr == false {
			t.Errorf("%s -> IsValid(%s, %s) got false but true was expected", tt.name, tt.password, hash)
		}

	}
}
