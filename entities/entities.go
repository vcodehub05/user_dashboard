package entities

import "github.com/dgrijalva/jwt-go/v4"
//struct user stores details of every employe
type User struct {
	ID        int64  `json:"user_id,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	Email     string `json:"email,omitempty"`
	Password  string `json:"password,omitempty"`
	DOB       string `json:"dob,omitempty"`
}
//struct ligin_info stores the credentials inserted by user while login
type Login_info struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type Claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}
