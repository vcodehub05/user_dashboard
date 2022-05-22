package entities

import "github.com/dgrijalva/jwt-go/v4"

type User struct {
    ID       string  `json:"user_id"`
    FirstName     string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email string `json:"email"`
	Password string `json:"password"`
	DOB string `json:"dob"`
	
}
type Login_info struct{
	Email string `json:"email"`
	Password string `json:"password"`

}
type Claims struct{
	Email string `json:"email"`
	jwt.StandardClaims

}

