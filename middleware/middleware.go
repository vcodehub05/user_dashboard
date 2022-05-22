package middleware

import (
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go/v4"
	"os"
)


var MySigningKey = []byte(os.Getenv("SECRET_KEY"))

func Authorized(endpoint func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		coockie, err := r.Cookie("token-test")
		if err != nil {
			if err == http.ErrNoCookie {
				w.WriteHeader(http.StatusUnauthorized)
				
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		tokenRecv := coockie.Value
		if tokenRecv != "" {

			token, err := jwt.Parse(tokenRecv, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf(("Invalid Signing Method"))
				}

				return MySigningKey, nil
			})
			if err != nil {
				fmt.Fprintf(w, err.Error())
			}

			if token.Valid {
				endpoint(w, r)
			}

		} else {
			fmt.Fprintf(w, "No Authorization Token provided")

		}
	})
}
