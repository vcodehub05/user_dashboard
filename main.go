package main

import (
	"fmt"
	"log"
	"net/http"
	"userdb/router"

	"github.com/joho/godotenv"
)

func main() {
	r := router.Router()
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	fmt.Println("Starting server on the port 9000")

	log.Fatal(http.ListenAndServe("127.0.0.1:9000", r))
}
