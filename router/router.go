package router

import (
	"userdb/middleware"
	
	"userdb/services"

	"github.com/gorilla/mux"
)

// Router is exported and used in main.go
func Router() *mux.Router {

	router := mux.NewRouter()
	router.HandleFunc("/api/user/search", middleware.Authorized(services.SearchUser)).Methods("GET")
	router.HandleFunc("/api/user/{id}", middleware.Authorized(services.GetUser)).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/user",middleware.Authorized(services.GetAllUser) ).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/user", services.CreateUser).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/user/{id}",middleware.Authorized( services.UpdateUser)).Methods("PUT", "OPTIONS")
	router.HandleFunc("/api/user/{id}",middleware.Authorized(services.DeleteUser)).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/api/login", services.Login).Methods("POST", "OPTIONS")
	

	return router
}
