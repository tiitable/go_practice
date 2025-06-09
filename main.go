package main

import (
	"database/sql"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
)

var db *sql.DB // Declare db at package level so server.go can access it

// enableCORS is a middleware to add CORS headers for development.
func enableCORS(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow requests from any origin during development
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		// Handle preflight requests (OPTIONS)
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		handler.ServeHTTP(w, r)
	})
}

func main() {
	var err error
	// Replace YOUR_PASSWORD with your actual MySQL root password
	db, err = sql.Open("mysql", "root:DELLxps14z@tcp(127.0.0.1:3306)/im_demo")
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	log.Println("Database connected.")

	// Start the broadcaster goroutine
	go StartBroadcaster()

	// Create a new ServeMux
	mux := http.NewServeMux()

	// Register handlers on the mux
	mux.HandleFunc("/login", LoginHandler)
	mux.HandleFunc("/register", RegisterHandler)
	mux.HandleFunc("/ws", WsHandler)
	mux.HandleFunc("/change-username", ChangeUsernameHandler)
	mux.HandleFunc("/change-password", ChangePasswordHandler) // New endpoint for changing password

	// No CORS middleware applied (as per previous request)

	log.Println("Server started on :8080")
	// Use the mux directly
	log.Fatal(http.ListenAndServe(":8080", mux))
}
