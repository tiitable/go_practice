package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
)

// Client struct to hold a client's WebSocket connection and username.
type Client struct {
	conn     *websocket.Conn
	username string // Changed from name to username
}

var (
	clients   = make(map[*Client]bool)
	clientsMu sync.Mutex
	broadcast = make(chan []byte)
	// db is declared in main.go and accessible here because they are in the same package
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all connections
	},
}

var jwtSecret = []byte("your_jwt_secret") // Secret for signing JWTs

// StartBroadcaster runs in a goroutine to broadcast messages.
func StartBroadcaster() {
	for {
		msg := <-broadcast
		clientsMu.Lock()
		for client := range clients {
			err := client.conn.WriteMessage(websocket.TextMessage, msg)
			if err != nil {
				log.Printf("Error sending message to %s: %v", client.username, err)
				// Clean up the broken connection
				client.conn.Close()
				delete(clients, client)
			}
		}
		clientsMu.Unlock()
	}
}

// LoginHandler handles user login and returns a JWT.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var hash string
	// Use the db variable from main.go
	// Changed 'name' to 'username' in the query
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = ?", creds.Username).Scan(&hash)
	if err == sql.ErrNoRows {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	} else if err != nil {
		log.Printf("Database error during login: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(creds.Password)); err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": creds.Username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // Token expires in 24 hours
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		log.Printf("Error signing token: %v", err)
		http.Error(w, "Could not create token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

// RegisterHandler handles new user registration.
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Check if user already exists
	var existingID int
	// Changed 'name' to 'username' in the query
	err := db.QueryRow("SELECT id FROM users WHERE username = ?", creds.Username).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		log.Printf("Database error during registration check: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if err == nil { // User found
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}

	// Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Insert new user into database
	// Changed 'name' to 'username' in the query
	result, err := db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", creds.Username, string(hash))
	if err != nil {
		log.Printf("Database error during user insertion: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Get the auto-generated ID
	userID, err := result.LastInsertId()
	if err != nil {
		log.Printf("Error getting last insert ID: %v", err)
		// Continue without sending ID, or send an error? Sending ID is not critical for chat.
	}

	// Respond with success and user info
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{"message": "User registered successfully!", "username": creds.Username, "id": userID})
}

// ChangeUsernameHandler handles requests to change a user's username.
func ChangeUsernameHandler(w http.ResponseWriter, r *http.Request) {
	var reqBody struct {
		CurrentUsername string `json:"current_username"`
		Password        string `json:"password"`
		NewUsername     string `json:"new_username"`
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Basic validation
	if reqBody.CurrentUsername == "" || reqBody.Password == "" || reqBody.NewUsername == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	if reqBody.CurrentUsername == reqBody.NewUsername {
		http.Error(w, "New username cannot be the same as the current username", http.StatusBadRequest)
		return
	}

	// Authenticate the user with current credentials
	var storedHash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = ?", reqBody.CurrentUsername).Scan(&storedHash)
	if err == sql.ErrNoRows {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	} else if err != nil {
		log.Printf("Database error during username change (auth): %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(reqBody.Password)); err != nil {
		http.Error(w, "Invalid current username or password", http.StatusUnauthorized)
		return
	}

	// Check if the new username already exists
	var existingID int
	err = db.QueryRow("SELECT id FROM users WHERE username = ?", reqBody.NewUsername).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		log.Printf("Database error during username change (new username check): %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if err == nil {
		http.Error(w, "New username already exists", http.StatusConflict)
		return
	}

	// Update the username in the database
	_, err = db.Exec("UPDATE users SET username = ? WHERE username = ?", reqBody.NewUsername, reqBody.CurrentUsername)
	if err != nil {
		log.Printf("Database error during username update: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Username changed successfully!")
}

// ChangePasswordHandler handles requests to change a user's password.
func ChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	var reqBody struct {
		Username        string `json:"username"`
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Basic validation
	if reqBody.Username == "" || reqBody.CurrentPassword == "" || reqBody.NewPassword == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Authenticate the user with current credentials
	var storedHash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = ?", reqBody.Username).Scan(&storedHash)
	if err == sql.ErrNoRows {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	} else if err != nil {
		log.Printf("Database error during password change (auth): %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(reqBody.CurrentPassword)); err != nil {
		http.Error(w, "Invalid username or current password", http.StatusUnauthorized)
		return
	}

	// Hash the new password
	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(reqBody.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing new password: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Update the password hash in the database
	_, err = db.Exec("UPDATE users SET password_hash = ? WHERE username = ?", string(newPasswordHash), reqBody.Username)
	if err != nil {
		log.Printf("Database error during password update: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "Password changed successfully!")
}

// WsHandler handles WebSocket connections after JWT authentication.
func WsHandler(w http.ResponseWriter, r *http.Request) {
	// Authentication already done by the handler chain or by checking token here.
	// For simplicity, we'll re-validate the token query param here.

	tokenString := r.URL.Query().Get("token")
	// In a real app, you'd want to validate the token more robustly, maybe middleware.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Unauthorized: Invalid or missing token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["username"] == nil {
		http.Error(w, "Unauthorized: Invalid token claims", http.StatusUnauthorized)
		return
	}

	username, ok := claims["username"].(string)
	if !ok {
		http.Error(w, "Unauthorized: Invalid username in token", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error for user", username, ":", err)
		return
	}

	// Create a new client instance
	client := &Client{conn: conn, username: username} // Use username field

	// Register the new client
	clientsMu.Lock()
	clients[client] = true
	clientsMu.Unlock()

	log.Printf("Client connected: %s", client.username)
	// Broadcast join message
	joinMsg := []byte(client.username + " has joined the chat.")
	broadcast <- joinMsg

	defer func() {
		clientsMu.Lock()
		delete(clients, client)
		clientsMu.Unlock()
		conn.Close()
		log.Printf("Client disconnected: %s", client.username) // Log disconnect here
		// Broadcast leave message
		leaveMsg := []byte(client.username + " has left the chat.")
		broadcast <- leaveMsg
	}()

	for {
		// Use a separate variable for the read message to avoid issues with the defer closing conn
		_, msg, readErr := client.conn.ReadMessage()
		if readErr != nil {
			log.Println("Read error from client", client.username, ":", readErr)
			break // This will trigger the defer function
		}

		message := string(msg)
		trimmedMsg := strings.TrimSpace(message)

		if trimmedMsg == "/users" {
			// Handle /users command
			handleUsersCommand(client)
		} else if trimmedMsg == "/help" { // Handle /help command
			// Handle /help command
			handleHelpCommand(client)
		} else if strings.HasPrefix(trimmedMsg, "/msg ") {
			// Handle /msg command
			handleMsgCommand(client, trimmedMsg)
		} else if strings.HasPrefix(trimmedMsg, "/changeusername ") { // Handle /changeusername command
			// Handle change username command
			handleChangeUsernameCommand(client, trimmedMsg)
		} else if strings.HasPrefix(trimmedMsg, "/changepassword ") { // Handle /changepassword command
			// Handle change password command
			handleChangePasswordCommand(client, trimmedMsg)
		} else {
			// Broadcast regular message
			fullMsg := []byte(client.username + ": " + message)
			broadcast <- fullMsg
		}
	}
}

// handleUsersCommand sends a list of online users to the requesting client.
func handleUsersCommand(client *Client) {
	clientsMu.Lock()
	userList := []string{}
	for c := range clients {
		userList = append(userList, c.username) // Use client.username
	}
	clientsMu.Unlock()

	onlineUsersMsg := "Online users: " + strings.Join(userList, ", ")
	err := client.conn.WriteMessage(websocket.TextMessage, []byte(onlineUsersMsg))
	if err != nil {
		log.Printf("Error sending user list to %s: %v", client.username, err)
	}
}

// handleMsgCommand parses a private message and sends it to the target user.
func handleMsgCommand(sender *Client, message string) {
	parts := strings.SplitN(strings.TrimSpace(message), " ", 3)
	if len(parts) != 3 {
		err := sender.conn.WriteMessage(websocket.TextMessage, []byte("Invalid /msg command format. Use: /msg <username> <message>"))
		if err != nil {
			log.Printf("Error sending /msg format error to %s: %v", sender.username, err)
		}
		return
	}

	recipientName := parts[1]
	priMsgContent := parts[2]

	clientsMu.Lock()
	recipientClient := findClientByUsername(recipientName) // Helper function
	clientsMu.Unlock()

	if recipientClient != nil {
		formattedMsg := []byte(fmt.Sprintf("[Private from %s]: %s", sender.username, priMsgContent))
		err := recipientClient.conn.WriteMessage(websocket.TextMessage, formattedMsg)
		if err != nil {
			log.Printf("Error sending private message to %s: %v", recipientClient.username, err)
		}
	} else {
		err := sender.conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("User %s not found or offline.", recipientName)))
		if err != nil {
			log.Printf("Error sending user not found message to %s: %v", sender.username, err)
		}
	}
}

// handleHelpCommand sends a list of available commands to the requesting client.
func handleHelpCommand(client *Client) {
	helpMessage := "Available chat commands:\n"
	helpMessage += "/users - List online users\n"
	helpMessage += "/msg <username> <message> - Send a private message\n"
	helpMessage += "/help - Show this help message\n"
	// Added new chat commands
	helpMessage += "/changeusername <new_username> <current_password> - Change your username\n"
	helpMessage += "/changepassword <current_password> <new_password> - Change your password"

	err := client.conn.WriteMessage(websocket.TextMessage, []byte(helpMessage))
	if err != nil {
		log.Printf("Error sending help message to %s: %v", client.username, err)
	}
}

// Helper function to find a client by username (requires mutex lock outside)
func findClientByUsername(username string) *Client {
	for client := range clients {
		if client.username == username {
			return client
		}
	}
	return nil
}

// changeUsername sends a POST request to the server to change the user's username.
// This function is now repurposed to handle the logic when the command is received via WebSocket.
func handleChangeUsernameCommand(client *Client, message string) {
	parts := strings.Fields(message) // Split by whitespace
	// Expected format: /changeusername <new_username> <current_password>
	if len(parts) != 3 {
		sendWsMessage(client, "Invalid /changeusername command format. Use: /changeusername <new_username> <current_password>")
		return
	}

	newUsername := parts[1]
	currentPassword := parts[2]

	// Authenticate the user with current credentials
	var storedHash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = ?", client.username).Scan(&storedHash)
	if err == sql.ErrNoRows {
		// This should not happen if the client is connected via authenticated WebSocket, but handle defensively
		sendWsMessage(client, "Error: User not found.")
		log.Printf("Auth error during username change for connected user %s: User not found", client.username)
		return
	} else if err != nil {
		sendWsMessage(client, "Internal server error during authentication.")
		log.Printf("Database error during username change (auth) for %s: %v", client.username, err)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(currentPassword)); err != nil {
		sendWsMessage(client, "Invalid current password.")
		return
	}

	// Check if the new username already exists
	var existingID int
	err = db.QueryRow("SELECT id FROM users WHERE username = ?", newUsername).Scan(&existingID)
	if err != nil && err != sql.ErrNoRows {
		sendWsMessage(client, "Internal server error checking new username.")
		log.Printf("Database error during username change (new username check) for %s: %v", client.username, err)
		return
	}
	if err == nil { // User found with new username
		sendWsMessage(client, fmt.Sprintf("Username '%s' already exists.", newUsername))
		return
	}

	// Update the username in the database
	_, err = db.Exec("UPDATE users SET username = ? WHERE username = ?", newUsername, client.username)
	if err != nil {
		sendWsMessage(client, "Internal server error updating username.")
		log.Printf("Database error during username update for %s: %v", client.username, err)
		return
	}

	// Update the username in the client struct (important for subsequent messages)
	client.username = newUsername

	sendWsMessage(client, fmt.Sprintf("Username successfully changed to '%s'.", newUsername))
	log.Printf("Username changed from %s to %s", client.username, newUsername) // Log the change
}

// changePassword sends a POST request to the server to change the user's password.
// This function is now repurposed to handle the logic when the command is received via WebSocket.
func handleChangePasswordCommand(client *Client, message string) {
	parts := strings.Fields(message) // Split by whitespace
	// Expected format: /changepassword <current_password> <new_password>
	if len(parts) != 3 {
		sendWsMessage(client, "Invalid /changepassword command format. Use: /changepassword <current_password> <new_password>")
		return
	}

	currentPassword := parts[1]
	newPassword := parts[2]

	// Authenticate the user with current credentials
	var storedHash string
	err := db.QueryRow("SELECT password_hash FROM users WHERE username = ?", client.username).Scan(&storedHash)
	if err == sql.ErrNoRows {
		// This should not happen if the client is connected via authenticated WebSocket, but handle defensively
		sendWsMessage(client, "Error: User not found.")
		log.Printf("Auth error during password change for connected user %s: User not found", client.username)
		return
	} else if err != nil {
		sendWsMessage(client, "Internal server error during authentication.")
		log.Printf("Database error during password change (auth) for %s: %v", client.username, err)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(currentPassword)); err != nil {
		sendWsMessage(client, "Invalid current password.")
		return
	}

	// Hash the new password
	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		sendWsMessage(client, "Internal server error hashing new password.")
		log.Printf("Error hashing new password for %s: %v", client.username, err)
		return
	}

	// Update the password hash in the database
	_, err = db.Exec("UPDATE users SET password_hash = ? WHERE username = ?", string(newPasswordHash), client.username)
	if err != nil {
		sendWsMessage(client, "Internal server error updating password.")
		log.Printf("Database error during password update for %s: %v", client.username, err)
		return
	}

	sendWsMessage(client, "Password successfully changed.")
	log.Printf("Password changed for user %s", client.username) // Log the change
}

// Helper function to send a WebSocket message to a specific client
func sendWsMessage(client *Client, message string) {
	err := client.conn.WriteMessage(websocket.TextMessage, []byte(message))
	if err != nil {
		log.Printf("Error sending message to client %s: %v", client.username, err)
		// Consider marking client for removal if write fails consistently
	}
}
