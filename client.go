package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"syscall"

	"github.com/gorilla/websocket"
	"golang.org/x/term"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Choose an action:")
	fmt.Println("1. Login")
	fmt.Println("2. Register")
	fmt.Print("Enter choice (1 or 2): ")

	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	var username, password, token string
	var err error

	fmt.Print("Enter username: ")
	username, _ = reader.ReadString('\n')
	username = strings.TrimSpace(username)

	// Masking password input requires golang.org/x/term
	fmt.Print("Enter password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Error reading password: %v", err)
	}
	password = string(bytePassword)
	fmt.Println() // Add a newline after reading password

	switch choice {
	case "1":
		token, err = login(username, password)
		if err != nil {
			log.Fatalf("Login failed: %v", err)
		}
		fmt.Println("Login successful!")
	case "2":
		err = register(username, password)
		if err != nil {
			log.Fatalf("Registration failed: %v", err)
		}
		// After registration, the server now sends a response with username and id
		// We already handled the response decoding in the register function.
		fmt.Println("Registration successful!")

		// After registration, prompt for login to get a token
		fmt.Print("Enter username again to login: ")
		username, _ = reader.ReadString('\n')
		username = strings.TrimSpace(username)

		fmt.Print("Enter password again to login: ")
		bytePassword, err = term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatalf("Error reading password for login after registration: %v", err)
		}
		password = string(bytePassword)
		fmt.Println() // Add a newline

		token, err = login(username, password)
		if err != nil {
			log.Fatalf("Login after registration failed: %v", err)
		}
		fmt.Println("Login successful!")

	default:
		log.Fatal("Invalid choice.")
	}

	fmt.Println("Got token:", token)

	url := fmt.Sprintf("ws://localhost:8080/ws?token=%s", token)

	// Establish WebSocket connection
	c, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		log.Fatal("WebSocket dial error:", err)
	}
	defer c.Close()

	fmt.Println("Connected to chat! Type /help for commands.")

	// Goroutine to receive messages
	go func() {
		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				log.Println("Read error:", err)
				return
			}
			fmt.Printf("%s\n", message) // Print message directly
		}
	}()

	// Main loop to send messages
	for {
		msg, _ := reader.ReadString('\n')
		msg = strings.TrimSpace(msg)

		// Don't send empty messages
		if msg == "" {
			continue
		}

		if err := c.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
			log.Println("Write error:", err)
			return
		}
	}
}

func login(username, password string) (string, error) {
	loginData := map[string]string{
		"username": username,
		"password": password,
	}
	jsonData, _ := json.Marshal(loginData)

	resp, err := http.Post("http://localhost:8080/login", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("HTTP POST error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Login failed with status %d: %s", resp.StatusCode, string(bodyBytes)) // Corrected variable name
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("Error decoding login response: %w", err)
	}

	token, ok := result["token"]
	if !ok || token == "" {
		return "", fmt.Errorf("Token not found in login response")
	}

	return token, nil
}

func register(username, password string) error {
	registerData := map[string]string{
		"username": username,
		"password": password,
	}
	jsonData, _ := json.Marshal(registerData)

	resp, err := http.Post("http://localhost:8080/register", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("HTTP POST error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Registration failed with status %d: %s", resp.StatusCode, string(bodyBytes)) // Corrected variable name
	}

	// Decode the success response to get the user ID and username
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		// Log error but don't fail registration - ID is not critical for chat.
		log.Printf("Warning: Could not decode registration success response: %v", err)
	} else {
		registeredUsername, _ := result["username"].(string)
		registeredID, _ := result["id"].(float64) // JSON numbers are float64 by default
		fmt.Printf("User '%s' registered successfully with ID: %.0f\n", registeredUsername, registeredID)
	}

	return nil
}
