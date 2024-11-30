package routes

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"netsocial/middlewares"
	"netsocial/types"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/gtuk/discordwebhook"
	"github.com/resend/resend-go/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = os.Getenv("jwtSecret")

func generateJWT(userID uuid.UUID) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID.String(),
		"exp":     time.Now().Add(time.Hour * 7628).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenCookie, err := r.Cookie("token")
		if err != nil || tokenCookie == nil {
			http.Error(w, "Hey! You need to provide your token in the authorization header. This endpoint is for authenticated users only!", http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(tokenCookie.Value, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("invalid token signing method")
			}
			return []byte(jwtSecret), nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		userID, err := uuid.Parse(claims["user_id"].(string))
		if err != nil {
			http.Error(w, "Invalid user ID in token", http.StatusUnauthorized)
			return
		}

		sessionCollection := r.Context().Value("db").(*mongo.Client).Database("SocialFlux").Collection("sessions")
		var session types.Session
		err = sessionCollection.FindOne(context.TODO(), bson.M{
			"user_id": userID.String(),
			"token":   tokenCookie.Value,
		}).Decode(&session)
		if err != nil {
			http.Error(w, "Session expired", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "user_id", userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func FetchDisposableDomains() (map[string]bool, error) {
	resp, err := http.Get("https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	disposableDomains := make(map[string]bool)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		domain := scanner.Text()
		disposableDomains[domain] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return disposableDomains, nil
}

func sendWelcomeEmail(email string) error {
	apiKey := os.Getenv("RESEND_API_KEY")

	client := resend.NewClient(apiKey)
	params := &resend.SendEmailRequest{
		From:    "Netsocial <welcome@netsocial.app>",
		To:      []string{email},
		Subject: "Welcome to Netsocial!",
		Text:    "Hey, welcome to Netsocial! Let's start by making your first post. [Post Now!](https://netsocial.app/post/new)",
	}
	_, err := client.Emails.Send(params)
	return err
}

func UserSignup(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, "Database connection not available", http.StatusInternalServerError)
		return
	}
	userCollection := db.Database("SocialFlux").Collection("users")

	username := r.Header.Get("x-username")
	encryptedemail := r.Header.Get("X-email")
	encryptedPassword := r.Header.Get("X-Password")

	if username == "" || encryptedemail == "" || encryptedPassword == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	email, err := middlewares.DecryptAES(encryptedemail)
	if err != nil {
		http.Error(w, "Failed to decrypt email", http.StatusBadRequest)
		return
	}

	password, err := middlewares.DecryptAES(encryptedPassword)
	if err != nil {
		http.Error(w, "Failed to decrypt password", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	disposableDomains, err := FetchDisposableDomains()
	if err != nil {
		http.Error(w, "Failed to fetch disposable email domains", http.StatusInternalServerError)
		return
	}

	emailParts := strings.Split(email, "@")
	if len(emailParts) != 2 {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	emailDomain := emailParts[1]
	if _, exists := disposableDomains[emailDomain]; exists {
		err = sendDiscordWebhookFailure(username, email)
		if err != nil {
			http.Error(w, "Failed to send Discord webhook", http.StatusInternalServerError)
			return
		}
		http.Error(w, "Disposable email domains are not allowed", http.StatusBadRequest)
		return
	}

	count, err := userCollection.CountDocuments(context.TODO(), bson.M{
		"$or": []bson.M{
			{"username": username},
			{"email": email},
		},
	})
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if count > 0 {
		http.Error(w, "Username or email already exists", http.StatusBadRequest)
		return
	}

	var lastUser types.User
	err = userCollection.FindOne(context.TODO(), bson.M{}, options.FindOne().SetSort(bson.D{{Key: "userid", Value: -1}})).Decode(&lastUser)
	if err != nil && err != mongo.ErrNoDocuments {
		http.Error(w, "Failed to retrieve last user", http.StatusInternalServerError)
		return
	}

	newUserID := lastUser.UserID + 1

	user := types.User{
		ID:             uuid.New().String(),
		UserID:         newUserID,
		Username:       username,
		DisplayName:    username,
		IsVerified:     false,
		IsOrganisation: false,
		ProfilePicture: "https://cdn.netsocial.app/logos/netsocial.png",
		IsDeveloper:    false,
		IsOwner:        false,
		IsPartner:      false,
		Email:          email,
		Links:          []string{},
		Password:       string(hashedPassword),
		CreatedAt:      time.Now(),
	}

	result, err := userCollection.InsertOne(context.TODO(), user)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Send the welcome email
	err = sendWelcomeEmail(email)
	if err != nil {
		// Delete the user if the email fails to send
		_, deleteErr := userCollection.DeleteOne(context.TODO(), bson.M{"_id": result.InsertedID})
		if deleteErr != nil {
			http.Error(w, "Failed to send email and rollback user creation", http.StatusInternalServerError)
			return
		}
		http.Error(w, "Failed to send welcome email. Account creation not allowed", http.StatusBadRequest)
		return
	}

	err = sendDiscordWebhook(username)
	if err != nil {
		http.Error(w, "Failed to send Discord webhook", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintln(w, `{"message": "User created successfully"}`)
}

func sendDiscordWebhook(username string) error {
	webhookURL := os.Getenv("DISCORD_WEBHOOK_URL")
	if webhookURL == "" {
		return errors.New("Discord webhook URL not set in environment variables")
	}

	content := "A new user has registered by the name: " + username
	message := discordwebhook.Message{
		Content: &content,
	}

	err := discordwebhook.SendMessage(webhookURL, message)
	if err != nil {
		log.Printf("Error sending Discord webhook: %v", err)
		return err
	}

	return nil
}

func sendDiscordWebhookFailure(username, email string) error {
	webhookURL := os.Getenv("DISCORD_WEBHOOK_URL")
	if webhookURL == "" {
		return errors.New("Discord webhook URL not set in environment variables")
	}

	content := fmt.Sprintf("User registration failed for username: %s with email: %s (Disposable email domain)", username, email)
	message := discordwebhook.Message{
		Content: &content,
	}

	err := discordwebhook.SendMessage(webhookURL, message)
	if err != nil {
		log.Printf("Error sending Discord webhook: %v", err)
		return err
	}

	return nil
}

func UserLogin(w http.ResponseWriter, r *http.Request) {
	// Access the database connection from the context
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	userCollection := db.Database("SocialFlux").Collection("users")
	sessionCollection := db.Database("SocialFlux").Collection("sessions")

	// Retrieve login data from request headers
	Identifier := r.Header.Get("X-usernameoremail")
	password := r.Header.Get("X-password")

	// Validate that the headers are not empty
	if Identifier == "" || password == "" {
		http.Error(w, `{"error": "Missing required fields"}`, http.StatusBadRequest)
		return
	}

	// Decrypt Identifier
	decryptedIdentifier, err := middlewares.DecryptAES(Identifier)
	if err != nil {
		http.Error(w, `{"error": "Failed to decrypt Identifier"}`, http.StatusBadRequest)
		return
	}

	// Decrypt the password
	decryptedPassword, err := middlewares.DecryptAES(password)
	if err != nil {
		http.Error(w, `{"error": "Failed to decrypt password"}`, http.StatusBadRequest)
		return
	}

	// Find user in the database
	var user types.User
	err = userCollection.FindOne(context.TODO(), bson.M{
		"$or": []bson.M{
			{"username": decryptedIdentifier},
			{"email": decryptedIdentifier},
		},
	}).Decode(&user)
	if err != nil {
		http.Error(w, `{"error": "Invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	// Compare hashed passwords
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(decryptedPassword))
	if err != nil {
		http.Error(w, `{"error": "Invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	// Validate and generate token
	userUUID, err := uuid.Parse(user.ID)
	if err != nil {
		http.Error(w, `{"error": "Invalid user ID format"}`, http.StatusInternalServerError)
		return
	}

	token, err := generateJWT(userUUID)
	if err != nil {
		http.Error(w, `{"error": "Failed to generate token"}`, http.StatusInternalServerError)
		return
	}

	// Set the JWT token in a secure cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	// Create and store session
	sessionID := uuid.New().String()
	device := r.UserAgent()

	claims, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.NewValidationError("Invalid token", jwt.ValidationErrorSignatureInvalid)
		}
		return []byte(jwtSecret), nil
	})
	if err != nil {
		http.Error(w, `{"error": "Failed to parse token"}`, http.StatusInternalServerError)
		return
	}

	expirationTime := time.Unix(int64(claims.Claims.(jwt.MapClaims)["exp"].(float64)), 0)

	session := types.Session{
		UserID:    userUUID.String(),
		SessionID: sessionID,
		Device:    device,
		StartedAt: time.Now(),
		ExpiresAt: expirationTime,
		Token:     token,
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    session.SessionID,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	_, err = sessionCollection.InsertOne(context.TODO(), session)
	if err != nil {
		http.Error(w, `{"error": "Failed to create session"}`, http.StatusInternalServerError)
		return
	}

	// Send login info to Discord webhook
	err = sendDiscordWebhookLogin(user.Username)
	if err != nil {
		log.Printf("Error sending Discord webhook: %v", err)
	}

	// Respond with success message
	response := map[string]interface{}{
		"message": "Logged in successfully",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func sendDiscordWebhookLogin(username string) error {
	webhookURL := os.Getenv("DISCORD_WEBHOOK_URL")
	if webhookURL == "" {
		return errors.New("Discord webhook URL not set in environment variables")
	}

	// Construct the message content with username, host, and IP address
	content := fmt.Sprintf("User logged in: %s", username)

	message := discordwebhook.Message{
		Content: &content,
	}

	// Send the message to the Discord webhook
	err := discordwebhook.SendMessage(webhookURL, message)
	if err != nil {
		return err
	}

	return nil
}

func UserLogout(w http.ResponseWriter, r *http.Request) {
	currentSessionID := r.Header.Get("X-sessionID")
	encrypteduserID := r.Header.Get("X-userID")

	if currentSessionID == "" || encrypteduserID == "" {
		http.Error(w, jsonResponse("Missing session_id or userID"), http.StatusBadRequest)
		return
	}

	userID, err := middlewares.DecryptAES(encrypteduserID)
	if err != nil {
		http.Error(w, "Failed to decrypt userId", http.StatusBadRequest)
		return
	}

	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, jsonResponse("Database connection not available"), http.StatusInternalServerError)
		return
	}
	sessionCollection := db.Database("SocialFlux").Collection("sessions")

	result, err := sessionCollection.DeleteOne(context.TODO(), bson.M{
		"session_id": currentSessionID,
		"user_id":    userID,
	})
	if err != nil {
		http.Error(w, jsonResponse("Failed to revoke session"), http.StatusInternalServerError)
		return
	}

	// Check if a session was deleted
	if result.DeletedCount == 0 {
		http.Error(w, jsonResponse("Session not found"), http.StatusNotFound)
		return
	}

	// Invalidate the JWT token (log out the user)
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	// Clear the session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	// Respond with a success message
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

func ChangePassword(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, "Database connection not available", http.StatusInternalServerError)
		return
	}
	userCollection := db.Database("SocialFlux").Collection("users")

	userID := r.Header.Get("X-userID")
	var user types.User
	err := userCollection.FindOne(context.TODO(), bson.M{"id": userID}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	oldPassword := r.Header.Get("X-oldpassword")
	newPassword := r.Header.Get("X-newpassword")

	// Decrypt the oldpassword
	decryptedoldPassword, err := middlewares.DecryptAES(oldPassword)
	if err != nil {
		http.Error(w, `{"error": "Failed to decrypt old password"}`, http.StatusBadRequest)
		return
	}

	// Decrypt the newpassword
	decryptednewPassword, err := middlewares.DecryptAES(newPassword)
	if err != nil {
		http.Error(w, `{"error": "Failed to decrypt new password"}`, http.StatusBadRequest)
		return
	}

	if newPassword == "" {
		http.Error(w, "New password is required", http.StatusBadRequest)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(decryptedoldPassword))
	if err != nil {
		http.Error(w, "Incorrect old password", http.StatusUnauthorized)
		return
	}

	hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(decryptednewPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash new password", http.StatusInternalServerError)
		return
	}

	_, err = userCollection.UpdateOne(context.TODO(), bson.M{"_id": userID}, bson.M{"$set": bson.M{"password": string(hashedNewPassword)}})
	if err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, `{"message": "Password changed successfully"}`)
}

func CurrentUser(w http.ResponseWriter, r *http.Request) {
	// Retrieve MongoDB client from context
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	// Retrieve user ID from context (UUID)
	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		http.Error(w, `{"error": "Invalid user ID"}`, http.StatusInternalServerError)
		return
	}

	// Set up collections
	userCollection := db.Database("SocialFlux").Collection("users")
	sessionCollection := db.Database("SocialFlux").Collection("sessions")

	// Retrieve user information
	var user types.User
	err := userCollection.FindOne(context.TODO(), bson.M{"id": userID.String()}).Decode(&user)
	if err != nil {
		http.Error(w, `{"error": "Failed to find user"}`, http.StatusInternalServerError)
		return
	}

	// Retrieve sessions for the user
	var sessions []map[string]interface{}
	cursor, err := sessionCollection.Find(context.TODO(), bson.M{"user_id": userID.String()})
	if err != nil {
		http.Error(w, `{"error": "Failed to retrieve sessions"}`, http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	// Retrieve the session ID from the cookie
	currentSessionCookie, err := r.Cookie("session_id")
	var currentSessionID string
	if err == nil {
		currentSessionID = currentSessionCookie.Value
	}

	for cursor.Next(context.TODO()) {
		var session types.Session
		if err := cursor.Decode(&session); err != nil {
			http.Error(w, `{"error": "Failed to decode session"}`, http.StatusInternalServerError)
			return
		}

		// Check if this session is the current session
		currentSession := session.SessionID == currentSessionID

		sessions = append(sessions, map[string]interface{}{
			"session_id": session.SessionID,
			"device":     session.Device,
			"started_at": session.StartedAt,
			"expires_at": session.ExpiresAt,
			"current":    currentSession,
		})
	}

	if err := cursor.Err(); err != nil {
		http.Error(w, `{"error": "Cursor error"}`, http.StatusInternalServerError)
		return
	}

	// Prepare response
	response := map[string]interface{}{
		"_id":             user.ID,
		"username":        user.Username,
		"displayname":     user.DisplayName,
		"bio":             user.Bio,
		"links":           user.Links,
		"isPrivateHearts": user.IsPrivateHearts,
		"isPrivate":       user.IsPrivate,
		"profilePicture":  user.ProfilePicture,
		"isOrganisation":  user.IsOrganisation,
		"sessions":        sessions,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, `{"error": "Failed to encode response"}`, http.StatusInternalServerError)
	}
}

func LogOutSession(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	sessionIDStr := r.Header.Get("X-sessionID")
	encrypteduserID := r.Header.Get("X-userID")

	userIDStr, err := middlewares.DecryptAES(encrypteduserID)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	// Validate the user_id (UUID)
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		http.Error(w, `{"error": "Invalid user ID"}`, http.StatusBadRequest)
		return
	}

	// Validate the session_id (UUID)
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		http.Error(w, `{"error": "Invalid session ID"}`, http.StatusBadRequest)
		return
	}

	// Retrieve database client from context
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	sessionCollection := db.Database("SocialFlux").Collection("sessions")

	// Delete the session and its JWT token
	result, err := sessionCollection.DeleteOne(context.TODO(), bson.M{
		"session_id": sessionID.String(), // Store as a string representation of UUID
		"user_id":    userID.String(),    // Store as a string representation of UUID
	})
	if err != nil {
		http.Error(w, `{"error": "Failed to revoke session"}`, http.StatusInternalServerError)
		return
	}

	if result.DeletedCount == 0 {
		http.Error(w, `{"error": "Session not found"}`, http.StatusNotFound)
		return
	}

	// Invalidate JWT token in cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		MaxAge:   -1,   // Expire the cookie immediately
		Secure:   true, // Ensure the cookie is sent over HTTPS
		SameSite: http.SameSiteNoneMode,
		Path:     "/",
	})

	// Respond with success
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, `{"message": "Session revoked and user logged out successfully"}`)
}

func jsonResponse(message string) string {
	response, _ := json.Marshal(map[string]string{"error": message})
	return string(response)
}

func Auth(router chi.Router) {
	router.Post("/auth/signup", (middlewares.DiscordErrorReport(http.HandlerFunc(UserSignup)).ServeHTTP))
	router.Post("/auth/login", (middlewares.DiscordErrorReport(http.HandlerFunc(UserLogin)).ServeHTTP))
	router.Post("/auth/logout", (middlewares.DiscordErrorReport(authMiddleware(http.HandlerFunc(UserLogout))).ServeHTTP))
	router.Post("/auth/change-password", (middlewares.DiscordErrorReport(authMiddleware(http.HandlerFunc(ChangePassword))).ServeHTTP))
	router.Delete("/auth/logout/session", (middlewares.DiscordErrorReport(authMiddleware(http.HandlerFunc(LogOutSession))).ServeHTTP))
	router.Get("/auth/@me", (middlewares.DiscordErrorReport(authMiddleware(http.HandlerFunc(CurrentUser))).ServeHTTP))
}
