package routes

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
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
	db := r.Context().Value("db").(*mongo.Client)
	userCollection := db.Database("SocialFlux").Collection("users")

	var signupData struct {
		Username          string `json:"username"`
		EncryptedEmail    string `json:"email"`
		EncryptedPassword string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&signupData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	email, err := middlewares.DecryptAES(signupData.EncryptedEmail)
	if err != nil {
		http.Error(w, "Failed to decrypt email", http.StatusBadRequest)
		return
	}

	password, err := middlewares.DecryptAES(signupData.EncryptedPassword)
	if err != nil {
		http.Error(w, "Failed to decrypt password", http.StatusBadRequest)
		return
	}

	if signupData.Username == "" || email == "" || password == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
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
		err = sendDiscordWebhookFailure(signupData.Username, email)
		if err != nil {
			http.Error(w, "Failed to send Discord webhook", http.StatusInternalServerError)
			return
		}
		http.Error(w, "Disposable email domains are not allowed", http.StatusBadRequest)
		return
	}

	count, err := userCollection.CountDocuments(context.TODO(), bson.M{
		"$or": []bson.M{
			{"username": signupData.Username},
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
		Username:       signupData.Username,
		DisplayName:    signupData.Username,
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

	err = sendWelcomeEmail(email)
	if err != nil {
		_, deleteErr := userCollection.DeleteOne(context.TODO(), bson.M{"_id": result.InsertedID})
		if deleteErr != nil {
			http.Error(w, "Failed to send email and rollback user creation", http.StatusInternalServerError)
			return
		}
		http.Error(w, "Failed to send welcome email. Account creation not allowed", http.StatusBadRequest)
		return
	}

	err = sendDiscordWebhook(signupData.Username)
	if err != nil {
		http.Error(w, "Failed to send Discord webhook", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully"})
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
	db := r.Context().Value("db").(*mongo.Client)
	userCollection := db.Database("SocialFlux").Collection("users")
	sessionCollection := db.Database("SocialFlux").Collection("sessions")

	var loginData struct {
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	decryptedIdentifier, err := middlewares.DecryptAES(loginData.Identifier)
	if err != nil {
		http.Error(w, "Failed to decrypt identifier", http.StatusBadRequest)
		return
	}

	decryptedPassword, err := middlewares.DecryptAES(loginData.Password)
	if err != nil {
		http.Error(w, "Failed to decrypt password", http.StatusBadRequest)
		return
	}

	var user types.User
	err = userCollection.FindOne(context.TODO(), bson.M{
		"$or": []bson.M{
			{"username": decryptedIdentifier},
			{"email": decryptedIdentifier},
		},
	}).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(decryptedPassword))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	userUUID, err := uuid.Parse(user.ID)
	if err != nil {
		http.Error(w, "Invalid user ID format", http.StatusInternalServerError)
		return
	}

	token, err := generateJWT(userUUID)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	sessionID := uuid.New().String()
	device := r.UserAgent()

	claims, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.NewValidationError("Invalid token", jwt.ValidationErrorSignatureInvalid)
		}
		return []byte(jwtSecret), nil
	})
	if err != nil {
		http.Error(w, "Failed to parse token", http.StatusInternalServerError)
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
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	err = sendDiscordWebhookLogin(user.Username)
	if err != nil {
		log.Printf("Error sending Discord webhook: %v", err)
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Logged in successfully"})
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
	var logoutData struct {
		SessionID string `json:"sessionId"`
		UserID    string `json:"userId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&logoutData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userID, err := middlewares.DecryptAES(logoutData.UserID)
	if err != nil {
		http.Error(w, "Failed to decrypt userId", http.StatusBadRequest)
		return
	}

	db := r.Context().Value("db").(*mongo.Client)
	sessionCollection := db.Database("SocialFlux").Collection("sessions")

	result, err := sessionCollection.DeleteOne(context.TODO(), bson.M{
		"session_id": logoutData.SessionID,
		"user_id":    userID,
	})
	if err != nil {
		http.Error(w, "Failed to revoke session", http.StatusInternalServerError)
		return
	}

	if result.DeletedCount == 0 {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

func ChangePassword(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*mongo.Client)
	userCollection := db.Database("SocialFlux").Collection("users")

	var passwordData struct {
		UserID      string `json:"userId"`
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&passwordData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userId, err := middlewares.DecryptAES(passwordData.UserID)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	var user types.User
	err = userCollection.FindOne(context.TODO(), bson.M{"id": userId}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	decryptedOldPassword, err := middlewares.DecryptAES(passwordData.OldPassword)
	if err != nil {
		http.Error(w, "Failed to decrypt old password", http.StatusBadRequest)
		return
	}

	decryptedNewPassword, err := middlewares.DecryptAES(passwordData.NewPassword)
	if err != nil {
		http.Error(w, "Failed to decrypt new password", http.StatusBadRequest)
		return
	}

	if decryptedNewPassword == "" {
		http.Error(w, "New password is required", http.StatusBadRequest)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(decryptedOldPassword))
	if err != nil {
		http.Error(w, "Incorrect old password", http.StatusUnauthorized)
		return
	}

	hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(decryptedNewPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash new password", http.StatusInternalServerError)
		return
	}

	_, err = userCollection.UpdateOne(context.TODO(), bson.M{"_id": passwordData.UserID}, bson.M{"$set": bson.M{"password": string(hashedNewPassword)}})
	if err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Password changed successfully"})
}

func CurrentUser(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*mongo.Client)
	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		http.Error(w, "Invalid user ID", http.StatusInternalServerError)
		return
	}

	userCollection := db.Database("SocialFlux").Collection("users")
	sessionCollection := db.Database("SocialFlux").Collection("sessions")

	var user types.User
	err := userCollection.FindOne(context.TODO(), bson.M{"id": userID.String()}).Decode(&user)
	if err != nil {
		http.Error(w, "Failed to find user", http.StatusInternalServerError)
		return
	}

	var sessions []map[string]interface{}
	cursor, err := sessionCollection.Find(context.TODO(), bson.M{"user_id": userID.String()})
	if err != nil {
		http.Error(w, "Failed to retrieve sessions", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	currentSessionCookie, err := r.Cookie("session_id")
	var currentSessionID string
	if err == nil {
		currentSessionID = currentSessionCookie.Value
	}

	for cursor.Next(context.TODO()) {
		var session types.Session
		if err := cursor.Decode(&session); err != nil {
			http.Error(w, "Failed to decode session", http.StatusInternalServerError)
			return
		}

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
		http.Error(w, "Cursor error", http.StatusInternalServerError)
		return
	}

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

	json.NewEncoder(w).Encode(response)
}

func LogOutSession(w http.ResponseWriter, r *http.Request) {
	var logoutData struct {
		SessionID string `json:"sessionId"`
		UserID    string `json:"userId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&logoutData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userID, err := uuid.Parse(logoutData.UserID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	sessionID, err := uuid.Parse(logoutData.SessionID)
	if err != nil {
		http.Error(w, "Invalid session ID", http.StatusBadRequest)
		return
	}

	db := r.Context().Value("db").(*mongo.Client)
	sessionCollection := db.Database("SocialFlux").Collection("sessions")

	result, err := sessionCollection.DeleteOne(context.TODO(), bson.M{
		"session_id": sessionID.String(),
		"user_id":    userID.String(),
	})
	if err != nil {
		http.Error(w, "Failed to revoke session", http.StatusInternalServerError)
		return
	}

	if result.DeletedCount == 0 {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		MaxAge:   -1,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
		Path:     "/",
	})

	json.NewEncoder(w).Encode(map[string]string{"message": "Session revoked and user logged out successfully"})
}

func generateTemporaryPassword() (string, error) {
	b := make([]byte, 15) // Generate a 15-byte random password
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func ResetPassword(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*mongo.Client)
	userCollection := db.Database("SocialFlux").Collection("users")

	var resetData struct {
		Identifier string `json:"identifier"`
	}

	if err := json.NewDecoder(r.Body).Decode(&resetData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var user types.User
	err := userCollection.FindOne(context.TODO(), bson.M{
		"$or": []bson.M{
			{"username": resetData.Identifier},
			{"email": resetData.Identifier},
		},
	}).Decode(&user)

	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Generate a temporary password for the user
	tempPassword, err := generateTemporaryPassword()
	if err != nil {
		http.Error(w, "Failed to generate temporary password", http.StatusInternalServerError)
		return
	}

	// Hash the temporary password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash temporary password", http.StatusInternalServerError)
		return
	}

	// Update the user's password in the database
	_, err = userCollection.UpdateOne(
		context.TODO(),
		bson.M{"id": user.ID},
		bson.M{"$set": bson.M{
			"password":          string(hashedPassword),
			"password_reset_at": time.Now(),
		}},
	)
	if err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	// Send an email to the user with the temporary password
	err = sendPasswordResetEmail(user.Email, tempPassword)
	if err != nil {
		http.Error(w, "Failed to send password reset email", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Password reset email sent"})
}

func sendPasswordResetEmail(email, tempPassword string) error {
	apiKey := os.Getenv("RESEND_API_KEY")
	client := resend.NewClient(apiKey)

	// Construct the email body
	params := &resend.SendEmailRequest{
		From:    "Netsocial <noreply@netsocial.app>",
		To:      []string{email},
		Subject: "Password Reset for Your Netsocial Account",
		Html:    fmt.Sprintf("<p>Your temporary password is: <strong>%s</strong></p><p>Please log in and change your password immediately.</p>", tempPassword),
	}

	// Send the email using the Resend service
	_, err := client.Emails.Send(params)
	return err
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
	router.Post("/auth/reset-password", (middlewares.DiscordErrorReport(http.HandlerFunc(ResetPassword)).ServeHTTP))
}
