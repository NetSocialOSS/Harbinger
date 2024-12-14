package routes

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"netsocial/middlewares"
	"netsocial/types"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/resend/resend-go/v2"
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

		db, ok := r.Context().Value("db").(*sql.DB)
		if !ok {
			http.Error(w, "Database connection not found", http.StatusInternalServerError)
			return
		}

		var sessionExists bool
		err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM sessions WHERE user_id = $1 AND token = $2)", userID.String(), tokenCookie.Value).Scan(&sessionExists)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		if !sessionExists {
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
	db := r.Context().Value("db").(*sql.DB)

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

	// Check for existing user
	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1 OR email = $2)",
		signupData.Username, email).Scan(&exists)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if exists {
		http.Error(w, "Username or email already exists", http.StatusBadRequest)
		return
	}

	// Get the last user ID
	var lastUserID int
	err = db.QueryRow("SELECT COALESCE(MAX(userid), 0) FROM users").Scan(&lastUserID)
	if err != nil {
		http.Error(w, "Failed to get last user ID", http.StatusInternalServerError)
		return
	}

	// Begin transaction
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		http.Error(w, "Failed to start transaction", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// Insert new user
	userID := uuid.New().String()
	_, err = tx.Exec(`
		INSERT INTO users (
			id, userid, username, displayname, email, password, 
			profilepicture, createdat, links
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		userID, lastUserID+1, signupData.Username, signupData.Username, email,
		hashedPassword, "https://cdn.netsocial.app/logos/netsocial.png",
		time.Now(), pq.Array([]string{}),
	)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Send welcome email
	err = sendWelcomeEmail(email)
	if err != nil {
		http.Error(w, "Failed to send welcome email", http.StatusInternalServerError)
		return
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		http.Error(w, "Failed to commit transaction", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully"})
}

func UserLogin(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*sql.DB)

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

	query := `SELECT id, username, email, password FROM users WHERE username = $1 OR email = $1 LIMIT 1`
	err = db.QueryRow(query, decryptedIdentifier).Scan(&user.ID, &user.Username, &user.Email, &user.Password)
	if err == sql.ErrNoRows {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, fmt.Sprintf("Database query error: %v", err), http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(decryptedPassword))
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	userUUID, err := uuid.NewUUID()
	if err != nil {
		http.Error(w, "Failed to generate user UUID", http.StatusInternalServerError)
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

	insertSessionQuery := `INSERT INTO sessions (session_id, user_id, device, started_at, expires_at, token) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err = db.Exec(insertSessionQuery, sessionID, user.ID, device, time.Now(), expirationTime, token)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	json.NewEncoder(w).Encode(map[string]string{"message": "Logged in successfully"})
}

func UserLogout(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*sql.DB)

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

	result, err := db.Exec("DELETE FROM sessions WHERE session_id = $1 AND user_id = $2",
		logoutData.SessionID, userID)
	if err != nil {
		http.Error(w, "Failed to revoke session", http.StatusInternalServerError)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, "Failed to get rows affected", http.StatusInternalServerError)
		return
	}

	if rowsAffected == 0 {
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
	db := r.Context().Value("db").(*sql.DB)

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
	err = db.QueryRow("SELECT id, password FROM users WHERE id = $1", userId).Scan(&user.ID, &user.Password)
	if err == sql.ErrNoRows {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
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

	_, err = db.Exec("UPDATE users SET password = $1 WHERE id = $2", string(hashedNewPassword), user.ID)
	if err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Password changed successfully"})
}

func CurrentUser(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*sql.DB)
	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		http.Error(w, "Invalid user ID", http.StatusInternalServerError)
		return
	}

	var user types.User
	err := db.QueryRow(`
		SELECT id, username, displayname, bio, profilepicture, isorganisation,
			"isPrivateHearts", "isPrivate"
		FROM users WHERE id = $1
	`, userID.String()).Scan(
		&user.ID, &user.Username, &user.DisplayName, &user.Bio,
		&user.ProfilePicture, &user.IsOrganisation,
		&user.IsPrivateHearts, &user.IsPrivate,
	)
	if err != nil {
		http.Error(w, "Failed to find user", http.StatusInternalServerError)
		return
	}

	rows, err := db.Query(`
		SELECT session_id, device, started_at, expires_at
		FROM sessions WHERE user_id = $1
	`, userID.String())
	if err != nil {
		http.Error(w, "Failed to retrieve sessions", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	currentSessionCookie, err := r.Cookie("session_id")
	var currentSessionID string
	if err == nil {
		currentSessionID = currentSessionCookie.Value
	}

	var sessions []map[string]interface{}
	for rows.Next() {
		var session types.Session
		err := rows.Scan(&session.SessionID, &session.Device, &session.StartedAt, &session.ExpiresAt)
		if err != nil {
			http.Error(w, "Failed to scan session", http.StatusInternalServerError)
			return
		}

		sessions = append(sessions, map[string]interface{}{
			"session_id": session.SessionID,
			"device":     session.Device,
			"started_at": session.StartedAt,
			"expires_at": session.ExpiresAt,
			"current":    session.SessionID == currentSessionID,
		})
	}

	if err = rows.Err(); err != nil {
		http.Error(w, "Error iterating sessions", http.StatusInternalServerError)
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

	db := r.Context().Value("db").(*sql.DB)

	result, err := db.Exec(`
		DELETE FROM sessions 
		WHERE session_id = $1 AND user_id = $2
	`, sessionID.String(), userID.String())
	if err != nil {
		http.Error(w, "Failed to revoke session", http.StatusInternalServerError)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		http.Error(w, "Failed to get rows affected", http.StatusInternalServerError)
		return
	}

	if rowsAffected == 0 {
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
	db := r.Context().Value("db").(*sql.DB)

	var resetData struct {
		Identifier string `json:"identifier"`
	}

	if err := json.NewDecoder(r.Body).Decode(&resetData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var user types.User
	err := db.QueryRow(`
		SELECT id, email FROM users 
		WHERE username = $1 OR email = $1
	`, resetData.Identifier).Scan(&user.ID, &user.Email)
	if err == sql.ErrNoRows {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
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
	_, err = db.Exec(`
		UPDATE users 
		SET password = $1, password_reset_at = $2 
		WHERE id = $3
	`, string(hashedPassword), time.Now(), user.ID)
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

func Auth(router chi.Router) {
	router.Post("/auth/signup", (middlewares.DiscordErrorReport(http.HandlerFunc(UserSignup)).ServeHTTP))
	router.Post("/auth/login", (middlewares.DiscordErrorReport(http.HandlerFunc(UserLogin)).ServeHTTP))
	router.Post("/auth/logout", (middlewares.DiscordErrorReport(authMiddleware(http.HandlerFunc(UserLogout))).ServeHTTP))
	router.Post("/auth/change-password", (middlewares.DiscordErrorReport(authMiddleware(http.HandlerFunc(ChangePassword))).ServeHTTP))
	router.Delete("/auth/logout/session", (middlewares.DiscordErrorReport(authMiddleware(http.HandlerFunc(LogOutSession))).ServeHTTP))
	router.Get("/auth/@me", (middlewares.DiscordErrorReport(authMiddleware(http.HandlerFunc(CurrentUser))).ServeHTTP))
	router.Post("/auth/reset-password", (middlewares.DiscordErrorReport(http.HandlerFunc(ResetPassword)).ServeHTTP))
}
