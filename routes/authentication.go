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
	"netsocial/database"
	"netsocial/middlewares"
	"netsocial/types"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var configuration types.Config

var jwtSecret = configuration.JwtSecret

func generateJWT(userID uuid.UUID) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID.String(),
		"exp":     time.Now().Add(time.Hour * 7628).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCookie, err := r.Cookie("token")
		if err != nil || tokenCookie.Value == "" {
			http.Error(w, "Token missing", http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(tokenCookie.Value, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok || token.Method != jwt.SigningMethodHS256 {
				return nil, errors.New("invalid signing method")
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

		exp, ok := claims["exp"].(float64)
		if !ok || time.Now().Unix() > int64(exp) {
			http.Error(w, "Token expired", http.StatusUnauthorized)
			return
		}

		userID, err := uuid.Parse(claims["user_id"].(string))
		if err != nil {
			http.Error(w, "Invalid user ID in token", http.StatusUnauthorized)
			return
		}

		conn := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
		var exists bool
		query := "select exists(select 1 from sessions where userid = $1 and token = $2)"
		err = conn.QueryRow(r.Context(), query, userID.String(), tokenCookie.Value).Scan(&exists)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		if !exists {
			http.Error(w, "Session expired", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "user_id", userID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
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
	emailData := middlewares.EmailData{
		From:    "Netsocial <welcome@netsocial.app>",
		To:      email,
		Subject: "Welcome to Netsocial!",
		Text:    "Hey, welcome to Netsocial! Let's start by making your first post. [Post Now!](https://netsocial.app/post/new)",
	}
	return middlewares.SendEmail(emailData)
}

func UserSignup(w http.ResponseWriter, r *http.Request) {
	pool := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)

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
	err = pool.QueryRow(r.Context(), "select exists(select 1 from users where username = $1 or email = $2)", signupData.Username, email).Scan(&exists)
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
	err = pool.QueryRow(r.Context(), "select coalesce(max(userid::int), 0) from users;").Scan(&lastUserID)
	if err != nil {
		http.Error(w, "Failed to get last user ID", http.StatusInternalServerError)
		return
	}

	// Begin transaction
	tx, err := pool.BeginTx(r.Context(), pgx.TxOptions{})
	if err != nil {
		http.Error(w, "Failed to start transaction", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(r.Context())

	// Insert new user
	_, err = tx.Exec(r.Context(), `
		insert into users (
			 userid, username, displayname, email, password,
			profilepicture, createdat
		) values ($1::int, $2, $3, $4, $5, $6, $7)`,
		lastUserID+1, signupData.Username, signupData.Username, email,
		hashedPassword, "https://cdn.netsocial.app/logos/netsocial.png",
		time.Now(),
	)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Commit transaction
	if err = tx.Commit(r.Context()); err != nil {
		http.Error(w, "Failed to commit transaction", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully"})
}

func UserLogin(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)

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

	query := `select id, username, email, password from users where username = $1 or email = $1`
	err = db.QueryRow(r.Context(), query, decryptedIdentifier).Scan(&user.ID, &user.Username, &user.Email, &user.Password)
	if errors.Is(err, pgx.ErrNoRows) {
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

	device := r.UserAgent()
	sessionID := uuid.New()

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

	insertSessionQuery := `insert into sessions (sessionid, userid, device, expiresat, token, type) values ($1, $2, $3, $4, $5, $6)`
	_, err = db.Exec(r.Context(), insertSessionQuery, sessionID, user.ID, device, expirationTime, token, "harbinger-generated")
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		errorMessage := fmt.Sprintf("Failed to create session: %v", err)
		log.Println(errorMessage)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID.String(),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	})

	json.NewEncoder(w).Encode(map[string]string{"message": "Logged in successfully"})
}

func UserLogout(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)

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

	userUUID, err := uuid.Parse(userID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	result, err := db.Exec(r.Context(), "delete from sessions where sessionid = $1 and userid = $2",
		logoutData.SessionID, userUUID)
	if err != nil {
		http.Error(w, "Failed to revoke session", http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
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
	db := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)

	var passwordData struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&passwordData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		http.Error(w, "Invalid or missing user ID", http.StatusInternalServerError)
		return
	}

	var user types.User
	err := db.QueryRow(r.Context(), "select id, password from users where id = $1", userID).Scan(&user.ID, &user.Password)
	if errors.Is(err, pgx.ErrNoRows) {
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

	_, err = db.Exec(r.Context(), "update users set password = $1 where id = $2", string(hashedNewPassword), user.ID)
	if err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec(r.Context(), "delete from sessions where userid = $1", user.ID)
	if err != nil {
		log.Printf("Failed to clear sessions: %v", err)
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Password changed successfully"})
}

func CurrentUser(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
	if !ok || db == nil {
		http.Error(w, "Database connection not found", http.StatusInternalServerError)
		return
	}

	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		http.Error(w, "Invalid or missing user ID", http.StatusInternalServerError)
		return
	}

	var user types.User
	err := db.QueryRow(r.Context(), `
		select id, username, displayname, bio, profilepicture, isorganisation,
		       isprivatehearts, isprivate, links
		from users where id = $1
	`, userID).Scan(
		&user.ID, &user.Username, &user.DisplayName, &user.Bio,
		&user.ProfilePicture, &user.IsOrganisation,
		&user.IsPrivateHearts, &user.IsPrivate, &user.Links,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	} else if err != nil {
		log.Println(err)

		http.Error(w, "Failed to retrieve user information", http.StatusInternalServerError)
		return
	}

	rows, err := db.Query(r.Context(), `
		select sessionid, device, startedat, expiresat, type
		from sessions where userid = $1
	`, userID)
	if err != nil {
		http.Error(w, "Failed to retrieve user sessions", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	currentSessionID := ""
	if currentSessionCookie, err := r.Cookie("session_id"); err == nil {
		currentSessionID = currentSessionCookie.Value
	}

	var sessions []map[string]interface{}
	for rows.Next() {
		var session types.Session
		if err := rows.Scan(&session.SessionID, &session.Device, &session.StartedAt, &session.ExpiresAt, &session.Type); err != nil {
			http.Error(w, "Failed to parse session data", http.StatusInternalServerError)
			return
		}

		sessions = append(sessions, map[string]interface{}{
			"session_id": session.SessionID,
			"device":     session.Device,
			"started_at": session.StartedAt,
			"expires_at": session.ExpiresAt,
			"current":    session.SessionID.String() == currentSessionID,
		})
	}
	if err = rows.Err(); err != nil {
		http.Error(w, "Error iterating session rows", http.StatusInternalServerError)
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

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

func LogOutSession(w http.ResponseWriter, r *http.Request) {
	var logoutData struct {
		SessionID string `json:"sessionId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&logoutData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userID, ok := r.Context().Value("user_id").(uuid.UUID)
	if !ok {
		http.Error(w, "Invalid or missing user ID", http.StatusInternalServerError)
		return
	}

	sessionID, err := uuid.Parse(logoutData.SessionID)
	if err != nil {
		http.Error(w, "Invalid session ID", http.StatusBadRequest)
		return
	}

	db, ok := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
	if !ok {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	result, err := db.Exec(r.Context(), `
		delete from sessions
		where sessionid = $1 and userid = $2
	`, sessionID, userID)
	if err != nil {
		http.Error(w, "Failed to revoke session", http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
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
	response := map[string]string{"message": "Session revoked and user logged out successfully"}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to send response", http.StatusInternalServerError)
	}
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
	db := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)

	var resetData struct {
		Identifier string `json:"identifier"`
	}

	if err := json.NewDecoder(r.Body).Decode(&resetData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var user types.User
	err := db.QueryRow(r.Context(), `
		select id, email from users
		where username = $1 or email = $1
	`, resetData.Identifier).Scan(&user.ID, &user.Email)

	// Always return success to prevent user enumeration
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			json.NewEncoder(w).Encode(map[string]string{"message": "If the account exists, a password reset email has been sent"})
			return
		}
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Generate temporary password and update only if user exists
	tempPassword, err := generateTemporaryPassword()
	if err != nil {
		http.Error(w, "Failed to generate temporary password", http.StatusInternalServerError)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash temporary password", http.StatusInternalServerError)
		return
	}

	// Set temporary password expiry to 15 minutes from now
	tempPasswordExpiry := time.Now().Add(15 * time.Minute)
	_, err = db.Exec(r.Context(), `
		update users
		set password = $1, temp_password_expiry = $2
		where id = $3
	`, string(hashedPassword), tempPasswordExpiry, user.ID)
	if err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	// Send email only if user exists
	err = sendPasswordResetEmail(user.Email, tempPassword)
	if err != nil {
		log.Printf("Failed to send password reset email to %s: %v", user.Email, err)
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "If the account exists, a password reset email has been sent"})
}

func sendPasswordResetEmail(email, tempPassword string) error {

	// Construct the email body
	emailData := middlewares.EmailData{
		From:    "Netsocial <noreply@netsocial.app>",
		To:      email,
		Subject: "Password Reset for Your Netsocial Account",
		Html:    fmt.Sprintf("<p>Your temporary password is: <strong>%s</strong></p><p>Please log in and change your password immediately. Do note this will expire in 15mins</p>", tempPassword),
	}

	return middlewares.SendEmail(emailData)
}

func Auth(r chi.Router) {
	r.With(RateLimit(5, 5*time.Minute)).Post("/auth/logout", authMiddleware(http.HandlerFunc(UserLogout)).(http.HandlerFunc))
	r.With(RateLimit(5, 5*time.Minute)).Post("/auth/change-password", authMiddleware(http.HandlerFunc(ChangePassword)).(http.HandlerFunc))
	r.Delete("/auth/logout/session", authMiddleware(http.HandlerFunc(LogOutSession)).(http.HandlerFunc))
	r.Get("/auth/@me", authMiddleware(http.HandlerFunc(CurrentUser)).(http.HandlerFunc))
	r.With(RateLimit(5, 5*time.Minute)).Post("/auth/signup", UserSignup)
	r.With(RateLimit(5, 5*time.Minute)).Post("/auth/login", UserLogin)
	r.With(RateLimit(5, 5*time.Minute)).Post("/auth/reset-password", ResetPassword)
}
