package routes

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"netsocial/middlewares"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// CheckCoterieChatAllowed checks if chat is allowed in the specified coterie.
func CheckCoterieChatAllowed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		db, ok := r.Context().Value("db").(*sql.DB)
		if !ok {
			http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
			return
		}

		coterieName := r.URL.Query().Get("coterieName")
		if coterieName == "" {
			http.Error(w, `{"error": "Missing required field: coterieName"}`, http.StatusBadRequest)
			return
		}

		var isChatAllowed bool
		err := db.QueryRow("SELECT `isChatAllowed` FROM coterie WHERE name = $1", coterieName).Scan(&isChatAllowed)
		if err == sql.ErrNoRows {
			http.Error(w, `{"error": "Coterie not found"}`, http.StatusNotFound)
			return
		} else if err != nil {
			http.Error(w, `{"error": "Database error: `+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		if !isChatAllowed {
			http.Error(w, `{"error": "Chatting is disabled for this coterie."}`, http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// PostMessage allows a user to post a message in a coterie.
func PostMessage(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*sql.DB)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	coterieName := r.URL.Query().Get("coterieName")
	userIDStr := r.URL.Query().Get("userID")
	content := r.URL.Query().Get("content")

	if coterieName == "" || userIDStr == "" || content == "" {
		http.Error(w, `{"error": "Missing required fields: coterieName, userID, and content are required"}`, http.StatusBadRequest)
		return
	}

	userIDD, err := middlewares.DecryptAES(userIDStr)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	userID, err := uuid.Parse(userIDD)
	if err != nil {
		http.Error(w, `{"error": "Invalid user ID format"}`, http.StatusBadRequest)
		return
	}

	var memberExists bool
	err = db.QueryRow("SELECT EXISTS (SELECT 1 FROM coterie WHERE name = $1 AND $2 = ANY(members))", coterieName, userID.String()).Scan(&memberExists)
	if err != nil {
		http.Error(w, `{"error": "Database error: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	if !memberExists {
		http.Error(w, `{"error": "You are not a member of this coterie"}`, http.StatusForbidden)
		return
	}

	encryptedContent, err := middlewares.EncryptAES(content)
	if err != nil {
		http.Error(w, `{"error": "Failed to encrypt message: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	_, err = db.Exec(
		"INSERT INTO messages (id, coterie, user_id, content, created_at) VALUES ($1, $2, $3, $4, $5)",
		uuid.New().String(), coterieName, userID.String(), encryptedContent, time.Now(),
	)
	if err != nil {
		http.Error(w, `{"error": "Failed to post message: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Message posted successfully"}`))
}

// FetchMessages retrieves messages for a specific coterie.
func FetchMessages(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*sql.DB)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	coterieName := r.URL.Query().Get("coterieName")
	userIDStr := r.URL.Query().Get("userID")

	if coterieName == "" || userIDStr == "" {
		http.Error(w, `{"error": "Missing required fields: coterieName and userID are required"}`, http.StatusBadRequest)
		return
	}

	userIDD, err := middlewares.DecryptAES(userIDStr)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	userID, err := uuid.Parse(userIDD)
	if err != nil {
		http.Error(w, `{"error": "Invalid user ID format"}`, http.StatusBadRequest)
		return
	}

	var memberExists bool
	err = db.QueryRow("SELECT EXISTS (SELECT 1 FROM coterie WHERE name = $1 AND $2 = ANY(members))", coterieName, userID.String()).Scan(&memberExists)
	if err != nil {
		http.Error(w, `{"error": "Database error: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	if !memberExists {
		http.Error(w, `{"error": "You are not a member of this coterie"}`, http.StatusForbidden)
		return
	}

	rows, err := db.Query("SELECT content, created_at, user_id FROM messages WHERE coterie = $1 ORDER BY created_at DESC", coterieName)
	if err != nil {
		http.Error(w, `{"error": "Failed to fetch messages: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var messages []map[string]interface{}
	for rows.Next() {
		var content, userID string
		var createdAt time.Time

		if err := rows.Scan(&content, &createdAt, &userID); err != nil {
			http.Error(w, `{"error": "Error reading message data: `+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		decryptedContent, err := middlewares.DecryptAES(content)
		if err != nil {
			http.Error(w, `{"error": "Error decrypting message content: `+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		var username, profilePicture string
		if err := db.QueryRow("SELECT username, profilepicture FROM users WHERE id = $1", userID).Scan(&username, &profilePicture); err != nil {
			http.Error(w, `{"error": "Error fetching user data: `+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		messages = append(messages, map[string]interface{}{
			"content":   decryptedContent,
			"createdAt": createdAt,
			"author": map[string]interface{}{
				"username":       username,
				"profilePicture": profilePicture,
			},
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(messages); err != nil {
		http.Error(w, `{"error": "Failed to encode messages: `+err.Error()+`"}`, http.StatusInternalServerError)
	}
}

func HavokRoutes(r *chi.Mux) {
	r.With(CheckCoterieChatAllowed).Post("/new/message", middlewares.DiscordErrorReport(http.HandlerFunc(PostMessage)).ServeHTTP)
	r.With(CheckCoterieChatAllowed).Get("/messages/@all", middlewares.DiscordErrorReport(http.HandlerFunc(FetchMessages)).ServeHTTP)
}
