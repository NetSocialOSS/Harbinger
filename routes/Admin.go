package routes

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"netsocial/middlewares"
	"netsocial/types"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func ManageBadge(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*sql.DB)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	username := r.Header.Get("X-username")
	action := r.Header.Get("X-action")
	badge := r.Header.Get("X-badge")
	encryptedid := r.Header.Get("X-modid")
	entity := r.Header.Get("X-entity")

	modID, err := middlewares.DecryptAES(encryptedid)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	// Validate modID
	_, err = uuid.Parse(modID)
	if err != nil {
		http.Error(w, `{"error": "Invalid modID"}`, http.StatusBadRequest)
		return
	}

	// Check if the mod is an owner or moderator
	var isOwner, isModerator, isDeveloper bool
	err = db.QueryRow("SELECT isowner, ismoderator, isdeveloper FROM users WHERE id = $1", modID).Scan(&isOwner, &isModerator, &isDeveloper)
	if err != nil {
		http.Error(w, `{"error": "Moderator not found"}`, http.StatusInternalServerError)
		return
	}

	// Check if the mod has permission to manage
	if !isOwner && !isModerator && !isDeveloper {
		http.Error(w, `{"error": "Permission denied. Only owners, moderators, or developers can manage badges."}`, http.StatusForbidden)
		return
	}

	// Handle entity based on X-entity header
	switch entity {
	case "user":
		// Manage badge for user
		var user types.User
		err := db.QueryRow("SELECT * FROM users WHERE username = $1", username).Scan(
			&user.Username,
		)
		if err != nil {
			http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
			return
		}

		// Update the user's badge based on action
		var query string
		switch action {
		case "add":
			query = fmt.Sprintf("UPDATE users SET %s = true WHERE username = $1", getBadgeColumn(badge))
		case "remove":
			query = fmt.Sprintf("UPDATE users SET %s = false WHERE username = $1", getBadgeColumn(badge))
		default:
			http.Error(w, `{"error": "Invalid action"}`, http.StatusBadRequest)
			return
		}

		_, err = db.Exec(query, username)
		if err != nil {
			http.Error(w, `{"error": "Failed to update user badges"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": fmt.Sprintf("Badge %s successfully %sed for user %s", badge, action, username),
		})

	case "coterie":
		// Manage badge for coterie
		// Note: As the coterie table structure wasn't provided, this part remains conceptual
		coterieName := r.Header.Get("X-username")
		var query string
		switch action {
		case "add":
			query = "UPDATE coterie SET isorganisation = true WHERE name = $1"
		case "remove":
			query = "UPDATE coterie SET isorganisation = false WHERE name = $1"
		default:
			http.Error(w, `{"error": "Invalid action"}`, http.StatusBadRequest)
			return
		}

		result, err := db.Exec(query, coterieName)
		if err != nil {
			http.Error(w, `{"error": "Failed to update coterie badges"}`, http.StatusInternalServerError)
			return
		}

		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			http.Error(w, `{"error": "Coterie not found"}`, http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": fmt.Sprintf("Badge %s successfully %sed for coterie %s", badge, action, coterieName),
		})

	default:
		http.Error(w, `{"error": "Invalid entity type"}`, http.StatusBadRequest)
	}
}

func getBadgeColumn(badge string) string {
	switch badge {
	case "dev":
		return "isdeveloper"
	case "verified":
		return "isverified"
	case "partner":
		return "ispartner"
	case "owner":
		return "isowner"
	case "moderator":
		return "ismoderator"
	default:
		return ""
	}
}

func DeletePostAdmin(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*sql.DB)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	postID := r.Header.Get("X-postId")
	encryptedid := r.Header.Get("X-modid")

	modID, err := middlewares.DecryptAES(encryptedid)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	// Validate modID
	_, err = uuid.Parse(modID)
	if err != nil {
		http.Error(w, `{"error": "Invalid modID"}`, http.StatusBadRequest)
		return
	}

	// Check if the mod is an owner or moderator
	var isOwner, isModerator bool
	err = db.QueryRow("SELECT isowner, ismoderator FROM users WHERE id = $1", modID).Scan(&isOwner, &isModerator)
	if err != nil {
		http.Error(w, `{"error": "Moderator not found"}`, http.StatusInternalServerError)
		return
	}

	// Check if the user has permission
	if !isOwner && !isModerator {
		http.Error(w, `{"error": "Permission denied. Only owners and moderators can delete posts."}`, http.StatusForbidden)
		return
	}

	// Delete the post from the database
	result, err := db.Exec("DELETE FROM post WHERE id = $1", postID)
	if err != nil {
		http.Error(w, `{"error": "Failed to delete post"}`, http.StatusInternalServerError)
		return
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, `{"error": "Post not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Post with ID %s successfully deleted", postID),
	})
}

func DeleteCoterieAdmin(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*sql.DB)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	coterieName := r.Header.Get("X-name")
	encryptedid := r.Header.Get("X-modid")

	modID, err := middlewares.DecryptAES(encryptedid)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	// Validate modID
	_, err = uuid.Parse(modID)
	if err != nil {
		http.Error(w, `{"error": "Invalid modID"}`, http.StatusBadRequest)
		return
	}

	// Check if the mod is an owner or moderator
	var isOwner, isModerator bool
	err = db.QueryRow("SELECT isowner, ismoderator FROM users WHERE id = $1", modID).Scan(&isOwner, &isModerator)
	if err != nil {
		http.Error(w, `{"error": "Moderator not found"}`, http.StatusInternalServerError)
		return
	}

	// Check if the user has permission
	if !isOwner && !isModerator {
		http.Error(w, `{"error": "Permission denied. Only owners and moderators can delete coteries."}`, http.StatusForbidden)
		return
	}

	// Delete the coterie from the database
	// Note: As the coterie table structure wasn't provided, this part remains conceptual
	result, err := db.Exec("DELETE FROM coterie WHERE name = $1", coterieName)
	if err != nil {
		http.Error(w, `{"error": "Failed to delete coterie"}`, http.StatusInternalServerError)
		return
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, `{"error": "Coterie not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Coterie with name %s successfully deleted", coterieName),
	})
}

func ManageUser(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value("db").(*sql.DB)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	username := r.Header.Get("X-username")
	action := r.Header.Get("X-action")
	encryptedid := r.Header.Get("X-modid")

	modID, err := middlewares.DecryptAES(encryptedid)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	// Validate modID
	_, err = uuid.Parse(modID)
	if err != nil {
		http.Error(w, `{"error": "Invalid modID"}`, http.StatusBadRequest)
		return
	}

	// Check if the mod is an owner or moderator
	var isOwner, isModerator bool
	err = db.QueryRow("SELECT isowner, ismoderator FROM users WHERE id = $1", modID).Scan(&isOwner, &isModerator)
	if err != nil {
		http.Error(w, `{"error": "Moderator not found"}`, http.StatusInternalServerError)
		return
	}

	// Check if the user has permission
	if !isOwner && !isModerator {
		http.Error(w, `{"error": "Permission denied. Only owners and moderators can manage users."}`, http.StatusForbidden)
		return
	}

	// Update the user's ban status based on action
	var query string
	switch action {
	case "ban":
		query = "UPDATE users SET isbanned = true WHERE username = $1"
	case "unban":
		query = "UPDATE users SET isbanned = false WHERE username = $1"
	default:
		http.Error(w, `{"error": "Invalid action"}`, http.StatusBadRequest)
		return
	}

	result, err := db.Exec(query, username)
	if err != nil {
		http.Error(w, `{"error": "Failed to update user status"}`, http.StatusInternalServerError)
		return
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("User %s successfully %sed", username, action),
	})
}

func Admin(r chi.Router) {
	r.With(RateLimit(5, 10*time.Minute)).Post("/admin/manage/badge", (middlewares.DiscordErrorReport(http.HandlerFunc(ManageBadge)).ServeHTTP))
	r.With(RateLimit(5, 10*time.Minute)).Post("/admin/manage/user", (middlewares.DiscordErrorReport(http.HandlerFunc(ManageUser)).ServeHTTP))
	r.With(RateLimit(5, 10*time.Minute)).Delete("/admin/manage/post", (middlewares.DiscordErrorReport(http.HandlerFunc(DeletePostAdmin)).ServeHTTP))
	r.With(RateLimit(5, 10*time.Minute)).Delete("/admin/manage/coterie", (middlewares.DiscordErrorReport(http.HandlerFunc(DeleteCoterieAdmin)).ServeHTTP))
}
