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
	// Get database connection
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

	// Decrypt modID
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
	var modUser types.User
	err = db.QueryRow("SELECT id, isowner, ismoderator, isdeveloper FROM users WHERE id = $1", modID).Scan(&modUser.ID, &modUser.IsOwner, &modUser.IsModerator, &modUser.IsDeveloper)
	if err != nil {
		http.Error(w, `{"error": "Moderator not found"}`, http.StatusInternalServerError)
		return
	}

	if !modUser.IsOwner && !modUser.IsModerator && !modUser.IsDeveloper {
		http.Error(w, `{"error": "Permission denied. Only owners, moderators, or developers can manage badges."}`, http.StatusForbidden)
		return
	}

	switch entity {
	case "user":
		var user types.User
		err := db.QueryRow("SELECT id FROM users WHERE username = $1", username).Scan(&user.ID)
		if err != nil {
			http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
			return
		}

		update := handleBadgeUpdateForUser(badge, action)
		if update == "" {
			http.Error(w, `{"error": "Invalid badge type"}`, http.StatusBadRequest)
			return
		}

		query := "UPDATE users SET " + update + " WHERE username = $1"
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
		coterieName := r.Header.Get("X-username")
		var coterie types.Coterie
		err := db.QueryRow("SELECT id FROM coterie WHERE name = $1", coterieName).Scan(&coterie.ID)
		if err != nil {
			http.Error(w, `{"error": "Coterie not found"}`, http.StatusNotFound)
			return
		}

		update := handleBadgeUpdateForCoterie(badge, action)
		if update == "" {
			http.Error(w, `{"error": "Invalid badge type"}`, http.StatusBadRequest)
			return
		}

		query := "UPDATE coterie SET " + update + " WHERE name = $1"
		_, err = db.Exec(query, coterieName)
		if err != nil {
			http.Error(w, `{"error": "Failed to update coterie badges"}`, http.StatusInternalServerError)
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

func handleBadgeUpdateForUser(badge string, action string) string {
	switch badge {
	case "dev":
		if action == "add" {
			return "isdeveloper = true"
		} else if action == "remove" {
			return "isdeveloper = false"
		}
	case "verified":
		if action == "add" {
			return "isverified = true"
		} else if action == "remove" {
			return "isverified = false"
		}
	case "partner":
		if action == "add" {
			return "ispartner = true"
		} else if action == "remove" {
			return "ispartner = false"
		}
	case "owner":
		if action == "add" {
			return "isowner = true"
		} else if action == "remove" {
			return "isowner = false"
		}
	case "moderator":
		if action == "add" {
			return "ismoderator = true"
		} else if action == "remove" {
			return "ismoderator = false"
		}
	}
	return ""
}

func handleBadgeUpdateForCoterie(badge string, action string) string {
	switch badge {
	case "organisation":
		if action == "add" {
			return "\"isOrganisation\" = true"
		} else if action == "remove" {
			return "\"isOrganisation\" = false"
		}
	case "verified":
		if action == "add" {
			return "\"isVerified\" = true"
		} else if action == "remove" {
			return "\"isVerified\" = false"
		}
	}
	return ""
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
