package routes

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"netsocial/middlewares"
	"netsocial/types"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

func PostActions(w http.ResponseWriter, r *http.Request) {
	postId := r.Header.Get("X-postId")
	encryptedUserID := r.Header.Get("X-userID")
	action := r.URL.Query().Get("action")
	optionId := r.Header.Get("X-optionid")

	if action != "like" && action != "unlike" && action != "vote" {
		http.Error(w, `{"error": "Invalid action. Action must be 'like', 'unlike', or 'vote'."}`, http.StatusBadRequest)
		return
	}

	userID, err := middlewares.DecryptAES(encryptedUserID)
	if err != nil {
		http.Error(w, `{"error": "Failed to decrypt userid"}`, http.StatusBadRequest)
		return
	}

	if _, err := uuid.Parse(userID); err != nil {
		http.Error(w, `{"error": "Invalid user ID. Must be a valid UUID."}`, http.StatusBadRequest)
		return
	}

	db, ok := r.Context().Value("db").(*sql.DB)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	var user types.User
	err = db.QueryRowContext(r.Context(), `SELECT isbanned FROM users WHERE id = $1`, userID).Scan(
		&user.ID)

	if err != nil {
		http.Error(w, `{"error": "Failed to fetch user details"}`, http.StatusInternalServerError)
		return
	}

	if user.IsBanned {
		http.Error(w, `{"error": "You are banned from using NetSocial's services."}`, http.StatusForbidden)
		return
	}

	// Handle "like" and "unlike"
	if action == "like" || action == "unlike" {
		var query string
		if action == "like" {
			query = `UPDATE post SET hearts = hearts || array[$1] WHERE id = $2`
		} else {
			query = `UPDATE post SET hearts = array_remove(hearts, $1) WHERE id = $2`
		}

		_, err = db.ExecContext(r.Context(), query, userID, postId)
		if err != nil {
			http.Error(w, `{"error": "Failed to update post"}`, http.StatusInternalServerError)
			return
		}

		message := "Post liked successfully"
		if action == "unlike" {
			message = "Post unliked successfully"
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"message": message})
		return
	}

	// Handle "vote"
	if action == "vote" {
		if optionId == "" {
			http.Error(w, `{"error": "Option ID is required for voting"}`, http.StatusBadRequest)
			return
		}

		// Check if the poll exists in the post
		var pollJSON json.RawMessage
		err := db.QueryRowContext(r.Context(), `SELECT poll FROM post WHERE id = $1`, postId).Scan(&pollJSON)
		if err != nil {
			http.Error(w, `{"error": "Post not found"}`, http.StatusNotFound)
			return
		}

		// Check if the poll is expired or the user already voted
		var poll types.Poll
		err = json.Unmarshal(pollJSON, &poll)
		if err != nil || len(poll.Options) == 0 {
			http.Error(w, `{"error": "No poll found for this post"}`, http.StatusNotFound)
			return
		}

		// Check if poll is expired
		if poll.Expiration.Before(time.Now()) {
			http.Error(w, `{"error": "Poll has expired"}`, http.StatusForbidden)
			return
		}

		// Ensure user hasn't already voted
		var alreadyVoted bool
		err = db.QueryRowContext(r.Context(), `
			SELECT EXISTS (
					SELECT 1 FROM unnest(poll->'options'->0->'votes') AS votes WHERE votes = $1
			)`, userID).Scan(&alreadyVoted)

		if alreadyVoted {
			http.Error(w, `{"error": "You have already voted in this poll"}`, http.StatusForbidden)
			return
		}

		// Update vote in the poll
		_, err = db.ExecContext(r.Context(), `
			UPDATE post 
			SET poll = jsonb_set(
					poll, 
					'{options, 0, votes}', 
					(jsonb_array_append(poll->'options'->0->'votes', to_jsonb($1))) 
			)
			WHERE id = $2`, userID, postId)
		if err != nil {
			http.Error(w, `{"error": "Failed to cast vote"}`, http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{"message": "Vote cast successfully"})
	}
}
