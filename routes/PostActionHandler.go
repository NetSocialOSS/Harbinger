package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"netsocial/database"
	"netsocial/middlewares"
	"netsocial/types"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
)

func PostActions(w http.ResponseWriter, r *http.Request) {
	postId := r.Header.Get("X-postId")
	action := r.URL.Query().Get("action")
	optionId := r.Header.Get("X-optionid")
	encryptedUserID := r.Header.Get("X-userID")

	if action != "like" && action != "unlike" && action != "vote" {
		http.Error(w, `{"error": "Invalid action. Action must be 'like', 'unlike', or 'vote'."}`, http.StatusBadRequest)
		return
	}

	userID, err := middlewares.DecryptAES(encryptedUserID)
	if err != nil {
		http.Error(w, "Failed to decrypt user ID", http.StatusBadRequest)
		return
	}

	db, ok := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	var user types.User
	err = db.QueryRow(context.Background(), `SELECT isbanned FROM users WHERE id = $1`, userID).Scan(&user.IsBanned)
	if err != nil {
		http.Error(w, `{"error": "Failed to fetch user details"}`, http.StatusInternalServerError)
		return
	}

	if user.IsBanned {
		http.Error(w, `{"error": "You are banned from using NetSocial's services."}`, http.StatusForbidden)
		return
	}

	if action == "like" || action == "unlike" {
		handleLikeUnlike(w, r, db, userID, postId, action)
		return
	}

	if action == "vote" {
		handleVote(w, r, db, userID, postId, optionId)
	}
}

func handleLikeUnlike(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool, userID, postId, action string) {
	var query string
	if action == "like" {
		query = "UPDATE post SET hearts = hearts || array[$1] WHERE id = $2"
	} else {
		query = "UPDATE post SET hearts = array_remove(hearts, $1) WHERE id = $2"
	}

	_, err := db.Exec(context.Background(), query, userID, postId)
	if err != nil {
		http.Error(w, `{"error": "Failed to update post"}`, http.StatusInternalServerError)
		return
	}

	if action == "like" {
		var likerDisplayName, authorId string
		if err = db.QueryRow(r.Context(), "SELECT displayname FROM users WHERE id = $1", userID).Scan(&likerDisplayName); err != nil {
			http.Error(w, "Error fetching display name", http.StatusInternalServerError)
			return
		}
		if err = db.QueryRow(r.Context(), "SELECT author FROM post WHERE id = $1", postId).Scan(&authorId); err != nil {
			http.Error(w, "Error fetching post author", http.StatusInternalServerError)
			return
		}

		// Skip notification if the user is liking their own post
		if userID != authorId {
			_, err = db.Exec(r.Context(),
				"INSERT INTO notifications (userid, type, content, link) VALUES ($1, $2, $3, $4)",
				authorId, "like", fmt.Sprintf("%s liked your post!", likerDisplayName), fmt.Sprintf("/post/%s", postId))
			if err != nil {
				http.Error(w, "Error creating like notification", http.StatusInternalServerError)
				println(err)
				return
			}
		}
	}

	message := "Post liked successfully"
	if action == "unlike" {
		message = "Post unliked successfully"
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"message": message})
}

func handleVote(w http.ResponseWriter, r *http.Request, db *pgxpool.Pool, userID, postId, optionId string) {
	if optionId == "" {
		http.Error(w, `{"error": "Option ID is required for voting"}`, http.StatusBadRequest)
		return
	}

	var pollJSON json.RawMessage
	err := db.QueryRow(context.Background(), `SELECT poll FROM post WHERE id = $1`, postId).Scan(&pollJSON)
	if err != nil {
		http.Error(w, `{"error": "Post not found"}`, http.StatusNotFound)
		return
	}

	var poll types.Poll
	err = json.Unmarshal(pollJSON, &poll)
	if err != nil || len(poll.Options) == 0 {
		http.Error(w, `{"error": "No poll found for this post"}`, http.StatusNotFound)
		return
	}

	if poll.Expiration.Before(time.Now()) {
		http.Error(w, `{"error": "Poll has expired"}`, http.StatusForbidden)
		return
	}

	var alreadyVoted bool
	voteCheckQuery := `
	WITH options AS (
		SELECT jsonb_array_elements(poll->'options') AS opt
		FROM post
		WHERE id = $3
	)
	SELECT EXISTS (
		SELECT 1
		FROM options
		WHERE opt->>'id' = $1
			AND $2 = ANY (SELECT jsonb_array_elements_text(opt->'votes'))
	)
`
	err = db.QueryRow(context.Background(), voteCheckQuery, optionId, userID, postId).Scan(&alreadyVoted)
	if err != nil {
		http.Error(w, `{"error": "Failed to check vote status"}`, http.StatusInternalServerError)
		return
	}

	if alreadyVoted {
		http.Error(w, `{"error": "You have already voted in this poll"}`, http.StatusForbidden)
		return
	}

	voteUpdateQuery := `
		WITH matched_option AS (
	SELECT idx - 1 AS idx
	FROM (
		SELECT elem, idx
		FROM jsonb_array_elements(COALESCE((SELECT poll FROM post WHERE id = $3)::jsonb->'options', '[]')) 
		WITH ORDINALITY AS t(elem, idx)
	) AS subquery
	WHERE elem->>'id' = $2
)
UPDATE post 
SET poll = jsonb_set(
	poll, 
	ARRAY['options', (matched_option.idx)::text, 'votes'],  -- Use an array for the path
	COALESCE(
		(poll->'options'->(matched_option.idx)::text->'votes') || to_jsonb($1::text), 
		to_jsonb(array[$1::text])
	), 
	true
)
FROM matched_option
WHERE post.id = $3;
`

	_, err = db.Exec(context.Background(), voteUpdateQuery, userID, optionId, postId)
	if err != nil {
		http.Error(w, `{"error": "Failed to cast vote"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"message": "Vote cast successfully"})
}
