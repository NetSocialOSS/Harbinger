package routes

import (
	"database/sql"
	"encoding/json"
	"log"
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
		&user.IsBanned)

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

func handleLikeUnlike(w http.ResponseWriter, r *http.Request, db *sql.DB, userID, postId, action string) {
	var query string
	if action == "like" {
		query = `UPDATE post SET hearts = hearts || array[$1] WHERE id = $2`
	} else {
		query = `UPDATE post SET hearts = array_remove(hearts, $1) WHERE id = $2`
	}

	_, err := db.ExecContext(r.Context(), query, userID, postId)
	if err != nil {
		http.Error(w, `{"error": "Failed to update post"}`, http.StatusInternalServerError)
		return
	}

	message := "Post liked successfully"
	if action == "unlike" {
		message = "Post unliked successfully"
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"message": message})
}

func handleVote(w http.ResponseWriter, r *http.Request, db *sql.DB, userID, postId, optionId string) {
	log.Println("Action: vote")

	if optionId == "" {
		log.Println("Error: Option ID is missing")
		http.Error(w, `{"error": "Option ID is required for voting"}`, http.StatusBadRequest)
		return
	}

	log.Printf("Option ID: %s, Post ID: %s, User ID: %s", optionId, postId, userID)

	// Fetch the poll JSON
	var pollJSON json.RawMessage
	err := db.QueryRowContext(r.Context(), `SELECT poll FROM post WHERE id = $1`, postId).Scan(&pollJSON)
	if err != nil {
		log.Printf("Error fetching poll for post ID %s: %v", postId, err)
		http.Error(w, `{"error": "Post not found"}`, http.StatusNotFound)
		return
	}

	log.Println("Fetched poll JSON:", string(pollJSON))

	var poll types.Poll
	err = json.Unmarshal(pollJSON, &poll)
	if err != nil || len(poll.Options) == 0 {
		log.Printf("Error unmarshalling poll JSON or no options found: %v", err)
		http.Error(w, `{"error": "No poll found for this post"}`, http.StatusNotFound)
		return
	}

	log.Printf("Poll expiration: %v, Current time: %v", poll.Expiration, time.Now())

	if poll.Expiration.Before(time.Now()) {
		log.Println("Error: Poll has expired")
		http.Error(w, `{"error": "Poll has expired"}`, http.StatusForbidden)
		return
	}

	// Check if user has already voted
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
	err = db.QueryRowContext(r.Context(), voteCheckQuery, optionId, userID, postId).Scan(&alreadyVoted)
	if err != nil {
		log.Printf("Error checking if user already voted: %v", err)
		http.Error(w, `{"error": "Failed to check vote status"}`, http.StatusInternalServerError)
		return
	}

	if alreadyVoted {
		log.Println("Error: User has already voted")
		http.Error(w, `{"error": "You have already voted in this poll"}`, http.StatusForbidden)
		return
	}

	log.Println("User has not voted yet. Proceeding to cast vote.")

	// Update the poll to add the vote
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

	_, err = db.ExecContext(r.Context(), voteUpdateQuery, userID, optionId, postId)
	if err != nil {
		log.Printf("Error casting vote: %v", err)
		http.Error(w, `{"error": "Failed to cast vote"}`, http.StatusInternalServerError)
		return
	}

	log.Println("Vote cast successfully")
	json.NewEncoder(w).Encode(map[string]interface{}{"message": "Vote cast successfully"})
}
