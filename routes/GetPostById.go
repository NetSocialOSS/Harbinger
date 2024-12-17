package routes

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"netsocial/types"

	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/lib/pq"
)

// Function to handle fetching a single post by ID from PostgreSQL
func GetPostById(w http.ResponseWriter, r *http.Request) {
	postID := chi.URLParam(r, "id")

	db, ok := r.Context().Value("db").(*sql.DB)
	if !ok {
		http.Error(w, "Database connection not available", http.StatusInternalServerError)
		return
	}

	var scheduledFor sql.NullTime
	var image pq.StringArray
	var coterie sql.NullString
	var hearts pq.StringArray
	var comments sql.NullString
	var poll sql.NullString

	var post types.Post
	query := `
			SELECT id, author, title, content, coterie, scheduledFor, image, poll, createdAt, hearts, comments
			FROM Post WHERE id = $1`
	err := db.QueryRow(query, postID).Scan(
		&post.ID, &post.Author, &post.Title, &post.Content, &coterie, &scheduledFor, &image,
		&poll, &post.CreatedAt, &hearts, &comments)

	if comments.Valid && comments.String != "" {
		var commentList []types.Comment

		// Try to unmarshal the comments field into a slice of Comment
		if err := json.Unmarshal([]byte(comments.String), &commentList); err != nil {
			// If unmarshalling into a slice fails, try unmarshalling into a single Comment object
			var singleComment types.Comment
			if err := json.Unmarshal([]byte(comments.String), &singleComment); err != nil {
				// Log the issue and default to an empty list without crashing
				post.Comments = []types.Comment{}
			} else {
				commentList = append(commentList, singleComment)
			}
		}

		post.Comments = commentList
	} else {
		// Default to an empty comments list if the data is NULL or empty
		post.Comments = []types.Comment{}
	}

	// Handle error if the query fails
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Post not found", http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf("Failed to fetch post: %v", err), http.StatusInternalServerError)
		return
	}

	// Assign the scheduledFor time if it's not NULL
	if scheduledFor.Valid {
		post.ScheduledFor = scheduledFor.Time
	} else {
		post.ScheduledFor = time.Time{}
	}

	// Handle the nullable coterie field
	if coterie.Valid {
		post.Coterie = coterie.String
	} else {
		post.Coterie = ""
	}

	// Handle the nullable image field (TEXT[])
	if image != nil {
		post.Image = image
	} else {
		post.Image = []string{}
	}

	// Handle the nullable hearts field (TEXT[])
	if hearts != nil {
		post.Hearts = hearts
	} else {
		post.Hearts = []string{}
	}

	// Handle the poll
	if poll.Valid {
		var decodedPoll []types.Poll
		err := json.Unmarshal([]byte(poll.String), &decodedPoll)

		// If unmarshalling into a slice fails, try unmarshalling into a single Poll object
		if err != nil {
			var singlePoll types.Poll
			if err := json.Unmarshal([]byte(poll.String), &singlePoll); err != nil {
				http.Error(w, fmt.Sprintf("Failed to decode poll: %v", err), http.StatusInternalServerError)
				return
			}
			// Convert single poll to a slice
			decodedPoll = append(decodedPoll, singlePoll)
		}

		post.Poll = decodedPoll
	}

	// Fetch author details
	var author types.Author
	query = `SELECT username, isVerified, isOrganisation, profileBanner, profilePicture, isDeveloper, isPartner, isOwner, isModerator, createdAt
						FROM users WHERE id = $1`
	err = db.QueryRow(query, post.Author).Scan(
		&author.Username, &author.IsVerified, &author.IsOrganisation, &author.ProfileBanner, &author.ProfilePicture,
		&author.IsDeveloper, &author.IsPartner, &author.IsOwner, &author.IsModerator, &author.CreatedAt)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch author details: %v", err), http.StatusInternalServerError)
		return
	}

	// Fetch comments with authors
	var commentsWithAuthor []types.Comment
	for _, comment := range post.Comments {
		var commentAuthor types.Author
		query := `SELECT username, isVerified, isOrganisation, profilePicture, isOwner, isModerator, isDeveloper
						FROM users WHERE id = $1`
		err = db.QueryRow(query, comment.Author).Scan(
			&commentAuthor.Username, &commentAuthor.IsVerified, &commentAuthor.IsOrganisation, &commentAuthor.ProfilePicture,
			&commentAuthor.IsOwner, &commentAuthor.IsModerator, &commentAuthor.IsDeveloper)

		// Handle if no rows were returned (author doesn't exist)
		if err == sql.ErrNoRows {
			commentAuthor.Username = "Unknown"
			commentAuthor.IsVerified = false
			commentAuthor.IsOrganisation = false
			commentAuthor.ProfilePicture = nil
			commentAuthor.IsOwner = false
			commentAuthor.IsModerator = false
			commentAuthor.IsDeveloper = false
		} else if err != nil {
			http.Error(w, fmt.Sprintf("Failed to fetch author details for comment: %v", err), http.StatusInternalServerError)
			return
		}

		commentData := types.Comment{
			ID:             comment.ID,
			Content:        comment.Content,
			IsVerified:     commentAuthor.IsVerified,
			IsOrganisation: commentAuthor.IsOrganisation,
			IsPartner:      commentAuthor.IsPartner,
			TimeAgo:        calculateTimeAgo(comment.CreatedAt),
			AuthorName:     commentAuthor.Username,
			IsOwner:        commentAuthor.IsOwner,
			IsModerator:    commentAuthor.IsModerator,
			ProfilePicture: func() string {
				if commentAuthor.ProfilePicture != nil {
					return *commentAuthor.ProfilePicture
				}
				return ""
			}(),
			IsDeveloper: commentAuthor.IsDeveloper,
			Replies:     comment.Replies,
			CreatedAt:   comment.CreatedAt,
		}
		commentsWithAuthor = append(commentsWithAuthor, commentData)
	}

	// Sort comments by CreatedAt in descending order (most recent first)
	sort.Slice(commentsWithAuthor, func(i, j int) bool {
		return commentsWithAuthor[i].CreatedAt.After(commentsWithAuthor[j].CreatedAt)
	})

	// Update hearts with author usernames
	var heartsWithUsernames []string
	for _, heartID := range post.Hearts {
		var heartAuthor types.Author
		if err := db.QueryRow(`SELECT username FROM users WHERE id = $1`, heartID).Scan(&heartAuthor.Username); err != nil {
			heartsWithUsernames = append(heartsWithUsernames, "Unknown")
			continue
		}
		heartsWithUsernames = append(heartsWithUsernames, heartAuthor.Username)
	}

	// Calculate total votes for polls if applicable
	if post.Poll != nil {
		totalVotes := 0
		for i := range post.Poll {
			for j := range post.Poll[i].Options {
				// Calculate the vote count from the Votes field
				optionVoteCount := len(post.Poll[i].Options[j].Votes)
				totalVotes += optionVoteCount

				// Set the VoteCount for the option
				post.Poll[i].Options[j].VoteCount = optionVoteCount
			}
		}
		// Set total votes for the poll
		if len(post.Poll) > 0 {
			post.Poll[0].TotalVotes = totalVotes
		}
	}

	// Construct the response data
	responseData := map[string]interface{}{
		"_id":     post.ID,
		"title":   post.Title,
		"content": post.Content,
		"author": map[string]interface{}{
			"username":       author.Username,
			"isVerified":     author.IsVerified,
			"isOrganisation": author.IsOrganisation,
			"profileBanner":  author.ProfileBanner,
			"profilePicture": author.ProfilePicture,
			"isDeveloper":    author.IsDeveloper,
			"isPartner":      author.IsPartner,
			"isOwner":        author.IsOwner,
			"isModerator":    author.IsModerator,
			"createdAt":      author.CreatedAt,
		},
		"createdAt": post.CreatedAt,
		"poll":      post.Poll,
		"hearts":    heartsWithUsernames,
		"comments":  commentsWithAuthor,
	}

	// Add image field if it is not empty
	if len(post.Image) > 0 {
		responseData["image"] = post.Image
	}

	// Respond with JSON
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(responseData); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response: %v", err), http.StatusInternalServerError)
		return
	}
}
