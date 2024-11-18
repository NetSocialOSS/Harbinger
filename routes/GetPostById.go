package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"netsocial/types"

	"net/http"

	"github.com/go-chi/chi/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Function to handle fetching a single post by ID
func GetPostById(w http.ResponseWriter, r *http.Request) {
	// Get the post ID from the URL parameter
	postID := chi.URLParam(r, "id")

	// Access MongoDB client from context
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, "Database connection not available", http.StatusInternalServerError)
		return
	}

	// Access MongoDB collection for posts
	postsCollection := db.Database("SocialFlux").Collection("posts")

	// Define options to customize the query
	opts := options.FindOne().SetProjection(bson.M{
		"title":     1,
		"content":   1,
		"author":    1,
		"createdAt": 1,
		"poll":      1,
		"hearts":    1,
		"image":     1, // Updated field to "image"
		"comments":  1, // Fetch all comments
	})

	// Find the post by its ID
	var post types.Post

	if err := postsCollection.FindOne(context.Background(), bson.M{"_id": postID}, opts).Decode(&post); err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Post not found", http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf("Failed to fetch post: %v", err), http.StatusInternalServerError)
		return
	}

	// Fetch author details from the users collection
	usersCollection := db.Database("SocialFlux").Collection("users")
	var author types.Author
	if err := usersCollection.FindOne(context.Background(), bson.M{"id": post.Author}).Decode(&author); err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch author details: %v", err), http.StatusInternalServerError)
		return
	}

	// Fetch comments with limited author details
	var comments []types.Comment
	for _, comment := range post.Comments {
		var commentAuthor types.Author
		if err := usersCollection.FindOne(context.Background(), bson.M{"id": comment.Author}).Decode(&commentAuthor); err != nil {
			http.Error(w, fmt.Sprintf("Failed to fetch author details for comment: %v", err), http.StatusInternalServerError)
			return
		}

		// Construct each comment with author's details
		commentData := types.Comment{
			ID:             comment.ID,
			Content:        comment.Content,
			IsVerified:     commentAuthor.IsVerified,
			IsOrganisation: commentAuthor.IsOrganisation,
			IsPartner:      commentAuthor.IsPartner,
			TimeAgo:        TimeAgo(comment.CreatedAt),
			AuthorName:     commentAuthor.Username,
			IsOwner:        commentAuthor.IsOwner,
			IsModerator:    commentAuthor.IsModerator,
			ProfilePicture: commentAuthor.ProfilePicture,
			IsDeveloper:    commentAuthor.IsDeveloper,
			Replies:        comment.Replies,
			CreatedAt:      comment.CreatedAt,
		}
		comments = append(comments, commentData)
	}

	// Sort comments by CreatedAt in descending order (most recent first)
	sort.Slice(comments, func(i, j int) bool {
		return comments[i].CreatedAt.After(comments[j].CreatedAt)
	})

	// Update hearts with author usernames
	var hearts []string
	for _, heartID := range post.Hearts {
		var heartAuthor types.Author
		if err := usersCollection.FindOne(context.Background(), bson.M{"id": heartID}).Decode(&heartAuthor); err != nil {
			hearts = append(hearts, "Unknown")
			continue
		}

		hearts = append(hearts, heartAuthor.Username)
	}

	// Calculate total votes for polls if applicable
	if post.Poll != nil {
		totalVotes := 0
		for i := range post.Poll {
			for j := range post.Poll[i].Options {
				optionVoteCount := len(post.Poll[i].Options[j].Votes)
				totalVotes += optionVoteCount

				// Clear votes from the response but set vote count
				post.Poll[i].Options[j].Votes = nil
				post.Poll[i].Options[j].VoteCount = optionVoteCount
			}
		}
		// Set total votes for the first poll in the list
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
		"hearts":    hearts,
		"comments":  comments,
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

// Function to calculate time ago
func TimeAgo(createdAt time.Time) string {
	now := time.Now().UTC()
	diff := now.Sub(createdAt)

	years := int(diff.Hours() / 24 / 365)
	if years > 0 {
		return fmt.Sprintf("%d years ago", years)
	}

	months := int(diff.Hours() / 24 / 30)
	if months > 0 {
		return fmt.Sprintf("%d months ago", months)
	}

	days := int(diff.Hours() / 24)
	if days > 0 {
		return fmt.Sprintf("%d days ago", days)
	}

	hours := int(diff.Hours())
	if hours > 0 {
		return fmt.Sprintf("%d hours ago", hours)
	}

	minutes := int(diff.Minutes())
	if minutes > 0 {
		return fmt.Sprintf("%d minutes ago", minutes)
	}

	return "Just now"
}
