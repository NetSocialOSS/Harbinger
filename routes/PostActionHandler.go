package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"netsocial/middlewares"
	"netsocial/types"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// PostActions handles actions on posts, including like, unlike, and voting.
func PostActions(w http.ResponseWriter, r *http.Request) {
	postId := r.Header.Get("X-postId")
	encryptedUserID := r.Header.Get("X-userID")
	action := r.URL.Query().Get("action")
	optionId := r.Header.Get("X-optionId")

	// Validate action (supporting "like", "unlike", and "vote")
	if action != "like" && action != "unlike" && action != "vote" {
		http.Error(w, `{"error": "Invalid action. Action must be 'like', 'unlike', or 'vote'."}`, http.StatusBadRequest)
		return
	}

	// Decrypt the user ID
	userID, err := middlewares.DecryptAES(encryptedUserID)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	// Validate that userId is a valid UUID
	if _, err := uuid.Parse(userID); err != nil {
		http.Error(w, `{"error": "Invalid user ID. Must be a valid UUID."}`, http.StatusBadRequest)
		return
	}

	// Access MongoDB client from context
	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	// Access MongoDB collection for users
	usersCollection := db.Database("SocialFlux").Collection("users")

	// Check if the user is banned
	var user types.User
	err = usersCollection.FindOne(context.Background(), bson.M{"id": userID}).Decode(&user)
	if err != nil {
		http.Error(w, `{"error": "Failed to fetch user details"}`, http.StatusInternalServerError)
		return
	}
	if user.IsBanned {
		http.Error(w, `{"error": "You are banned from using NetSocial's services."}`, http.StatusForbidden)
		return
	}

	// Access MongoDB collection for posts
	postsCollection := db.Database("SocialFlux").Collection("posts")

	// Filter for the post by postId
	filter := bson.M{"_id": postId}

	switch action {
	case "like", "unlike":
		// Handle like/unlike actions
		var update bson.M
		if action == "like" {
			update = bson.M{"$addToSet": bson.M{"hearts": userID}}
		} else {
			update = bson.M{"$pull": bson.M{"hearts": userID}}
		}
		_, err = postsCollection.UpdateOne(context.Background(), filter, update)
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

	case "vote":
		// Ensure the optionId is provided
		if optionId == "" {
			http.Error(w, `{"error": "Option ID is required for voting"}`, http.StatusBadRequest)
			return
		}

		// Fetch post and validate poll data
		var post types.Post
		err = postsCollection.FindOne(context.Background(), filter).Decode(&post)
		if err != nil {
			http.Error(w, `{"error": "Post not found"}`, http.StatusNotFound)
			return
		}

		// Check poll expiration and existence
		var targetPoll *types.Poll
		for _, poll := range post.Poll {
			if poll.Expiration.After(time.Now()) && poll.ID == optionId {
				targetPoll = &poll
				break
			}
		}
		if targetPoll == nil {
			http.Error(w, `{"error": "Poll has expired or does not exist"}`, http.StatusForbidden)
			return
		}

		// Verify if user has already voted in the poll
		userAlreadyVoted := false
		for _, option := range targetPoll.Options {
			for _, voter := range option.Votes {
				if voter == userID {
					userAlreadyVoted = true
					break
				}
			}
			if userAlreadyVoted {
				break
			}
		}
		if userAlreadyVoted {
			http.Error(w, `{"error": "You have already voted in this poll"}`, http.StatusForbidden)
			return
		}

		// Update vote for the selected option
		voteUpdate := bson.M{
			"$addToSet": bson.M{"poll.$[poll].options.$[option].votes": userID},
			"$inc":      bson.M{"poll.$[poll].options.$[option].voteCount": 1},
		}
		arrayFilters := options.Update().SetArrayFilters(options.ArrayFilters{
			Filters: []interface{}{
				bson.M{"poll._id": targetPoll.ID},
				bson.M{"option._id": optionId},
			},
		})

		res, err := postsCollection.UpdateOne(context.Background(), filter, voteUpdate, arrayFilters)
		if err != nil || res.ModifiedCount == 0 {
			http.Error(w, `{"error": "Failed to cast vote or vote already counted"}`, http.StatusInternalServerError)
			return
		}

		// Respond with success message
		json.NewEncoder(w).Encode(map[string]interface{}{"message": "Vote cast successfully"})
		return
	}
}
