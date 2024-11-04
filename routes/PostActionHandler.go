package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"netsocial/types"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// PostActions handles actions on posts, including like, unlike, and voting.
func PostActions(w http.ResponseWriter, r *http.Request) {
	// Get the postId, userId, action, and optionId from query parameters
	postId := r.URL.Query().Get("postId")
	userId := r.URL.Query().Get("userId")
	action := r.URL.Query().Get("action")
	optionId := r.URL.Query().Get("optionId")

	// Validate action (supporting "like", "unlike", and "vote")
	if action != "like" && action != "unlike" && action != "vote" {
		http.Error(w, `{"error": "Invalid action. Action must be 'like', 'unlike', or 'vote'."}`, http.StatusBadRequest)
		return
	}

	// Parse userId to primitive.ObjectID
	userID, err := primitive.ObjectIDFromHex(userId)
	if err != nil {
		http.Error(w, `{"error": "Invalid user ID"}`, http.StatusBadRequest)
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
	err = usersCollection.FindOne(context.Background(), bson.M{"_id": userID}).Decode(&user)
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

		// Convert optionId to primitive.ObjectID
		optionObjectID, err := primitive.ObjectIDFromHex(optionId)
		if err != nil {
			http.Error(w, `{"error": "Invalid option ID"}`, http.StatusBadRequest)
			return
		}

		// Fetch post and check poll expiration
		var post types.Post
		err = postsCollection.FindOne(context.Background(), filter).Decode(&post)
		if err != nil {
			http.Error(w, `{"error": "Post not found"}`, http.StatusNotFound)
			return
		}

		// Check if any poll in the post has expired
		for _, poll := range post.Poll {
			if poll.Expiration.Before(time.Now()) {
				http.Error(w, `{"error": "Poll has expired; voting is not allowed"}`, http.StatusForbidden)
				return
			}
		}

		// Check if the user has already voted
		pollFilter := bson.M{
			"_id":                postId,
			"poll.options.votes": bson.M{"$ne": userID.Hex()}, // Ensure user hasn't voted yet
		}

		// Update the selected option if the user hasn't voted yet
		voteUpdate := bson.M{
			"$addToSet": bson.M{"poll.$[poll].options.$[option].votes": userID.Hex()},
			"$inc":      bson.M{"poll.$[poll].options.$[option].voteCount": 1},
		}
		arrayFilters := options.Update().SetArrayFilters(options.ArrayFilters{
			Filters: []interface{}{
				bson.M{"poll._id": post.Poll[0].ID},
				bson.M{"option._id": optionObjectID},
			},
		})

		// Execute the vote update with array filters
		res, err := postsCollection.UpdateOne(context.Background(), pollFilter, voteUpdate, arrayFilters)
		if err != nil {
			http.Error(w, `{"error": "Failed to cast vote"}`, http.StatusInternalServerError)
			return
		}
		if res.ModifiedCount == 0 {
			http.Error(w, `{"error": "You have already voted or the poll is expired"}`, http.StatusForbidden)
			return
		}

		// Respond with success message
		json.NewEncoder(w).Encode(map[string]interface{}{"message": "Vote cast successfully"})
		return
	}
}
