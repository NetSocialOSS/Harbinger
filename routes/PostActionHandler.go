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
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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

	db, ok := r.Context().Value("db").(*mongo.Client)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	usersCollection := db.Database("SocialFlux").Collection("users")
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

	postsCollection := db.Database("SocialFlux").Collection("posts")
	filter := bson.M{"_id": postId}

	switch action {
	case "like", "unlike":
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
		if optionId == "" {
			http.Error(w, `{"error": "Option ID is required for voting"}`, http.StatusBadRequest)
			return
		}

		var post types.Post
		err = postsCollection.FindOne(context.Background(), filter).Decode(&post)
		if err != nil {
			http.Error(w, `{"error": "Post not found"}`, http.StatusNotFound)
			return
		}

		if len(post.Poll) == 0 {
			http.Error(w, `{"error": "No poll found for this post"}`, http.StatusNotFound)
			return
		}

		poll := post.Poll[0]
		if poll.Expiration.Before(time.Now()) {
			http.Error(w, `{"error": "Poll has expired"}`, http.StatusForbidden)
			return
		}

		optionObjID, err := primitive.ObjectIDFromHex(optionId)
		if err != nil {
			http.Error(w, `{"error": "Invalid option ID"}`, http.StatusBadRequest)
			return
		}

		var targetOption *types.Options
		for i := range poll.Options {
			if poll.Options[i].ID == optionObjID {
				targetOption = &poll.Options[i]
				break
			}
		}

		if targetOption == nil {
			http.Error(w, `{"error": "Option not found in the poll"}`, http.StatusNotFound)
			return
		}

		for _, option := range poll.Options {
			for _, voter := range option.Votes {
				if voter == userID {
					http.Error(w, `{"error": "You have already voted in this poll"}`, http.StatusForbidden)
					return
				}
			}
		}

		update := bson.M{
			"$addToSet": bson.M{"poll.0.options.$[option].votes": userID},
		}
		arrayFilters := options.Update().SetArrayFilters(options.ArrayFilters{
			Filters: []interface{}{
				bson.M{"option._id": optionObjID},
			},
		})

		result, err := postsCollection.UpdateOne(context.Background(), filter, update, arrayFilters)
		if err != nil {
			http.Error(w, `{"error": "Failed to cast vote"}`, http.StatusInternalServerError)
			return
		}

		if result.ModifiedCount == 0 {
			http.Error(w, `{"error": "No changes made. Possible duplicate vote or option not found."}`, http.StatusBadRequest)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{"message": "Vote cast successfully"})
	}
}
