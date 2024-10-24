package routes

import (
	"context"
	"fmt"
	"time"

	"netsocial/types"

	"github.com/gofiber/fiber/v2"
	"github.com/karlseguin/ccache/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	userCache = ccache.New(ccache.Configure().MaxSize(1000).ItemsToPrune(100))
	postCache = ccache.New(ccache.Configure().MaxSize(1000).ItemsToPrune(100))
)

func init() {
	go purgeCachePeriodically() // Start cache purging routine
}

func purgeCachePeriodically() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		<-ticker.C
		userCache.Clear() // Purge user cache
		postCache.Clear() // Purge post cache
	}
}

func GetAllPosts(c *fiber.Ctx) error {
	db, ok := c.Locals("db").(*mongo.Client)
	if !ok {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Database connection not available",
		})
	}

	postsCollection := db.Database("SocialFlux").Collection("posts")
	usersCollection := db.Database("SocialFlux").Collection("users")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check if posts are already cached
	cachedPosts := postCache.Get("all_posts")
	if cachedPosts != nil {
		// Return cached posts if they exist
		return c.JSON(cachedPosts.Value())
	}

	// Sort posts by CreatedAt in descending order
	findOptions := options.Find().SetSort(bson.D{{Key: "createdAt", Value: -1}})
	cursor, err := postsCollection.Find(ctx, bson.M{}, findOptions)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	defer cursor.Close(ctx)

	var posts []types.Post
	if err := cursor.All(ctx, &posts); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	var visiblePosts []types.Post // A slice to store posts that can be shown

	for i, post := range posts {
		var author types.Author
		// Check if the author is cached
		cachedAuthor := userCache.Get(post.Author.Hex())
		if cachedAuthor != nil {
			author = cachedAuthor.Value().(types.Author)
		} else {
			// Query the usersCollection to check if the author exists
			err := usersCollection.FindOne(ctx, bson.M{"_id": post.Author}).Decode(&author)
			if err != nil {
				// Handle error (author not found)
				posts[i].Author = primitive.ObjectID{} // or set to default if necessary
				continue
			}
			// Cache the author with a 3-minute expiration
			userCache.Set(post.Author.Hex(), author, time.Minute*3)
		}

		// Check if the author's account is private
		if author.IsPrivate {
			continue // Skip this post if the author's account is private
		}

		if post.Poll != nil { // Check if the post has polls
			totalVotes := 0
			for _, poll := range post.Poll {
				for j := range poll.Options {
					optionVoteCount := len(poll.Options[j].Votes)
					totalVotes += optionVoteCount

					poll.Options[j].Votes = nil // Clear votes for the response
					poll.Options[j].VoteCount = optionVoteCount
				}
			}
			// Set total votes for the last poll or aggregate if needed
			if len(post.Poll) > 0 {
				post.Poll[0].TotalVotes = totalVotes
			}
		}

		// Update post author details if user is not private
		posts[i].Author = post.Author
		posts[i].AuthorDetails = author // Set the author details

		// Calculate time ago
		posts[i].TimeAgo = calculateTimeAgo(post.CreatedAt)

		// Calculate number of comments
		posts[i].CommentNumber = len(post.Comments)

		// Remove comments from the post object
		posts[i].Comments = nil
		// Update hearts with author usernames
		for j, heart := range post.Hearts {
			userID, err := primitive.ObjectIDFromHex(heart)
			if err != nil {
				posts[i].Hearts[j] = "Unknown"
				continue
			}

			// Check if the username is already cached
			cachedAuthor := userCache.Get(userID.Hex())
			if cachedAuthor == nil {
				var heartAuthor types.Author
				err := usersCollection.FindOne(ctx, bson.M{"_id": userID}).Decode(&heartAuthor)
				if err != nil {
					// Handle error (user not found)
					posts[i].Hearts[j] = "Unknown"
					continue
				}
				username := heartAuthor.Username
				// Cache the entire author struct with a 3-minute expiration
				userCache.Set(userID.Hex(), heartAuthor, time.Minute*3)
				posts[i].Hearts[j] = username
			} else {
				// Assert the cached value to the correct type (Author)
				author := cachedAuthor.Value().(types.Author)
				posts[i].Hearts[j] = author.Username
			}
		}

		// Add post to the visible posts slice
		visiblePosts = append(visiblePosts, posts[i])
	}

	// Cache the result of the posts for future requests with a 3-minute expiration
	postCache.Set("all_posts", visiblePosts, time.Minute*3)

	// Return only visible posts (posts from non-private accounts)
	return c.JSON(visiblePosts)
}

func calculateTimeAgo(createdAt time.Time) string {
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
