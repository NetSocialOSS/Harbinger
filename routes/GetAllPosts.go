package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"netsocial/database"
	"netsocial/types"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/karlseguin/ccache/v2"
)

var (
	userCache = ccache.New(ccache.Configure().MaxSize(1000).ItemsToPrune(100))
	postCache = ccache.New(ccache.Configure().MaxSize(1000).ItemsToPrune(100))

	// HTTP client with connection pooling
	httpClient = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     30 * time.Second,
		},
		Timeout: 10 * time.Second,
	}
	post   types.Post
	author types.Author
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

func GetAllPosts(w http.ResponseWriter, r *http.Request) {
	db, ok := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)
	if !ok {
		http.Error(w, `{"error": "Database connection not available"}`, http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check if posts are already cached
	cachedPosts := postCache.Get("all_posts")
	if cachedPosts != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cachedPosts.Value())
		return
	}

	query := `SELECT id, title, content, author, coterie, scheduledfor, image, poll, createdat, hearts, comments, isIndexed
			FROM post
			WHERE isIndexed = true
			ORDER BY createdat DESC`

	rows, err := db.Query(ctx, query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var posts []types.Post
	for rows.Next() {
		var commentsJSON []byte
		var pollJSON *string
		var scheduledFor *time.Time

		err := rows.Scan(
			&post.ID, &post.Title, &post.Content, &post.Author, &post.Coterie, &scheduledFor,
			&post.Image, &pollJSON, &post.CreatedAt, &post.Hearts,
			&commentsJSON, &post.Indexing,
		)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if scheduledFor != nil {
			post.ScheduledFor = *scheduledFor
		} else {
			post.ScheduledFor = time.Time{}
		}

		if err := json.Unmarshal(commentsJSON, &post.Comments); err != nil {
			post.Comments = nil
		}

		// Handle the poll
		if pollJSON != nil {
			var decodedPoll []types.Poll
			err := json.Unmarshal([]byte(*pollJSON), &decodedPoll)

			// If unmarshalling into a slice fails, try unmarshalling into a single Poll object
			if err != nil {
				var singlePoll types.Poll
				if err := json.Unmarshal([]byte(*pollJSON), &singlePoll); err != nil {
					http.Error(w, fmt.Sprintf("Failed to decode poll: %v", err), http.StatusInternalServerError)
					return
				}
				// Convert single poll to a slice
				decodedPoll = append(decodedPoll, singlePoll)
			}

			post.Poll = decodedPoll
		}

		posts = append(posts, post)
	}

	var visiblePosts []map[string]interface{}
	now := time.Now()
	for _, post := range posts {
		if !post.Indexing {
			continue
		}

		cachedAuthor := userCache.Get(post.Author)
		if cachedAuthor != nil {
			author = cachedAuthor.Value().(types.Author)
		} else {
			authorQuery := `SELECT username, isVerified, isOrganisation, profileBanner, profilePicture, isDeveloper, isOwner, isModerator, isPartner
				FROM users WHERE id = $1`
			err := db.QueryRow(ctx, authorQuery, post.Author).Scan(
				&author.Username, &author.IsVerified, &author.IsOrganisation, &author.ProfileBanner, &author.ProfilePicture,
				&author.IsDeveloper, &author.IsOwner, &author.IsModerator, &author.IsPartner,
			)
			if err != nil {
				continue
			}
			userCache.Set(post.Author, author, time.Minute*3)
		}

		if author.IsPrivate {
			continue
		}

		if post.Poll != nil {
			totalVotes := 0
			for _, poll := range post.Poll {
				for j := range poll.Options {
					totalVotes += len(poll.Options[j].Votes)
					poll.Options[j].VoteCount = len(poll.Options[j].Votes)
					poll.Options[j].Votes = nil
				}
			}
			if len(post.Poll) > 0 {
				post.Poll[0].TotalVotes = totalVotes
			}
		}

		if !post.ScheduledFor.IsZero() && post.ScheduledFor.After(now) {
			continue
		}

		var heartsDetails []string
		for _, heart := range post.Hearts {
			userID, err := uuid.Parse(heart)
			if err != nil {
				continue
			}

			cachedauthor := userCache.Get(userID.String())
			if cachedauthor == nil {

				err := db.QueryRow(ctx, `SELECT username, isVerified, isOrganisation, profileBanner, profilePicture, isDeveloper, isOwner, isModerator, isPartner FROM users WHERE id = $1`, userID.String()).Scan(
					&author.Username, &author.IsVerified, &author.IsOrganisation, &author.ProfileBanner, &author.ProfilePicture,
					&author.IsDeveloper, &author.IsOwner, &author.IsModerator, &author.IsPartner,
				)
				if err != nil {
					continue
				}
				heartsDetails = append(heartsDetails, author.Username)
				userCache.Set(userID.String(), author, time.Minute*3)
			} else {
				cachedAuthor := cachedauthor.Value().(types.Author)
				heartsDetails = append(heartsDetails, cachedAuthor.Username)
			}
		}

		postResponse := map[string]interface{}{
			"_id":           post.ID,
			"title":         post.Title,
			"content":       post.Content,
			"image":         post.Image,
			"hearts":        heartsDetails,
			"poll":          post.Poll,
			"timeAgo":       calculateTimeAgo(post.CreatedAt),
			"commentNumber": len(post.Comments),
			"authorDetails": map[string]interface{}{
				"isVerified":     author.IsVerified,
				"isOrganisation": author.IsOrganisation,
				"isDeveloper":    author.IsDeveloper,
				"profilePicture": author.ProfilePicture,
				"isPartner":      author.IsPartner,
				"isOwner":        author.IsOwner,
				"isModerator":    author.IsModerator,
				"username":       author.Username,
			},
		}

		if !post.ScheduledFor.IsZero() {
			postResponse["scheduledFor"] = post.ScheduledFor
		}

		visiblePosts = append(visiblePosts, postResponse)
	}

	postCache.Set("all_posts", visiblePosts, time.Minute*3)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(visiblePosts)
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
