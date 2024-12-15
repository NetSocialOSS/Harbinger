package routes

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"netsocial/types"

	"github.com/google/uuid"
	"github.com/karlseguin/ccache/v2"
	"github.com/lib/pq"
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
	db, ok := r.Context().Value("db").(*sql.DB)
	if !ok {
		http.Error(w, "Database connection not available", http.StatusInternalServerError)
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

	query := `SELECT id, title, content, author, coterie, scheduledfor, image, poll, createdat, hearts, comments, "isIndexed"
			FROM post
			WHERE "isIndexed" = true
			ORDER BY createdat DESC`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var posts []types.Post
	for rows.Next() {
		var post types.Post
		var commentsJSON []byte
		var pollJSON json.RawMessage
		var scheduledFor sql.NullTime

		err := rows.Scan(
			&post.ID, &post.Title, &post.Content, &post.Author, &post.Coterie, &scheduledFor,
			pq.Array(&post.Image), &pollJSON, &post.CreatedAt, pq.Array(&post.Hearts),
			&commentsJSON, &post.Indexing,
		)
		if err != nil {
			log.Printf("Error scanning row: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if scheduledFor.Valid {
			post.ScheduledFor = scheduledFor.Time
		} else {
			post.ScheduledFor = time.Time{}
		}

		if err := json.Unmarshal(commentsJSON, &post.Comments); err != nil {
			log.Printf("Error unmarshalling comments JSON: %v", err)
			post.Comments = nil
		}
		if err := json.Unmarshal(pollJSON, &post.Poll); err != nil {
			log.Printf("Error unmarshalling poll JSON: %v", err)
			post.Poll = nil
		}

		posts = append(posts, post)
	}

	var visiblePosts []map[string]interface{}
	now := time.Now()
	for _, post := range posts {
		if !post.Indexing {
			continue
		}

		var author types.Author
		cachedAuthor := userCache.Get(post.Author)
		if cachedAuthor != nil {
			author = cachedAuthor.Value().(types.Author)
		} else {
			authorQuery := `SELECT username, isVerified, isOrganisation, profileBanner, profilePicture, isDeveloper, isOwner, isModerator, isPartner
				FROM users WHERE id = $1`
			err := db.QueryRowContext(ctx, authorQuery, post.Author).Scan(
				&author.Username, &author.IsVerified, &author.IsOrganisation, &author.ProfileBanner, &author.ProfilePicture,
				&author.IsDeveloper, &author.IsOwner, &author.IsModerator, &author.IsPartner,
			)
			if err != nil {
				log.Printf("Error fetching author data for user %s", err)
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
				log.Printf("Error parsing heart UUID %s: %v", heart, err)
				continue
			}

			cachedHeartAuthor := userCache.Get(userID.String())
			if cachedHeartAuthor == nil {
				var heartAuthor types.Author
				err := db.QueryRowContext(ctx, `SELECT username, isVerified, isOrganisation, profileBanner, profilePicture, isDeveloper, isOwner, isModerator, isPartner FROM users WHERE id = $1`, userID.String()).Scan(
					&heartAuthor.Username, &heartAuthor.IsVerified, &heartAuthor.IsOrganisation, &heartAuthor.ProfileBanner, &heartAuthor.ProfilePicture,
					&heartAuthor.IsDeveloper, &heartAuthor.IsOwner, &heartAuthor.IsModerator, &heartAuthor.IsPartner,
				)
				if err != nil {
					log.Printf("Error fetching heart author data for user %s", err)
					continue
				}
				heartsDetails = append(heartsDetails, heartAuthor.Username)
				userCache.Set(userID.String(), heartAuthor, time.Minute*3)
			} else {
				cachedAuthor := cachedHeartAuthor.Value().(types.Author)
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
