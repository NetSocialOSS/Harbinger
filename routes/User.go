package routes

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"netsocial/middlewares"
	"netsocial/types"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/resend/resend-go/v2"
)

func deleteAccount(w http.ResponseWriter, r *http.Request) {
	var requestPayload struct {
		UserId string `json:"userId"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestPayload); err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	userId, err := middlewares.DecryptAES(requestPayload.UserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userId", http.StatusBadRequest)
		return
	}

	db := r.Context().Value("db").(*sql.DB)

	var user types.User
	err = db.QueryRowContext(r.Context(), `SELECT id, email FROM users WHERE id = $1`, userId).Scan(&user.ID, &user.Email)
	if err != nil {
		http.Error(w, "Failed to retrieve user details", http.StatusInternalServerError)
		return
	}

	// Send goodbye email
	err = sendGoodbyeEmail(user.Email)
	if err != nil {
		http.Error(w, "Failed to send goodbye email", http.StatusInternalServerError)
		return
	}

	// Delete user from users
	_, err = db.ExecContext(r.Context(), `DELETE FROM users WHERE id = $1`, userId)
	if err != nil {
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	// Delete all posts authored by the user
	_, err = db.ExecContext(r.Context(), `DELETE FROM post WHERE author = $1`, userId)
	if err != nil {
		http.Error(w, "Failed to delete posts", http.StatusInternalServerError)
		return
	}

	// Delete all coteries owned by the user
	_, err = db.ExecContext(r.Context(), `DELETE FROM coterie WHERE owner = $1`, userId)
	if err != nil {
		http.Error(w, "Failed to delete coteries", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User, their posts, and coteries deleted successfully"})
}

func sendGoodbyeEmail(email string) error {
	apiKey := os.Getenv("RESEND_API_KEY")

	client := resend.NewClient(apiKey)
	params := &resend.SendEmailRequest{
		From:    "Netsocial <goodbye@netsocial.app>",
		To:      []string{email},
		Subject: "Goodbye from Netsocial",
		Text:    "We're sorry to see you go. If you change your mind, you can always come back and start anew journey. [Rejoin Netsocial](https://netsocial.app/signup).",
	}
	_, err := client.Emails.Send(params)
	return err
}

func GetUserByName(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*sql.DB)
	username := chi.URLParam(r, "username")
	if username == "" {
		http.Error(w, "Name parameter is required", http.StatusBadRequest)
		return
	}

	action := r.URL.Query().Get("action")

	var user types.User

	err := db.QueryRowContext(r.Context(), `
    SELECT id, username, displayName, bio, isVerified, isOrganisation, isDeveloper, isOwner, isBanned, isPartner, isModerator, profilePicture, profileBanner, followers, following, createdAt, links, "isPrivate", "isPrivateHearts"
    FROM "users"
    WHERE username = $1`, username).Scan(
		&user.ID, &user.Username, &user.DisplayName, &user.Bio, &user.IsVerified, &user.IsOrganisation,
		&user.IsDeveloper, &user.IsOwner, &user.IsBanned, &user.IsPartner, &user.IsModerator, &user.ProfilePicture, &user.ProfileBanner,
		pq.Array(&user.Followers), pq.Array(&user.Following), &user.CreatedAt, pq.Array(&user.Links),
		&user.IsPrivate, &user.IsPrivateHearts,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		if err == context.Canceled {
			http.Error(w, "Request was canceled", http.StatusRequestTimeout)
			return
		} else if err == context.DeadlineExceeded {
			http.Error(w, "Request timed out", http.StatusGatewayTimeout)
			return
		}

		http.Error(w, "Error fetching user data", http.StatusInternalServerError)
		return
	}

	if user.IsPrivate {
		response := map[string]interface{}{
			"username":       user.Username,
			"displayname":    user.DisplayName,
			"profilePicture": user.ProfilePicture,
			"profileBanner":  user.ProfileBanner,
			"bio":            user.Bio,
			"followersCount": len(user.Followers),
			"followingCount": len(user.Following),
		}

		json.NewEncoder(w).Encode(response)
		return
	}

	response := map[string]interface{}{
		"username":       user.Username,
		"displayname":    user.DisplayName,
		"isVerified":     user.IsVerified,
		"isOrganisation": user.IsOrganisation,
		"isDeveloper":    user.IsDeveloper,
		"isOwner":        user.IsOwner,
		"isBanned":       user.IsBanned,
		"isPartner":      user.IsPartner,
		"isModerator":    user.IsModerator,
		"bio":            user.Bio,
		"createdAt":      user.CreatedAt,
		"profilePicture": user.ProfilePicture,
		"isPrivate":      user.IsPrivate,
		"profileBanner":  user.ProfileBanner,
		"followersCount": len(user.Followers),
		"followingCount": len(user.Following),
	}

	userIDToUsername := make(map[uuid.UUID]string)
	getUsername := func(id uuid.UUID) (string, error) {
		if username, found := userIDToUsername[id]; found {
			return username, nil
		}

		var username string
		query := `SELECT username FROM users WHERE id = $1`
		err := db.QueryRowContext(r.Context(), query, id).Scan(&username)

		if err != nil {
			if err == sql.ErrNoRows {
				return "Unknown User", nil
			}
			return "", err
		}

		userIDToUsername[id] = username
		return username, nil
	}

	if action == "info" {
		response := map[string]interface{}{
			"username":       user.Username,
			"displayname":    user.DisplayName,
			"bio":            user.Bio,
			"isVerified":     user.IsVerified,
			"isOrganisation": user.IsOrganisation,
			"isDeveloper":    user.IsDeveloper,
			"isOwner":        user.IsOwner,
			"isBanned":       user.IsBanned,
			"profilePicture": user.ProfilePicture,
			"profileBanner":  user.ProfileBanner,
			"followersCount": len(user.Followers),
			"followingCount": len(user.Following),
			"createdAt":      user.CreatedAt,
			"links":          user.Links,
			"isPrivate":      user.IsPrivate,
		}

		json.NewEncoder(w).Encode(response)
		return
	}

	processPost := func(post types.Post, author types.Author) (map[string]interface{}, error) {
		var hearts []string
		for _, heartID := range post.Hearts {
			id, err := uuid.Parse(heartID)
			if err != nil {
				return nil, fmt.Errorf("error parsing heart ID: %v", err)
			}

			username, err := getUsername(id)
			if err != nil {
				return nil, fmt.Errorf("error resolving heart usernames: %v", err)
			}
			hearts = append(hearts, username)
		}

		if post.Poll != nil {
			totalVotes := 0
			for i := range post.Poll {
				for j := range post.Poll[i].Options {
					optionVoteCount := len(post.Poll[i].Options[j].Votes)
					totalVotes += optionVoteCount

					post.Poll[i].Options[j].Votes = nil
					post.Poll[i].Options[j].VoteCount = optionVoteCount
				}
			}
			if len(post.Poll) > 0 {
				post.Poll[0].TotalVotes = totalVotes
			}
		}

		return map[string]interface{}{
			"_id":     post.ID,
			"title":   post.Title,
			"content": post.Content,
			"authorDetails": map[string]interface{}{
				"username":       author.Username,
				"isVerified":     author.IsVerified,
				"isOrganisation": author.IsOrganisation,
				"profileBanner":  author.ProfileBanner,
				"profilePicture": author.ProfilePicture,
				"isDeveloper":    author.IsDeveloper,
				"isOwner":        author.IsOwner,
				"isModerator":    author.IsModerator,
			},
			"poll":          post.Poll,
			"image":         post.Image,
			"createdAt":     post.CreatedAt,
			"hearts":        hearts,
			"commentNumber": len(post.Comments),
		}, nil
	}

	// Handle "followers" or "following" actions
	if action == "followers" || action == "following" {
		if user.IsPrivate {
			response["message"] = "This account is private"
			json.NewEncoder(w).Encode(response)
			return
		}

		var userIDs []uuid.UUID
		if action == "followers" {
			for _, follower := range user.Followers {
				id, err := uuid.Parse(follower)
				if err != nil {
					http.Error(w, "Error parsing follower ID", http.StatusInternalServerError)
					return
				}
				userIDs = append(userIDs, id)
			}
		} else {
			for _, followee := range user.Following {
				id, err := uuid.Parse(followee)
				if err != nil {
					http.Error(w, "Error parsing following ID", http.StatusInternalServerError)
					return
				}
				userIDs = append(userIDs, id)
			}
		}

		var usernames []string
		for _, id := range userIDs {
			username, err := getUsername(id)
			if err != nil {
				http.Error(w, "Error resolving usernames", http.StatusInternalServerError)
				return
			}
			usernames = append(usernames, username)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			action: usernames,
		})
		return
	}

	// Query posts that are indexed (isIndexed = true)
	var posts []map[string]interface{}
	rows, err := db.QueryContext(r.Context(), `
		SELECT id, title, content, author, coterie, scheduledfor, image, poll, createdat, hearts, comments, "isIndexed"
		FROM post
		WHERE "isIndexed" = true
		AND author = $1
		ORDER BY createdat DESC`, user.ID)
	if err != nil {
		http.Error(w, "Failed to fetch posts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var post types.Post
		var commentsJSON []byte
		var pollJSON json.RawMessage
		var scheduledFor pq.NullTime
		err := rows.Scan(
			&post.ID, &post.Title, &post.Content, &post.Author, &post.Coterie, &scheduledFor,
			pq.Array(&post.Image), &pollJSON, &post.CreatedAt, pq.Array(&post.Hearts),
			&commentsJSON, &post.Indexing,
		)
		if err != nil {
			http.Error(w, "Error decoding post data"+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := json.Unmarshal(pollJSON, &post.Poll); err != nil {
			http.Error(w, "Error decoding poll data: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if scheduledFor.Valid {
			post.ScheduledFor = scheduledFor.Time
		} else {
			post.ScheduledFor = time.Time{}
		}

		if err := json.Unmarshal(commentsJSON, &post.Comments); err != nil {
			http.Error(w, "Error decoding comments data: "+err.Error(), http.StatusInternalServerError)
			return
		}

		var author types.Author
		err = db.QueryRowContext(r.Context(), `
				SELECT username, isVerified, isOrganisation, profileBanner, profilePicture, isDeveloper, isOwner, isModerator
				FROM users WHERE id = $1
			`, post.Author).Scan(
			&author.Username, &author.IsVerified, &author.IsOrganisation, &author.ProfileBanner, &author.ProfilePicture,
			&author.IsDeveloper, &author.IsOwner, &author.IsModerator,
		)
		if err != nil {
			http.Error(w, "Error fetching author data", http.StatusInternalServerError)
			return
		}

		postData, err := processPost(post, author)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		posts = append(posts, postData)
	}

	// Handle "hearts" action
	if action == "hearts" {
		if user.IsPrivateHearts {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "This user has their hearted posts set as private!",
			})
			return
		}

		var heartedPosts []map[string]interface{}
		rows, err := db.QueryContext(r.Context(), `
				SELECT p.id, p.title, p.content, p.author, p.image, p.poll, p.createdat, p.hearts
				FROM post p
				JOIN unnest(p.hearts) h ON h = $1
				WHERE p."isIndexed" = true
				ORDER BY p.createdat DESC
			`, user.ID)
		if err != nil {
			http.Error(w, "Failed to fetch hearted posts", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var post types.Post
			var pollJSON json.RawMessage
			err := rows.Scan(&post.ID, &post.Title, &post.Content, &post.Author, pq.Array(&post.Image), &pollJSON, &post.CreatedAt, pq.Array(&post.Hearts))
			if err != nil {
				http.Error(w, "Error decoding post data", http.StatusInternalServerError)
				return
			}
			// Process the poll data
			if err := json.Unmarshal(pollJSON, &post.Poll); err != nil {
				http.Error(w, "Error decoding poll data", http.StatusInternalServerError)
				return
			}

			var author types.Author
			err = db.QueryRowContext(r.Context(), `
					SELECT username, isVerified, isOrganisation, profileBanner, profilePicture, isDeveloper, isOwner, isModerator
					FROM users WHERE id = $1
				`, post.Author).Scan(
				&author.Username, &author.IsVerified, &author.IsOrganisation, &author.ProfileBanner, &author.ProfilePicture,
				&author.IsDeveloper, &author.IsOwner, &author.IsModerator,
			)
			if err != nil {
				http.Error(w, "Error fetching author data", http.StatusInternalServerError)
				return
			}

			postData, err := processPost(post, author)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			heartedPosts = append(heartedPosts, postData)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"posts": heartedPosts,
		})
		return
	}

	response["posts"] = posts
	json.NewEncoder(w).Encode(response)
}

func UpdateProfileSettings(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*sql.DB)

	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}
	userID, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	// Prepare update fields
	var displayName, bio, profilePicture, profileBanner *string
	var links []string

	if value := r.URL.Query().Get("displayName"); value != "" {
		decoded, err := url.QueryUnescape(value)
		if err == nil {
			displayName = &decoded
		}
	}
	if value := r.URL.Query().Get("bio"); value != "" {
		decoded, err := url.QueryUnescape(value)
		if err == nil {
			bio = &decoded
		}
	}
	if value := r.URL.Query().Get("profilePicture"); value != "" {
		decoded, err := url.QueryUnescape(value)
		if err == nil {
			profilePicture = &decoded
		}
	}
	if value := r.URL.Query().Get("profileBanner"); value != "" {
		decoded, err := url.QueryUnescape(value)
		if err == nil {
			profileBanner = &decoded
		}
	}
	if linksParam := r.URL.Query().Get("links"); linksParam != "" {
		decodedLinks, err := url.QueryUnescape(linksParam)
		if err == nil {
			links = strings.Split(decodedLinks, ",")
		}
	}

	// Perform update operation
	query := `
		UPDATE users 
		SET 
			displayName = COALESCE($1, displayName), 
			bio = COALESCE($2, bio), 
			profilePicture = COALESCE($3, profilePicture), 
			profileBanner = COALESCE($4, profileBanner), 
			links = COALESCE($5, links) 
		WHERE id = $6`
	_, err = db.ExecContext(r.Context(), query, displayName, bio, profilePicture, profileBanner, pq.Array(links), userID)
	if err != nil {
		http.Error(w, "Failed to update user profile: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Send success response
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Profile settings updated successfully!",
	})
}

func FollowOrUnfollowUser(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*sql.DB)

	username := r.URL.Query().Get("username")
	action := r.URL.Query().Get("action") // This could be either "follow" or "unfollow"

	encryptedUserId := r.Header.Get("X-userID")
	if encryptedUserId == "" {
		http.Error(w, "userId header is required", http.StatusBadRequest)
		return
	}

	followerID, err := middlewares.DecryptAES(encryptedUserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userId", http.StatusBadRequest)
		return
	}

	var userToBeUpdated struct {
		ID        string         `json:"id"`
		Followers pq.StringArray `json:"followers"`
	}
	err = db.QueryRow("SELECT id, followers FROM users WHERE username = $1", username).Scan(&userToBeUpdated.ID, &userToBeUpdated.Followers)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Error finding user", http.StatusInternalServerError)
		return
	}

	var followerUser struct {
		ID        string         `json:"id"`
		Following pq.StringArray `json:"following"`
	}
	err = db.QueryRow("SELECT id, following FROM users WHERE id = $1", followerID).Scan(&followerUser.ID, &followerUser.Following)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Follower not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Error finding follower", http.StatusInternalServerError)
		return
	}

	var isBanned bool
	err = db.QueryRow("SELECT isbanned FROM users WHERE id = $1", followerID).Scan(&isBanned)
	if err != nil {
		http.Error(w, "Error checking user status", http.StatusInternalServerError)
		return
	}
	if isBanned {
		http.Error(w, "You are banned from following users.", http.StatusForbidden)
		return
	}

	if userToBeUpdated.ID == followerUser.ID {
		http.Error(w, "my guy you can't follow yourself!", http.StatusBadRequest)
		return
	}

	if userToBeUpdated.Followers == nil {
		userToBeUpdated.Followers = pq.StringArray{}
	}
	if followerUser.Following == nil {
		followerUser.Following = pq.StringArray{}
	}

	isAlreadyFollowing := false
	for _, follower := range userToBeUpdated.Followers {
		if follower == followerID {
			isAlreadyFollowing = true
			break
		}
	}

	if action == "follow" && isAlreadyFollowing {
		http.Error(w, fmt.Sprintf("You are already following %s", username), http.StatusBadRequest)
		return
	}

	if action == "unfollow" && !isAlreadyFollowing {
		http.Error(w, fmt.Sprintf("You are not following %s", username), http.StatusBadRequest)
		return
	}

	var updateFollowers pq.StringArray
	var updateFollowing pq.StringArray

	if action == "follow" {
		updateFollowers = append(userToBeUpdated.Followers, followerID)
		updateFollowing = append(followerUser.Following, userToBeUpdated.ID)
	} else if action == "unfollow" {
		updateFollowers = removeFromArray(userToBeUpdated.Followers, followerID)
		updateFollowing = removeFromArray(followerUser.Following, userToBeUpdated.ID)
	} else {
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("UPDATE users SET followers = $1 WHERE id = $2", pq.Array(updateFollowers), userToBeUpdated.ID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error updating followers list for user %s: %v", username, err), http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("UPDATE users SET following = $1 WHERE id = $2", pq.Array(updateFollowing), followerUser.ID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error updating following list for user %s: %v", username, err), http.StatusInternalServerError)
		return
	}

	// Respond with success
	actionMessage := "followed"
	if action == "unfollow" {
		actionMessage = "unfollowed"
	}
	successMessage := fmt.Sprintf("Successfully %s %s", actionMessage, username)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": successMessage})
}

func removeFromArray(arr pq.StringArray, value string) pq.StringArray {
	for i, v := range arr {
		if v == value {
			return append(arr[:i], arr[i+1:]...)
		}
	}
	return arr
}

func TogglePrivacy(w http.ResponseWriter, r *http.Request) {
	db := r.Context().Value("db").(*sql.DB)

	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId header is required", http.StatusBadRequest)
		return
	}
	userID, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userId", http.StatusBadRequest)
		return
	}

	action := r.Header.Get("X-action")
	if action == "" {
		http.Error(w, "action parameter is required", http.StatusBadRequest)
		return
	}

	var currentPrivacy bool

	switch action {
	case "togglePrivateHearts":
		err = db.QueryRowContext(r.Context(), `SELECT "isPrivateHearts" FROM users WHERE id = $1`, userID).Scan(&currentPrivacy)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve user details", http.StatusInternalServerError)
			return
		}

		newPrivacySetting := !currentPrivacy

		_, err = db.ExecContext(r.Context(), `UPDATE users SET "isPrivateHearts" = $1 WHERE id = $2`, newPrivacySetting, userID)
		if err != nil {
			http.Error(w, "Failed to update privacy setting", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		response := map[string]interface{}{
			"message":            "Privacy setting updated successfully",
			"isPrivateHeartsNow": newPrivacySetting,
		}
		json.NewEncoder(w).Encode(response)

	case "togglePrivateAccount":
		err = db.QueryRowContext(r.Context(), `SELECT "isPrivate" FROM users WHERE id = $1`, userID).Scan(&currentPrivacy)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve user details", http.StatusInternalServerError)
			return
		}

		newPrivacySetting := !currentPrivacy

		_, err = db.ExecContext(r.Context(), `UPDATE users SET "isPrivate" = $1 WHERE id = $2`, newPrivacySetting, userID)
		if err != nil {
			http.Error(w, "Failed to update privacy setting", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		response := map[string]interface{}{
			"message":      "Privacy setting updated successfully",
			"isPrivateNow": newPrivacySetting,
		}
		json.NewEncoder(w).Encode(response)

	default:
		http.Error(w, "Invalid action parameter", http.StatusBadRequest)
		return
	}
}

func User(r *chi.Mux) {
	r.Post("/user/account/delete", (middlewares.DiscordErrorReport(http.HandlerFunc(deleteAccount)).ServeHTTP))
	r.Get("/user/{username}", (middlewares.DiscordErrorReport(http.HandlerFunc(GetUserByName)).ServeHTTP))
	r.Post("/profile/settings", (middlewares.DiscordErrorReport(http.HandlerFunc(UpdateProfileSettings)).ServeHTTP))
	r.Post("/user/FollowOrUnfollowUser", (middlewares.DiscordErrorReport(http.HandlerFunc(FollowOrUnfollowUser)).ServeHTTP))
	r.Post("/user/settings/privacy", (middlewares.DiscordErrorReport(http.HandlerFunc(TogglePrivacy)).ServeHTTP))
}
