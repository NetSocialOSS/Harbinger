package routes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"netsocial/database"
	"netsocial/middlewares"
	"netsocial/types"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/lib/pq"
)

var err error

func deleteAccount(w http.ResponseWriter, r *http.Request) {
	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}
	userId, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	dbPool := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)

	var user types.User
	err = dbPool.QueryRow(r.Context(), `select id, email from users where id = $1`, userId).Scan(&user.ID, &user.Email)
	if err != nil {
		http.Error(w, "Failed to retrieve user details", http.StatusInternalServerError)
		return
	}

	err = SendGoodbyeEmail(user.Email)
	if err != nil {
		http.Error(w, "Failed to send goodbye email", http.StatusInternalServerError)
		return
	}

	tx, err := dbPool.Begin(r.Context())
	if err != nil {
		http.Error(w, "Failed to start transaction", http.StatusInternalServerError)
		return
	}
	defer func() {
		if err != nil {
			tx.Rollback(r.Context())
		} else {
			err = tx.Commit(r.Context())
		}
	}()

	_, err = tx.Exec(r.Context(), `delete from users where id = $1`, userId)
	if err != nil {
		http.Error(w, "Failed to delete user", http.StatusInternalServerError)
		return
	}

	_, err = tx.Exec(r.Context(), `delete from post where author = $1`, userId)
	if err != nil {
		http.Error(w, "Failed to delete posts", http.StatusInternalServerError)
		return
	}

	_, err = tx.Exec(r.Context(), `delete from coterie where owner = $1`, userId)
	if err != nil {
		http.Error(w, "Failed to delete coteries", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User, their posts, and coteries deleted successfully"})
}

func SendGoodbyeEmail(email string) error {
	emailData := middlewares.EmailData{
		From:    "Netsocial <goodbye@netsocial.app>",
		To:      email,
		Subject: "Goodbye from Netsocial",
		Text:    "We're sorry to see you go. If you change your mind, you can always come back and start anew journey. [Rejoin Netsocial](https://netsocial.app/signup).",
	}
	return middlewares.SendEmail(emailData)
}

func GetUserByName(w http.ResponseWriter, r *http.Request) {
	dbPool := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)

	usernameParam := chi.URLParam(r, "username")
	if usernameParam == "" {
		http.Error(w, "Name parameter is required", http.StatusBadRequest)
		return
	}

	action := r.URL.Query().Get("action")

	var user types.User

	err := dbPool.QueryRow(r.Context(), `
        select id, username, displayname, bio, isverified, isorganisation, isdeveloper, isowner,
               isbanned, ispartner, ismoderator, profilepicture, profilebanner, followers,
               following, createdat, links, isprivate, isprivatehearts
        from "users"
        where username = $1
    `, usernameParam).Scan(
		&user.ID, &user.Username, &user.DisplayName, &user.Bio, &user.IsVerified, &user.IsOrganisation,
		&user.IsDeveloper, &user.IsOwner, &user.IsBanned, &user.IsPartner, &user.IsModerator,
		&user.ProfilePicture, &user.ProfileBanner, &user.Followers, &user.Following, &user.CreatedAt,
		&user.Links, &user.IsPrivate, &user.IsPrivateHearts,
	)
	if err != nil {
		if err == pgx.ErrNoRows || err.Error() == "no rows in result set" {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, context.Canceled) {
			http.Error(w, "Request was canceled", http.StatusRequestTimeout)
			return
		} else if errors.Is(err, context.DeadlineExceeded) {
			http.Error(w, "Request timed out", http.StatusGatewayTimeout)
			return
		}

		http.Error(w, "Error fetching user data: "+err.Error(), http.StatusInternalServerError)
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

		var resolvedUsername string
		query := `select username from users where id = $1`
		err := dbPool.QueryRow(r.Context(), query, id).Scan(&resolvedUsername)
		if err != nil {
			if err.Error() == "no rows in result set" {
				return "Unknown User", nil
			}
			return "", err
		}

		userIDToUsername[id] = resolvedUsername
		return resolvedUsername, nil
	}

	if action == "info" {
		infoResponse := map[string]interface{}{
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
		json.NewEncoder(w).Encode(infoResponse)
		return
	}

	processPost := func(post types.Post, author types.Author) (map[string]interface{}, error) {
		var hearts []string
		for _, heartIDStr := range post.Hearts {
			id, err := uuid.Parse(heartIDStr)
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

	if action == "followers" || action == "following" {
		if user.IsPrivate {
			response["message"] = "This account is private"
			json.NewEncoder(w).Encode(response)
			return
		}

		var userIDs []uuid.UUID
		if action == "followers" {
			for _, followerStr := range user.Followers {
				id, err := uuid.Parse(followerStr)
				if err != nil {
					http.Error(w, "Error parsing follower ID", http.StatusInternalServerError)
					return
				}
				userIDs = append(userIDs, id)
			}
		} else {
			for _, followingStr := range user.Following {
				id, err := uuid.Parse(followingStr)
				if err != nil {
					http.Error(w, "Error parsing following ID", http.StatusInternalServerError)
					return
				}
				userIDs = append(userIDs, id)
			}
		}

		var usernames []string
		for _, id := range userIDs {
			un, err := getUsername(id)
			if err != nil {
				http.Error(w, "Error resolving usernames", http.StatusInternalServerError)
				return
			}
			usernames = append(usernames, un)
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			action: usernames,
		})
		return
	}

	var posts []map[string]interface{}
	rows, err := dbPool.Query(r.Context(), `
		select id, title, content, author, coterie, scheduledfor, image, poll, createdat, hearts, comments, isIndexed
		from post
		where isIndexed = true
		and author = $1
		order by createdat desc
	`, user.ID)
	if err != nil {
		http.Error(w, "Failed to fetch posts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var post types.Post
		var commentsJSON pgtype.Text
		var pollJSON pgtype.Text
		var scheduledFor pgtype.Timestamptz

		err := rows.Scan(
			&post.ID, &post.Title, &post.Content, &post.Author, &post.Coterie, &scheduledFor,
			&post.Image, &pollJSON, &post.CreatedAt, &post.Hearts,
			&commentsJSON, &post.Indexing,
		)
		if err != nil {
			http.Error(w, "Error decoding post data: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if scheduledFor.Status == pgtype.Present {
			post.ScheduledFor.Set(scheduledFor.Time)
		} else {
			post.ScheduledFor.Status = pgtype.Null
		}

		if pollJSON.Status == pgtype.Present {
			var decodedPoll []types.Poll
			if err := json.Unmarshal([]byte(pollJSON.String), &decodedPoll); err != nil {
				var singlePoll types.Poll
				if err := json.Unmarshal([]byte(pollJSON.String), &singlePoll); err != nil {
					http.Error(w, fmt.Sprintf("Failed to decode poll: %v", err), http.StatusInternalServerError)
					return
				}
				decodedPoll = append(decodedPoll, singlePoll)
			}
			post.Poll = decodedPoll
		}

		if commentsJSON.Status == pgtype.Present {
			var commentList []types.Comment
			if err := json.Unmarshal([]byte(commentsJSON.String), &commentList); err != nil {
				http.Error(w, fmt.Sprintf("Failed to decode comments: %v", err), http.StatusInternalServerError)
				return
			}
			post.Comments = commentList
		} else {
			post.Comments = []types.Comment{}
		}

		var author types.Author
		err = dbPool.QueryRow(r.Context(), `
				select username, isverified, isorganisation, profilebanner, profilepicture, isdeveloper, isowner, ismoderator
				from users where id = $1
			`, post.Author).Scan(
			&author.Username, &author.IsVerified, &author.IsOrganisation, &author.ProfileBanner,
			&author.ProfilePicture, &author.IsDeveloper, &author.IsOwner, &author.IsModerator,
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

	if action == "hearts" {
		if user.IsPrivateHearts {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "This user has their hearted posts set as private!",
			})
			return
		}

		var heartedPosts []map[string]interface{}
		rows, err := dbPool.Query(r.Context(), `
				select p.id, p.title, p.content, p.author, image, poll, createdat, hearts
				from post p
				join unnest(p.hearts) h on h = $1
				where p.isIndexed = true
				order by p.createdat desc
			`, user.ID)
		if err != nil {
			http.Error(w, "Failed to fetch hearted posts", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var post types.Post
			var pollJSON json.RawMessage
			err := rows.Scan(&post.ID, &post.Title, &post.Content, &post.Author, &post.Image, &pollJSON, &post.CreatedAt, &post.Hearts)
			if err != nil {
				http.Error(w, "Error decoding post data", http.StatusInternalServerError)
				return
			}
			if err := json.Unmarshal(pollJSON, &post.Poll); err != nil {
				http.Error(w, "Error decoding poll data", http.StatusInternalServerError)
				return
			}

			var author types.Author
			err = dbPool.QueryRow(r.Context(), `
					select username, isverified, isorganisation, profilebanner, profilepicture, isdeveloper, isowner, ismoderator
					from users where id = $1
				`, post.Author).Scan(
				&author.Username, &author.IsVerified, &author.IsOrganisation, &author.ProfileBanner,
				&author.ProfilePicture, &author.IsDeveloper, &author.IsOwner, &author.IsModerator,
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
	dbPool := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)

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

	query := `
		update users
		set
			displayname = coalesce($1, displayname),
			bio = coalesce($2, bio),
			profilepicture = coalesce($3, profilepicture),
			profilebanner = coalesce($4, profilebanner),
			links = coalesce($5, links)
		where id = $6`
	_, err = dbPool.Exec(r.Context(), query, displayName, bio, profilePicture, profileBanner, links, userID)
	if err != nil {
		http.Error(w, "Failed to update user profile: "+err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Profile settings updated successfully!",
	})
}

func FollowOrUnfollowUser(w http.ResponseWriter, r *http.Request) {
	dbPool := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)

	username := r.URL.Query().Get("username")
	action := r.URL.Query().Get("action")

	encrypteduserId := r.Header.Get("X-userID")
	if encrypteduserId == "" {
		http.Error(w, "userId query parameter is required", http.StatusBadRequest)
		return
	}
	followerID, err := middlewares.DecryptAES(encrypteduserId)
	if err != nil {
		http.Error(w, "Failed to decrypt userid", http.StatusBadRequest)
		return
	}

	var userToBeUpdated struct {
		ID        string         `json:"id"`
		Followers pq.StringArray `json:"followers"`
	}
	err = dbPool.QueryRow(r.Context(), "select id, followers from users where username = $1", username).Scan(&userToBeUpdated.ID, &userToBeUpdated.Followers)
	if err != nil {
		if err == pgx.ErrNoRows {
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
	err = dbPool.QueryRow(r.Context(), "select id, following from users where id = $1", followerID).Scan(&followerUser.ID, &followerUser.Following)
	if err != nil {
		if err == pgx.ErrNoRows {
			http.Error(w, "Follower not found", http.StatusNotFound)
			return
		}
		http.Error(w, "Error finding follower", http.StatusInternalServerError)
		return
	}

	var isBanned bool
	err = dbPool.QueryRow(r.Context(), "select isbanned from users where id = $1", followerID).Scan(&isBanned)
	if err != nil {
		http.Error(w, "Error checking user status", http.StatusInternalServerError)
		return
	}
	if isBanned {
		http.Error(w, "You are banned from following users.", http.StatusForbidden)
		return
	}

	if userToBeUpdated.ID == followerUser.ID {
		http.Error(w, "You can't follow yourself!", http.StatusBadRequest)
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

	_, err = dbPool.Exec(r.Context(), "update users set followers = $1 where id = $2", pq.Array(updateFollowers), userToBeUpdated.ID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error updating followers list for user %s: %v", username, err), http.StatusInternalServerError)
		return
	}

	_, err = dbPool.Exec(r.Context(), "update users set following = $1 where id = $2", pq.Array(updateFollowing), followerUser.ID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error updating following list for user %s: %v", username, err), http.StatusInternalServerError)
		return
	}

	var followerDisplayName string
	err = dbPool.QueryRow(r.Context(), "select displayname from users where id = $1", followerID).Scan(&followerDisplayName)
	if err != nil {
		http.Error(w, "Error fetching follower display name", http.StatusInternalServerError)
		return
	}

	if action == "follow" {
		_, err = dbPool.Exec(r.Context(),
			"insert into notifications (userid, type, content, link) values ($1, $2, $3, $4)",
			userToBeUpdated.ID, "follow", fmt.Sprintf("%s started following you", followerDisplayName), fmt.Sprintf("/user/%s", followerDisplayName))
		if err != nil {
			http.Error(w, "Error creating follow notification", http.StatusInternalServerError)
			return
		}
	}

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
	dbPool := r.Context().Value(database.DBContextKey).(*pgxpool.Pool)

	encryptedUserID := r.Header.Get("X-userID")

	userID, err := middlewares.DecryptAES(encryptedUserID)
	if err != nil {
		http.Error(w, "Failed to decrypt user ID", http.StatusBadRequest)
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
		err := dbPool.QueryRow(r.Context(), `select "isPrivateHearts" from users where id = $1`, userID).Scan(&currentPrivacy)
		if err != nil {
			if err == pgx.ErrNoRows {
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve user details", http.StatusInternalServerError)
			return
		}

		newPrivacySetting := !currentPrivacy

		_, err = dbPool.Exec(r.Context(), `update users set "isPrivateHearts" = $1 where id = $2`, newPrivacySetting, userID)
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
		err := dbPool.QueryRow(r.Context(), `select isprivate from users where id = $1`, userID).Scan(&currentPrivacy)
		if err != nil {
			if err == pgx.ErrNoRows {
				http.Error(w, "User not found", http.StatusNotFound)
				return
			}
			http.Error(w, "Failed to retrieve user details", http.StatusInternalServerError)
			return
		}

		newPrivacySetting := !currentPrivacy

		_, err = dbPool.Exec(r.Context(), `update users set isprivate = $1 where id = $2`, newPrivacySetting, userID)
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
	r.Post("/user/account/delete", deleteAccount)
	r.Get("/user/{username}", GetUserByName)
	r.Post("/profile/settings", UpdateProfileSettings)
	r.Post("/user/FollowOrUnfollowUser", FollowOrUnfollowUser)
	r.Post("/user/settings/privacy", TogglePrivacy)
}
