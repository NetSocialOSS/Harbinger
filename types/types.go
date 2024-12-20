package types

import (
	"time"
)

type Post struct {
	ID            string    `bson:"_id" json:"_id"`
	Title         string    `bson:"title" json:"title"`
	Content       string    `bson:"content" json:"content"`
	Author        string    `bson:"author" json:"-"`
	CommentNumber int       `bson:"commentNumber" json:"commentNumber"`
	TimeAgo       string    `bson:"timeAgo" json:"timeAgo"`
	ScheduledFor  time.Time `bson:"scheduledFor" json:"scheduledFor"`
	Image         []string  `bson:"image" json:"image"`
	Indexing      bool      `bson:"isIndexed"`
	Hearts        []string  `bson:"hearts" json:"hearts"`
	CreatedAt     time.Time `bson:"createdAt" json:"createdAt"`
	Poll          []Poll    `bson:"poll,omitempty" json:"poll,omitempty"`
	Comments      []Comment `bson:"comments,omitempty" json:"comments,omitempty"`
	Coterie       string    `bson:"coterie,omitempty" json:"coterie,omitempty"`
	AuthorDetails Author    `bson:"authorDetails,omitempty" json:"authorDetails,omitempty"`
}

type Poll struct {
	ID         string    `bson:"id" json:"id"`
	Options    []Options `bson:"options" json:"options"`
	CreatedAt  time.Time `bson:"createdAt" json:"createdAt"`
	TotalVotes int       `bson:"totalVotes" json:"totalVotes"`
	Expiration time.Time `bson:"expiration" json:"expiration"`
}

type Options struct {
	ID        string   `bson:"id" json:"id"`
	Votes     []string `bson:"votes" json:"votes"`
	VoteCount int      `json:"voteCount"`
	Name      string   `bson:"name" json:"name"`
}

type NewPost struct {
	ID           string    `json:"id,omitempty" bson:"_id,omitempty"`
	Title        string    `json:"title"`
	Content      string    `json:"content"`
	Indexing     bool      `bson:"isIndexed"`
	Author       string    `json:"author"`
	Image        []string  `json:"image,omitempty"`
	ScheduledFor time.Time `bson:"scheduledFor" json:"scheduledFor"`
	Coterie      string    `json:"coterie"`
	Hearts       []string  `json:"hearts,omitempty"`
	CreatedAt    time.Time `json:"createdAt" bson:"createdAt"`
	Poll         []NewPoll `bson:"poll,omitempty" json:"poll,omitempty"`
	Comments     []string  `json:"comments,omitempty" bson:"comments,omitempty"`
}

type NewPoll struct {
	ID         string       `bson:"id" json:"id"`
	Options    []NewOptions `bson:"options" json:"options"`
	CreatedAt  time.Time    `bson:"createdAt" json:"createdAt"`
	Expiration time.Time    `bson:"expiration" json:"expiration"`
}

type NewOptions struct {
	ID    string   `bson:"id" json:"id"`
	Votes []string `bson:"votes" json:"-"`
	Name  string   `bson:"name" json:"name"`
}

type UserSettingsUpdate struct {
	DisplayName    string   `json:"displayName,omitempty"`
	Bio            string   `json:"bio,omitempty"`
	ProfilePicture string   `json:"profilePicture,omitempty"`
	IsOrganisation *bool    `json:"isOrganisation"`
	ProfileBanner  string   `json:"profileBanner,omitempty"`
	Links          []string `json:"links,omitempty"`
}

type Author struct {
	IsVerified     bool      `json:"isVerified"`
	IsDeveloper    bool      `json:"isDeveloper"`
	IsPrivate      bool      `bson:"isPrivate" json:"isPrivate"`
	IsPartner      bool      `json:"isPartner"`
	ProfilePicture *string   `json:"profilePicture,omitempty"`
	ProfileBanner  *string   `bson:"profilebanner" json:"profilebanner"`
	IsOwner        bool      `json:"isOwner"`
	IsModerator    bool      `json:"isModerator"`
	IsOrganisation bool      `json:"isOrganisation"`
	CreatedAt      time.Time `bson:"createdAt" json:"createdAt"`
	Username       string    `bson:"username" json:"username"`
}

type NewComment struct {
	ID        string    `bson:"ID" json:"ID"`
	Content   string    `bson:"content" json:"Content"`
	Author    string    `bson:"author" json:"Author"`
	CreatedAt time.Time `json:"CreatedAt"`
}

type Comment struct {
	ID             string    `json:"ID"`
	Author         string    `json:"Author"`
	Content        string    `json:"Content"`
	CreatedAt      time.Time `json:"CreatedAt"`
	IsVerified     bool      `json:"isVerified"`
	IsOrganisation bool      `json:"isOrganisation"`
	IsModerator    bool      `json:"isModerator"`
	IsPartner      bool      `json:"isPartner"`
	AuthorName     string    `json:"authorName"`
	ProfilePicture string    `bson:"profilePicture" json:"profilePicture"`
	TimeAgo        string    `json:"timeAgo"`
	IsOwner        bool      `json:"isOwner"`
	IsDeveloper    bool      `json:"isDeveloper"`
	Replies        []Comment `bson:"replies" json:"replies"`
}

type User struct {
	ID              string    `json:"id"`
	Username        string    `json:"username"`
	DisplayName     string    `json:"displayname"`
	UserID          int       `bson:"userid" json:"userid"`
	Email           string    `bson:"email" json:"email"`
	CreatedAt       time.Time `bson:"createdAt" json:"createdAt"`
	ProfilePicture  string    `bson:"profilepicture" json:"profilepicture"`
	ProfileBanner   *string   `bson:"profilebanner" json:"profilebanner"`
	Bio             *string   `json:"bio"`
	IsVerified      bool      `json:"isVerified"`
	IsOrganisation  bool      `json:"isOrganisation"`
	IsDeveloper     bool      `json:"isDeveloper"`
	IsPartner       bool      `json:"isPartner"`
	IsOwner         bool      `json:"isOwner"`
	IsModerator     bool      `json:"isModerator"`
	IsPrivate       bool      `bson:"isPrivate" json:"isPrivate"`
	IsPrivateHearts bool      `bson:"isPrivateHearts"`
	IsBanned        bool      `json:"isBanned"`
	Session         []Session `bson:"session" json:"session"`
	Password        string    `bson:"password,omitempty" json:"-"`
	Links           []string  `bson:"links,omitempty" json:"links,omitempty"`
	Followers       []string  `bson:"followers" json:"followers"`
	Following       []string  `bson:"following" json:"following"`
}

type Session struct {
	UserID    string    `bson:"user_id"`
	SessionID string    `bson:"session_id"`
	Device    string    `bson:"device"`
	StartedAt time.Time `bson:"started_at"`
	ExpiresAt time.Time `bson:"expires_at"`
	Token     string    `bson:"token"`
}

type Coterie struct {
	ID             string                     `bson:"id" json:"id"`
	Name           string                     `bson:"name" json:"name"`
	Description    *string                    `bson:"description" json:"description"`
	Members        []string                   `bson:"members" json:"members"`
	Owner          string                     `bson:"owner" json:"owner"`
	OwnerUsername  string                     `json:"ownerUsername,omitempty"`
	IsOrganisation bool                       `json:"isOrganisation"`
	CreatedAt      time.Time                  `bson:"createdAt" json:"createdAt"`
	Banner         *string                    `bson:"banner" json:"banner,omitempty"`
	Avatar         *string                    `bson:"avatar" json:"avatar,omitempty"`
	IsChatAllowed  bool                       `bson:"isChatAllowed" json:"isChatAllowed"`
	IsVerified     bool                       `json:"isVerified"`
	TotalPosts     int                        `json:"totalPosts,omitempty"`
	Roles          map[string][]string        `bson:"roles,omitempty" json:"roles,omitempty"`
	BannedMembers  []string                   `bson:"bannedMembers,omitempty" json:"bannedMembers,omitempty"`
	MemberDetails  []map[string]interface{}   `json:"memberDetails"`
	WarningDetails map[string][]WarningDetail `bson:"warningDetails,omitempty" json:"warningDetails,omitempty"`
	WarningLimit   int                        `bson:"warningLimit" json:"warningLimit"`
}

type Roles struct {
	Owner     []string `json:"owners"`
	Moderator []string `json:"moderators"`
	Admin     []string `json:"admins"`
}

type WarningDetail struct {
	Reason string    `bson:"reason" json:"reason"`
	Time   time.Time `bson:"time" json:"time"`
}

type Message struct {
	ID        string    `bson:"_id,omitempty" json:"id"`
	Coterie   string    `bson:"coterie" json:"coterie"`
	UserID    string    `bson:"userID" json:"userID"`
	Content   string    `bson:"content" json:"content"`
	CreatedAt time.Time `bson:"createdAt" json:"createdAt"`
}

type BlogPost struct {
	ID       string      `bson:"id,omitempty" json:"id"`
	Slug     string      `json:"slug"`
	Title    string      `json:"title"`
	Date     string      `json:"date"`
	AuthorID string      `json:"authorId"`
	Overview string      `json:"overview"`
	Content  []PostEntry `json:"content"`
}

type PostEntry struct {
	Body string `json:"body"`
}

type Partner struct {
	ID     string `bson:"id,omitempty" json:"id"`
	Banner string `json:"banner,omitempty" bson:"banner,omitempty"`
	Logo   string `json:"logo,omitempty" bson:"logo,omitempty"`
	Title  string `json:"title,omitempty" bson:"title,omitempty"`
	Text   string `json:"text,omitempty" bson:"text,omitempty"`
	Link   string `json:"link,omitempty" bson:"link,omitempty"`
}

type LinkPreview struct {
	URL         string   `json:"url"`
	Images      []string `json:"images"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Domain      string   `json:"domain"`
}

/*
 * ==========================
 * Configuration Types: not suggested to mess with!!
 * ==========================
 */

type Config struct {
	ApiVersion string `json:"apiVersion"`
	Database   `json:"database"`
}

type Database struct {
	Url string `json:"url"`
}
