package types

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Post struct {
	ID        string             `bson:"_id" json:"_id"`
	Title     string             `bson:"title" json:"title"`
	Content   string             `bson:"content" json:"content"`
	Author    primitive.ObjectID `bson:"author" json:"-"`
	ImageURL  string             `bson:"imageUrl,omitempty" json:"imageUrl,omitempty"`
	Image     string             `bson:"image,omitempty" json:"image,omitempty"`
	Hearts    []string           `bson:"hearts" json:"hearts"`
	CreatedAt time.Time          `bson:"createdAt" json:"createdAt"`
	Comments  []Comment          `bson:"comments,omitempty" json:"comments,omitempty"`
}

type NewPost struct {
	ID        string             `json:"id,omitempty" bson:"_id,omitempty"`
	Title     string             `json:"title"`
	Content   string             `json:"content"`
	Author    primitive.ObjectID `json:"author"`
	Image     string             `json:"image,omitempty"`
	Hearts    []string           `json:"hearts,omitempty"`
	CreatedAt time.Time          `json:"createdAt"`
	Comments  []string           `json:"comments,omitempty" bson:"comments,omitempty"`
}

type Author struct {
	Bio            string    `bson:"bio" json:"bio"`
	IsVerified     bool      `json:"isVerified"`
	IsDeveloper    bool      `json:"isDeveloper"`
	IsPartner      bool      `json:"isPartner"`
	IsOwner        bool      `json:"isOwner"`
	IsOrganisation bool      `json:"isOrganisation"`
	CreatedAt      time.Time `bson:"createdAt" json:"createdAt"`
	Username       string    `bson:"username" json:"username"`
}

type Comment struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"_id,omitempty"`
	Content        string             `bson:"content" json:"content"`
	Author         primitive.ObjectID `bson:"author" json:"author"`
	IsVerified     bool               `json:"isVerified"`
	IsOrganisation bool               `json:"isOrganisation"`
	IsPartner      bool               `json:"isPartner"`
	AuthorName     string             `json:"authorName"`
	IsOwner        bool               `json:"isOwner"`
	IsDeveloper    bool               `json:"isDeveloper"`
	Replies        []Comment          `bson:"replies" json:"replies"`
}

type User struct {
	ID             primitive.ObjectID `json:"_id"`
	Username       string             `json:"username"`
	DisplayName    string             `json:"displayname"`
	UserID         int                `bson:"userid" json:"userid"`
	Email          string             `bson:"email" json:"email"`
	CreatedAt      time.Time          `bson:"createdAt" json:"createdAt"`
	ProfilePicture string             `bson:"profilePicture" json:"profilePicture"`
	ProfileBanner  string             `bson:"profileBanner" json:"profileBanner"`
	Bio            string             `bson:"bio" json:"bio"`
	IsVerified     bool               `json:"isVerified"`
	IsOrganisation bool               `json:"isOrganisation"`
	IsDeveloper    bool               `json:"isDeveloper"`
	IsPartner      bool               `json:"isPartner"`
	IsOwner        bool               `json:"isOwner"`
	Password       string             `bson:"password,omitempty" json:"-"`
	Links          []string           `bson:"links,omitempty" json:"links,omitempty"`
}

type BlogPost struct {
	Slug         string      `json:"slug"`
	Title        string      `json:"title"`
	Date         string      `json:"date"`
	AuthorName   string      `json:"authorname"`
	Overview     string      `json:"overview"`
	Authoravatar string      `json:"authoravatar"`
	Content      []PostEntry `json:"content"`
}

type PostEntry struct {
	Body string `json:"body"`
}

type ServerStatus struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url,omitempty"`
}

type Partner struct {
	Banner string `json:"banner,omitempty" bson:"banner,omitempty"`
	Logo   string `json:"logo,omitempty" bson:"logo,omitempty"`
	Title  string `json:"title,omitempty" bson:"title,omitempty"`
	Text   string `json:"text,omitempty" bson:"text,omitempty"`
	Link   string `json:"link,omitempty" bson:"link,omitempty"`
}

type ImgbbImage struct {
	Filename  string `json:"filename"`
	Name      string `json:"name"`
	Mime      string `json:"mime"`
	Extension string `json:"extension"`
	Url       string `json:"url"`
}

type ImgbbResponse struct {
	Data    ImgbbResponseData `json:"data"`
	Success bool              `json:"success"`
	Status  int               `json:"status"`
}

type ImgbbResponseData struct {
	ID string `json:"id"`

	DisplayURL string `json:"display_url"`
	DeleteURL  string `json:"delete_url"`

	Expiration string `json:"expiration"`

	Height string `json:"height"`
	Width  string `json:"width"`

	Image  ImgbbImage `json:"image"`
	Thumb  ImgbbImage `json:"thumb"`
	Medium ImgbbImage `json:"medium"`
}

/*
 * ==========================
 * Configuration Types: not suggested to mess with!!
 * ==========================
 */

type Config struct {
	ApiVersion int `json:"apiVersion"`
	Database   `json:"database"`
	Web        `json:"web"`
	APIUrl     string `json:"apiUrl"`
}

type Database struct {
	Url string `json:"url"`
}

type Web struct {
	Port           string `json:"port"`
	ImageUploadKey string `json:"ImageUploadKey"`
}
