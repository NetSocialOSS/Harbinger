package middlewares

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"

	"netsocial/types"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func generateRandomKey(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

var jwtKey []byte

func init() {
	keyLength := 32
	randomKey, err := generateRandomKey(keyLength)
	if err != nil {
		panic("Error generating random key: " + err.Error())
	}
	jwtKey = []byte(randomKey)
}

func GenerateJWT(c *fiber.Ctx, userID string) string {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = userID
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

	tokenString, _ := token.SignedString(jwtKey)

	accessToken := jwt.New(jwt.SigningMethodHS256)

	claims = accessToken.Claims.(jwt.MapClaims)
	claims["user_id"] = userID
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

	accessTokenString, _ := accessToken.SignedString(jwtKey)

	return tokenString + " " + accessTokenString
}

func ValidateJWT(c *fiber.Ctx) interface{} {
	token := c.Get("Authorization")
	if token == "" {
		return false
	}
	token = parseJWT(c, token).(string)

	_, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, nil
		}
		return jwtKey, nil
	})

	if err != nil {
		return false
	}

	db := c.Locals("db").(*mongo.Client)
	users := db.Database("TopicBots").Collection("usersDB1")

	var result types.User

	err = users.FindOne(context.Background(), bson.M{"access_token": token}).Decode(&result)

	if err != nil {
		return false
	}

	return token
}

func parseJWT(c *fiber.Ctx, string string) interface{} {
	parsedJWT := strings.Split(string, " ")

	if len(parsedJWT) == 2 {
		if parsedJWT[0] == "Bearer" {
			return parsedJWT[1]
		} else {
			return c.JSON(NewError("You are not authorized to access this resource"))
		}
	} else {
		return c.JSON(NewError("You are not authorized to access this resource"))
	}
}

func AuthRequired(c *fiber.Ctx) error {
	token := ValidateJWT(c)

	if token == false {
		return c.Status(401).JSON(NewError("You are not authorized to access this resource"))
	}

	return c.Next()
}

func GetUser(c *fiber.Ctx) interface{} {
	token := ValidateJWT(c)

	if token == false {
		return c.Status(401).JSON(NewError("You are not authorized to access this resource"))
	}

	db := c.Locals("db").(*mongo.Client)
	users := db.Database("TopicBots").Collection("usersDB1")

	var result types.User

	err := users.FindOne(context.Background(), bson.M{"access_token": token}).Decode(&result)

	if err != nil {
		return c.Status(401).JSON(NewError("You are not authorized to access this resource"))
	}
	return result
}

func GetUserID(c *fiber.Ctx) string {
	token := ValidateJWT(c)

	if token == false {
		return ""
	}

	db := c.Locals("db").(*mongo.Client)
	users := db.Database("TopicBots").Collection("usersDB1")

	var result types.User

	err := users.FindOne(context.Background(), bson.M{"access_token": token}).Decode(&result)

	if err != nil {
		return ""
	}

	return result.ID
}

func GetDetailedUser(c *fiber.Ctx) types.User {
	token := ValidateJWT(c)

	if token == false {
		return types.User{}
	}

	db := c.Locals("db").(*mongo.Client)
	users := db.Database("TopicBots").Collection("usersDB1")

	var result types.User

	err := users.FindOne(context.Background(), bson.M{"access_token": token}).Decode(&result)

	if err != nil {
		return types.User{}
	}

	return result
}
