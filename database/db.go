package database

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/redis/go-redis/v9"
)

const DBContextKey = "db"
const RedisContextKey = "redis"

type Database struct {
	Postgres *pgxpool.Pool
	Redis    *redis.Client
}

// Connect to PostgreSQL and Redis databases
func Connect(postgresURL, redisURL, seedDir string) (*Database, error) {
	// PostgreSQL Connection
	pgConfig, err := pgxpool.ParseConfig(postgresURL)
	if err != nil {
		log.Printf("[Harbinger] unable to parse PostgreSQL URL: %v", err)
		return nil, fmt.Errorf("unable to parse PostgreSQL URL: %v", err)
	}
	pgPool, err := pgxpool.ConnectConfig(context.Background(), pgConfig)
	if err != nil {
		log.Printf("[Harbinger] unable to connect to PostgreSQL: %v", err)
		return nil, fmt.Errorf("unable to connect to PostgreSQL: %v", err)
	}

	// Redis Connection
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Printf("[Harbinger] unable to parse Redis URL: %v", err)
		return nil, fmt.Errorf("unable to parse Redis URL: %v", err)
	}

	redisClient := redis.NewClient(opt)
	_, err = redisClient.Ping(context.Background()).Result()
	if err != nil {
		log.Printf("[Harbinger] unable to connect to Redis: %v", err)
		return nil, fmt.Errorf("unable to connect to Redis: %v", err)
	}

	log.Println("[Harbinger] connected to PostgreSQL")
	log.Println("[Harbinger] connected to Redis")
	log.Println("[Harbinger] Initiating seedey sequence...")

	// Apply seed scripts
	err = Seedey(pgPool, seedDir)
	if err != nil {
		log.Printf("[Seedey] error running seed scripts: %v", err)
	}

	return &Database{
		Postgres: pgPool,
		Redis:    redisClient,
	}, nil
}

// Disconnect from PostgreSQL and Redis
func Disconnect(db *Database) {
	if db.Postgres != nil {
		db.Postgres.Close()
		log.Println("[Gracey] disconnected from PostgreSQL")
	}
	if db.Redis != nil {
		err := db.Redis.Close()
		if err != nil {
			log.Printf("[Gracey] error closing Redis connection: %v", err)
		} else {
			log.Println("[Gracey] disconnected from Redis")
		}
	}
}

// Middleware to add database connections to context
func Middleware(db *Database) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), DBContextKey, db.Postgres)
			ctx = context.WithValue(ctx, RedisContextKey, db.Redis)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Check if a table exists in the database
func tableExists(db *pgxpool.Pool, tableName string) (bool, error) {
	query := `SELECT to_regclass($1)`
	var result pgtype.Text
	err := db.QueryRow(context.Background(), query, tableName).Scan(&result)
	if err != nil {
		return false, err
	}
	return result.String != "", nil
}

// Check if a type exists in the database
func typeExists(db *pgxpool.Pool, typeName string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM pg_type WHERE typname = $1)`
	var exists bool
	err := db.QueryRow(context.Background(), query, typeName).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// Check if an index exists in the database
func indexExists(db *pgxpool.Pool, indexName string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM pg_indexes WHERE indexname = $1)`
	var exists bool
	err := db.QueryRow(context.Background(), query, indexName).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

// Run Seed to check and apply any missing seed files
func Seedey(db *pgxpool.Pool, seedDir string) error {
	files, err := os.ReadDir(seedDir)
	if err != nil {
		return fmt.Errorf("[Seedey] unable to read seed directory: %v", err)
	}

	objectsToSeed := false
	var seededObjects []string
	var skippedObjects []string

	// Ensure users.sql is processed first
	usersSQLFound := false
	for _, file := range files {
		if file.Name() == "users.sql" {
			usersSQLFound = true
			sqlFilePath := filepath.Join(seedDir, file.Name())
			sqlContent, err := os.ReadFile(sqlFilePath)
			if err != nil {
				return fmt.Errorf("[Seedey] Error reading users.sql: %v", err)
			}

			objectType, objectName := getObjectFromSQL(string(sqlContent))
			if objectName == "" {
				return fmt.Errorf("[Seedey] Could not extract object from users.sql")
			}
			if objectType != "table" {
				return fmt.Errorf("[Seedey] users.sql must create a table")
			}

			exists, err := tableExists(db, objectName)
			if err != nil {
				return fmt.Errorf("[Seedey] Error checking table existence for users: %v", err)
			}

			if !exists {
				log.Printf("[Seedey] Running seed script for table %s from %s", objectName, sqlFilePath)
				_, err := db.Exec(context.Background(), string(sqlContent))
				if err != nil {
					return fmt.Errorf("[Seedey] Error executing seed script for users: %v", err)
				} else {
					objectsToSeed = true
					seededObjects = append(seededObjects, objectName)
				}
			} else {
				skippedObjects = append(skippedObjects, objectName)
			}
			break
		}
	}

	if !usersSQLFound {
		return fmt.Errorf("[Seedey] users.sql file not found in seed directory")
	}

	// Process remaining seed files
	for _, file := range files {
		if file.Name() == "users.sql" {
			continue
		}
		if strings.HasSuffix(file.Name(), ".sql") {
			sqlFilePath := filepath.Join(seedDir, file.Name())
			sqlContent, err := os.ReadFile(sqlFilePath)
			if err != nil {
				log.Printf("[Seedey] Error reading file %s: %v", sqlFilePath, err)
				continue
			}

			objectType, objectName := getObjectFromSQL(string(sqlContent))
			if objectName == "" {
				log.Printf("[Seedey] Could not extract object from %s", sqlFilePath)
				continue
			}

			var exists bool
			switch objectType {
			case "table":
				exists, err = tableExists(db, objectName)
			case "enum":
				exists, err = typeExists(db, objectName)
			case "index":
				exists, err = indexExists(db, objectName)
			default:
				log.Printf("[Seedey] Unsupported object type %s in %s", objectType, sqlFilePath)
				continue
			}

			if err != nil {
				log.Printf("[Seedey] Error checking existence for %s %s: %v", objectType, objectName, err)
				continue
			}

			if !exists {
				log.Printf("[Seedey] Running seed script for %s %s from %s", objectType, objectName, sqlFilePath)
				_, err := db.Exec(context.Background(), string(sqlContent))
				if err != nil {
					log.Printf("[Seedey] Error executing seed script for %s %s: %v", objectType, objectName, err)
				} else {
					objectsToSeed = true
					seededObjects = append(seededObjects, objectName)
				}
			} else {
				skippedObjects = append(skippedObjects, objectName)
			}
		}
	}

	if objectsToSeed {
		log.Printf("[Seedey] Seeding complete. Objects seeded: %v", seededObjects)
	} else {
		if len(skippedObjects) > 0 {
			log.Printf("[Seedey] No need for seeding. All objects are up-to-date.")
		}
	}

	return nil
}

// Extract the object type and name from SQL content
func getObjectFromSQL(sqlContent string) (objectType string, objectName string) {
	lines := strings.Split(sqlContent, "\n")
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		upperLine := strings.ToUpper(trimmedLine)

		// Check for CREATE TABLE
		if strings.HasPrefix(upperLine, "CREATE TABLE") {
			parts := strings.Fields(trimmedLine)
			if len(parts) >= 3 {
				return "table", parts[2]
			}
			// Check for CREATE TYPE as ENUM
		} else if strings.HasPrefix(upperLine, "CREATE TYPE") && strings.Contains(upperLine, "AS ENUM") {
			parts := strings.Fields(trimmedLine)
			if len(parts) >= 3 {
				return "enum", parts[2]
			}
			// Check for CREATE INDEX
		} else if strings.HasPrefix(upperLine, "CREATE INDEX") {
			parts := strings.Fields(trimmedLine)
			if len(parts) >= 3 {
				return "index", parts[2]
			}
		}
	}
	return "", ""
}
