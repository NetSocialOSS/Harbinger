package database

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgtype"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/redis/go-redis/v9"
)

const DBContextKey = "db"
const RedisContextKey = "redis"
const backupFileNameFormat = "PGDBDUMP_SEEDY_%s.sql"

type Database struct {
	Postgres *pgxpool.Pool
	Redis    *redis.Client
}

func Connect(postgresURL, redisURL, seedDir, backupDir string) (*Database, error) {
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

	log.Println("[Harbinger] connected to PostgreSQL")

	if backupDir != "" {
		log.Printf("[Harbinger] Initiating database backup to %s folder...", backupDir)
		if err := backupDatabase(postgresURL, backupDir); err != nil {
			log.Printf("[Harbinger] Warning: Unable to make DB backup. Proceeding with Seedey without backup: %v", err)
		} else {
			log.Println("[Harbinger] Database backup complete.")
		}
	} else {
		log.Println("[Harbinger] No backup directory specified. Skipping database backup.")
	}

	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Printf("[Harbinger] unable to parse Redis URL: %v", err)
		pgPool.Close()
		return nil, fmt.Errorf("unable to parse Redis URL: %v", err)
	}

	redisClient := redis.NewClient(opt)
	_, err = redisClient.Ping(context.Background()).Result()
	if err != nil {
		log.Printf("[Harbinger] unable to connect to Redis: %v", err)
		pgPool.Close()
		return nil, fmt.Errorf("unable to connect to Redis: %v", err)
	}

	log.Println("[Harbinger] connected to Redis")
	log.Println("[Harbinger] Initiating seedey sequence...")

	err = Seedey(pgPool, seedDir)
	if err != nil {
		log.Printf("[Seedey] error running seed scripts: %v", err)
	} else {
		log.Println("[Harbinger] Seedey sequence completed.")
	}

	return &Database{
		Postgres: pgPool,
		Redis:    redisClient,
	}, nil
}

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

func Middleware(db *Database) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), DBContextKey, db.Postgres)
			ctx = context.WithValue(ctx, RedisContextKey, db.Redis)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func tableExists(db *pgxpool.Pool, tableName string) (bool, error) {
	query := `SELECT to_regclass($1)`
	var result pgtype.Text
	err := db.QueryRow(context.Background(), query, tableName).Scan(&result)
	if err != nil {
		return false, err
	}
	return result.String != "", nil
}

func typeExists(db *pgxpool.Pool, typeName string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM pg_type WHERE typname = $1)`
	var exists bool
	err := db.QueryRow(context.Background(), query, typeName).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func indexExists(db *pgxpool.Pool, indexName string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM pg_indexes WHERE indexname = $1)`
	var exists bool
	err := db.QueryRow(context.Background(), query, indexName).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func Seedey(db *pgxpool.Pool, seedDir string) error {
	files, err := os.ReadDir(seedDir)
	if err != nil {
		return fmt.Errorf("[Seedey] unable to read seed directory: %v", err)
	}

	objectsToSeed := false
	var seededObjects []string
	var skippedObjects []string

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
					log.Printf("[Seedey] Successfully seeded table: %s", objectName)
				}
			} else {
				skippedObjects = append(skippedObjects, objectName)
				log.Printf("[Seedey] Table already exists, skipping seed: %s", objectName)
			}
			break
		}
	}

	if !usersSQLFound {
		log.Println("[Seedey] Warning: users.sql file not found in seed directory.")
	}

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
				log.Printf("[Seedey] Could not extract object (table, enum, or index) from %s", sqlFilePath)
				continue
			}

			var exists bool
			checkErr := error(nil)
			switch objectType {
			case "table":
				exists, checkErr = tableExists(db, objectName)
			case "enum":
				exists, checkErr = typeExists(db, objectName)
			case "index":
				exists, checkErr = indexExists(db, objectName)
			default:
				log.Printf("[Seedey] Unsupported object type '%s' in %s. Skipping.", objectType, sqlFilePath)
				continue
			}

			if checkErr != nil {
				log.Printf("[Seedey] Error checking existence for %s '%s': %v. Skipping %s.", objectType, objectName, checkErr, file.Name())
				continue
			}

			if !exists {
				log.Printf("[Seedey] Running seed script for %s %s from %s", objectType, objectName, sqlFilePath)
				_, err := db.Exec(context.Background(), string(sqlContent))
				if err != nil {
					log.Printf("[Seedey] Error executing seed script for %s %s (%s): %v", objectType, objectName, file.Name(), err)
				} else {
					objectsToSeed = true
					seededObjects = append(seededObjects, objectName)
					log.Printf("[Seedey] Successfully seeded %s: %s", objectType, objectName)
				}
			} else {
				skippedObjects = append(skippedObjects, objectName)
				log.Printf("[Seedey] %s already exists, skipping seed: %s", objectType, objectName)
			}
		}
	}

	if objectsToSeed {
		log.Printf("[Seedey] Seeding complete. Objects seeded: %v", seededObjects)
	} else {
		if len(skippedObjects) > 0 || !usersSQLFound {
			log.Printf("[Seedey] No new objects needed seeding. Objects checked/skipped: %v", skippedObjects)
		} else {
			log.Println("[Seedey] No seed files processed.")
		}
	}

	return nil
}

func getObjectFromSQL(sqlContent string) (objectType string, objectName string) {
	lines := strings.Split(sqlContent, "\n")
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		upperLine := strings.ToUpper(trimmedLine)

		if strings.HasPrefix(trimmedLine, "--") || trimmedLine == "" {
			continue
		}

		if strings.HasPrefix(upperLine, "CREATE TABLE") {
			parts := strings.Fields(trimmedLine)
			if len(parts) >= 3 {
				name := parts[2]
				name = strings.Trim(name, `"`)
				if parts := strings.Split(name, "."); len(parts) > 1 {
					name = parts[len(parts)-1]
				}
				name = strings.TrimSuffix(name, ";")
				return "table", name
			}
		} else if strings.HasPrefix(upperLine, "CREATE TYPE") && strings.Contains(upperLine, "AS ENUM") {
			parts := strings.Fields(trimmedLine)
			if len(parts) >= 3 {
				name := parts[2]
				name = strings.Trim(name, `"`)
				if parts := strings.Split(name, "."); len(parts) > 1 {
					name = parts[len(parts)-1]
				}
				name = strings.TrimSuffix(name, ";")
				return "enum", name
			}
		} else if strings.HasPrefix(upperLine, "CREATE UNIQUE INDEX") {
			parts := strings.Fields(trimmedLine)
			if len(parts) >= 4 && strings.ToUpper(parts[2]) == "INDEX" {
				name := parts[3]
				name = strings.Trim(name, `"`)
				name = strings.TrimSuffix(name, ";")
				return "index", name
			} else if len(parts) >= 3 {
				log.Printf("[Seedey] Warning: Complex CREATE INDEX statement in %s. Heuristic name extraction.", trimmedLine)
				name := parts[2]
				name = strings.Trim(name, `"`)
				name = strings.TrimSuffix(name, ";")
				if strings.ToUpper(parts[1]) == "UNIQUE" {
					if len(parts) >= 4 {
						name = parts[3]
						name = strings.Trim(name, `"`)
						name = strings.TrimSuffix(name, ";")
					}
				}
				return "index", name
			}
		} else if strings.HasPrefix(upperLine, "CREATE INDEX") {
			parts := strings.Fields(trimmedLine)
			if len(parts) >= 3 {
				name := parts[2]
				name = strings.Trim(name, `"`)
				name = strings.TrimSuffix(name, ";")
				return "index", name
			}
		}
	}
	return "", ""
}

func backupDatabase(postgresURL, backupDir string) error {
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory %s: %v", backupDir, err)
	}

	dateStr := time.Now().Format("2006-01-02")
	fileName := fmt.Sprintf(backupFileNameFormat, dateStr)
	backupFilePath := filepath.Join(backupDir, fileName)

	if _, err := os.Stat(backupFilePath); err == nil {
		log.Printf("[Harbinger] Backup file for today (%s) already exists: %s. Skipping backup.", dateStr, backupFilePath)
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("error checking for existing backup file %s: %v", backupFilePath, err)
	}

	parsedURL, err := url.Parse(postgresURL)
	if err != nil {
		return fmt.Errorf("failed to parse postgres URL for backup: %v", err)
	}

	dbName := strings.TrimPrefix(parsedURL.Path, "/")
	if dbName == "" {
		return fmt.Errorf("database name not found in postgres URL path: %s", postgresURL)
	}

	cmd := exec.Command("pg_dump", "-F", "p", "-f", backupFilePath, dbName)

	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, fmt.Sprintf("PGHOST=%s", parsedURL.Hostname()))
	if parsedURL.Port() != "" {
		cmd.Env = append(cmd.Env, fmt.Sprintf("PGPORT=%s", parsedURL.Port()))
	}
	if parsedURL.User != nil {
		cmd.Env = append(cmd.Env, fmt.Sprintf("PGUSER=%s", parsedURL.User.Username()))
		if password, ok := parsedURL.User.Password(); ok {
			cmd.Env = append(cmd.Env, fmt.Sprintf("PGPASSWORD=%s", password))
		}
	}

	log.Printf("[Harbinger] Running pg_dump command: %s", cmd.String())

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pg_dump command failed: %v. Output:\n%s", err, string(output))
	}

	log.Printf("[Harbinger] Successfully created backup: %s", backupFilePath)
	return nil
}
