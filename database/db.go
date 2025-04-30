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
				log.Printf("[Seedey] Running seed script for %s %s from %s", objectType, objectName, sqlFilePath)
				_, err := db.Exec(context.Background(), string(sqlContent))
				if err != nil {
					return fmt.Errorf("[Seedey] Error executing seed script for %s %s: %v", objectType, objectName, err)
				}
			} else {
				if objectType == "table" {
					log.Printf("[Seedey] Table exists: %s. Checking for schema updates...", objectName)
					if err := updateExistingTableStructure(db, objectName, string(sqlContent)); err != nil {
						log.Printf("[Seedey] Warning: Schema update failed for %s: %v", objectName, err)
					}
				} else {
					log.Printf("[Seedey] %s '%s' exists. Skipping schema updates.", strings.Title(objectType), objectName)
				}
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
				log.Printf("[Seedey] Running seed script for table %s from %s", objectName, sqlFilePath)
				_, err := db.Exec(context.Background(), string(sqlContent))
				if err != nil {
					return fmt.Errorf("[Seedey] Error executing seed script for users: %v", err)
				}
			} else {
				log.Printf("[Seedey] Table exists: %s. Checking for schema updates...", objectName)
				if err := updateExistingTableStructure(db, objectName, string(sqlContent)); err != nil {
					log.Printf("[Seedey] Warning: Schema update failed for %s: %v", objectName, err)
				}
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

func backupDatabase(postgresURL, backupDir string) error {
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory %s: %v", backupDir, err)
	}

	// Format the date and time for the filename
	datetimeStr := time.Now().Format("2006-01-02_15-04-05")
	fileName := fmt.Sprintf("PGDBDUMP_SEEDY_%s.sql", datetimeStr)
	backupFilePath := filepath.Join(backupDir, fileName)

	if _, err := os.Stat(backupFilePath); err == nil {
		log.Printf("[Harbinger] Backup file for this timestamp (%s) already exists: %s. Skipping backup.", datetimeStr, backupFilePath)
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
		if strings.Contains(err.Error(), "executable file not found") {
			log.Printf("[Harbinger] Warning: pg_dump command failed: %v. Output:\n%s", err, string(output))
			return nil // Ignore the error and continue
		}
		return fmt.Errorf("pg_dump command failed: %v. Output:\n%s", err, string(output))
	}

	log.Printf("[Harbinger] Successfully created backup: %s", backupFilePath)
	return nil
}

func updateExistingTableStructure(db *pgxpool.Pool, tableName, sqlContent string) error {
	type colInfo struct {
		name     string
		dataType string
		nullable string
		defValue *string
	}
	existingCols := make(map[string]colInfo)

	// Fetch existing column info
	rows, err := db.Query(context.Background(), `
			SELECT column_name, data_type, is_nullable, column_default
			FROM information_schema.columns
			WHERE table_name = $1
			ORDER BY ordinal_position`, tableName)
	if err != nil {
		return fmt.Errorf("failed to fetch schema: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var c colInfo
		if err := rows.Scan(&c.name, &c.dataType, &c.nullable, &c.defValue); err != nil {
			return fmt.Errorf("scan error: %w", err)
		}
		existingCols[c.name] = c
	}

	var pendingChecks []string
	inTable := false

	for _, rawLine := range strings.Split(sqlContent, "\n") {
		line := strings.TrimSpace(rawLine)
		upLine := strings.ToUpper(line)

		if strings.HasPrefix(upLine, "CREATE TABLE") {
			inTable = true
			continue
		}
		if !inTable || line == "" || strings.HasPrefix(line, ")") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		colName := strings.Trim(parts[0], `"`)
		targetType := strings.ToLower(strings.TrimSuffix(parts[1], ","))
		nullable := !strings.Contains(upLine, "NOT NULL")

		// Parse DEFAULT and CHECK constraints
		var defaultVal *string
		if idx := strings.Index(upLine, "DEFAULT"); idx != -1 {
			defaultPart := strings.Split(line[idx+7:], " ")[0]
			defaultPart = strings.Trim(defaultPart, ",;")
			if defaultPart != "" {
				defaultVal = &defaultPart
			}
		}

		// Handle CHECK constraints
		if chkIdx := strings.Index(upLine, "CHECK"); chkIdx != -1 {
			constraintBody := strings.TrimSpace(line[chkIdx+5:])
			constraintBody = strings.TrimSuffix(constraintBody, ",")
			constraintBody = strings.TrimSuffix(constraintBody, ";")
			constraintName := fmt.Sprintf("%s_%s_check", tableName, colName)

			// Check if the constraint already exists
			exists, err := constraintExists(db, tableName, constraintName)
			if err != nil {
				return fmt.Errorf("failed to check constraint existence: %w", err)
			}
			if !exists {
				pendingChecks = append(pendingChecks, fmt.Sprintf(
					"ADD CONSTRAINT %s CHECK %s",
					constraintName, constraintBody,
				))
			}
		}

		existing, exists := existingCols[colName]
		if !exists {
			continue
		}

		// Modify the type conversion block to handle jsonb
		if existing.dataType != targetType {
			if targetType == "uuid" || targetType == "jsonb" {
				conversionSQL := fmt.Sprintf(`
									DO $$
									BEGIN
											BEGIN
													ALTER TABLE "%s" ALTER COLUMN "%s" TYPE %s USING "%s"::%s;
											EXCEPTION WHEN others THEN
													RAISE NOTICE 'Skipping %s conversion for %s.%s';
											END;
									END $$;`,
					tableName, colName, targetType, colName, targetType,
					targetType, tableName, colName)
				if _, err := db.Exec(context.Background(), conversionSQL); err != nil {
					return fmt.Errorf("%s conversion failed: %w", targetType, err)
				}
			} else {
				alterSQL := fmt.Sprintf(
					`ALTER TABLE "%s" ALTER COLUMN "%s" TYPE %s`,
					tableName, colName, targetType,
				)
				if _, err := db.Exec(context.Background(), alterSQL); err != nil {
					return fmt.Errorf("type change failed: %w", err)
				}
			}
		}

		// Nullability
		if (existing.nullable == "YES" && !nullable) ||
			(existing.nullable == "NO" && nullable) {
			verb := "SET"
			if nullable {
				verb = "DROP"
			}
			alterSQL := fmt.Sprintf(
				`ALTER TABLE "%s" ALTER COLUMN "%s" %s NOT NULL`,
				tableName, colName, verb,
			)
			if _, err := db.Exec(context.Background(), alterSQL); err != nil {
				return fmt.Errorf("nullability change failed: %w", err)
			}
		}

		// Default values
		if (defaultVal != nil && existing.defValue == nil) ||
			(defaultVal != nil && *defaultVal != *existing.defValue) {
			alterSQL := fmt.Sprintf(
				`ALTER TABLE "%s" ALTER COLUMN "%s" SET DEFAULT %s`,
				tableName, colName, *defaultVal,
			)
			if _, err := db.Exec(context.Background(), alterSQL); err != nil {
				return fmt.Errorf("default change failed: %w", err)
			}
		}
	}

	// Apply pending CHECK constraints
	if len(pendingChecks) > 0 {
		alterSQL := fmt.Sprintf(
			`ALTER TABLE "%s" %s`,
			tableName, strings.Join(pendingChecks, ", "),
		)
		if _, err := db.Exec(context.Background(), alterSQL); err != nil {
			return fmt.Errorf("check constraints failed: %w", err)
		}
	}

	return nil
}

func constraintExists(db *pgxpool.Pool, tableName, constraintName string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM information_schema.table_constraints WHERE table_name = $1 AND constraint_name = $2)`
	var exists bool
	err := db.QueryRow(context.Background(), query, tableName, constraintName).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func getObjectFromSQL(sqlContent string) (string, string) {
	lines := strings.Split(sqlContent, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") || trimmed == "" {
			continue
		}

		upper := strings.ToUpper(trimmed)
		switch {
		case strings.HasPrefix(upper, "CREATE TABLE"):
			return extractTableName(trimmed)
		case strings.HasPrefix(upper, "CREATE TYPE") && strings.Contains(upper, "ENUM"):
			return extractTypeName(trimmed)
		case strings.Contains(upper, "CREATE INDEX"):
			return extractIndexName(trimmed)
		}
	}
	return "", ""
}

func extractTableName(line string) (string, string) {
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return "", ""
	}
	name := strings.Trim(parts[2], `"`)
	return "table", strings.TrimSuffix(name, ";")
}

func extractTypeName(line string) (string, string) {
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return "", ""
	}
	name := strings.Trim(parts[2], `"`)
	return "enum", strings.TrimSuffix(name, ";")
}

func extractIndexName(line string) (string, string) {
	parts := strings.Fields(line)
	for i, p := range parts {
		if strings.EqualFold(p, "INDEX") && i < len(parts)-1 {
			name := strings.Trim(parts[i+1], `"`)
			return "index", strings.TrimSuffix(name, ";")
		}
	}
	return "", ""
}
