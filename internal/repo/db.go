package repo

import (
	"log"
	"os"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// InitDB initializes the database connection with a tuned connection pool
func InitDB() {
	var err error
	dsn := os.Getenv("DATABASE_URL")

	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             200 * time.Millisecond,
			LogLevel:                  logger.Warn, // only slow queries and errors
			IgnoreRecordNotFoundError: true,
			Colorful:                  false,
		},
	)

	config := &gorm.Config{
		Logger:                 newLogger,
		PrepareStmt:            true, // cache prepared statements
		SkipDefaultTransaction: true, // skip implicit tx on single writes
	}

	if dsn != "" {
		DB, err = gorm.Open(postgres.Open(dsn), config)
	} else {
		DB, err = gorm.Open(sqlite.Open("baron.db"), config)
	}

	if err != nil {
		log.Fatalf("[DB] Failed to connect: %v", err)
	}

	// Configure connection pool
	sqlDB, err := DB.DB()
	if err != nil {
		log.Fatalf("[DB] Failed to get sql.DB: %v", err)
	}
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)
	sqlDB.SetConnMaxIdleTime(2 * time.Minute)

	// Auto-migrate
	err = DB.AutoMigrate(
		&User{}, &Client{}, &Task{}, &Result{},
		&Log{}, &Ban{}, &BuildToken{},
	)
	if err != nil {
		log.Fatalf("[DB] Migration failed: %v", err)
	}

	log.Println("[DB] Connected and migrated.")
}

// GenerateID creates a new unique string ID
func GenerateID() string {
	return uuid.New().String()
}

// Ping checks database connectivity
func Ping() error {
	sqlDB, err := DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}
