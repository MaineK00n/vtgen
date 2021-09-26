package util

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/mattn/go-sqlite3"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func NewDB(dbPath string) (*gorm.DB, error) {
	db, locked, err := openDB(dbPath)
	if err != nil {
		if locked {
			err = fmt.Errorf("SQLite3: %s is locked: %w", dbPath, err)
		}
		return nil, fmt.Errorf("failed to new DB: %w", err)
	}
	return db, nil
}

func openDB(dbPath string) (*gorm.DB, bool, error) {
	gormConfig := gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger: logger.New(
			log.New(os.Stderr, "\r\n", log.LstdFlags),
			logger.Config{
				SlowThreshold:             time.Second,
				LogLevel:                  logger.Warn,
				IgnoreRecordNotFoundError: false,
				Colorful:                  true,
			},
		),
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gormConfig)
	if err != nil {
		msg := fmt.Sprintf("failed to open DB. dbPath: %s", dbPath)
		switch err.(sqlite3.Error).Code {
		case sqlite3.ErrLocked, sqlite3.ErrBusy:
			return nil, true, fmt.Errorf("%s: %w", msg, err)
		}
		return nil, false, fmt.Errorf("%s: %w", msg, err)
	}

	db.Exec("PRAGMA foreign_keys = ON")
	return db, false, nil
}

func CloseDB(db *gorm.DB) error {
	if db == nil {
		return nil
	}

	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get DB Object: %w", err)
	}
	if err := sqlDB.Close(); err != nil {
		return fmt.Errorf("failed to close DB: %w", err)
	}
	return nil
}
