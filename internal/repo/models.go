package repo

import (
	"time"
	"gorm.io/gorm"
)

// User represents an admin user
type User struct {
	ID        uint           `gorm:"primaryKey" json:"id"`
	Username  string         `gorm:"uniqueIndex;not null" json:"username"`
	Password  string         `gorm:"not null" json:"-"`
	IsAdmin   bool           `gorm:"default:false" json:"is_admin"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// Client represents an infected agent
type Client struct {
	ID          string    `gorm:"primaryKey" json:"id"`
	Hostname    string    `json:"hostname"`
	Username    string    `json:"username"`
	OS          string    `json:"os"`
	IP          string    `json:"ip"`
	IsAdmin     bool      `json:"is_admin"`
	Version     string    `json:"version"`
	Fingerprint string    `gorm:"index" json:"fingerprint"`
	FirstSeen   time.Time `json:"first_seen"`
	// composite index for background worker queries
	LastSeen time.Time `gorm:"index:idx_client_status" json:"last_seen"`
	Online   bool      `gorm:"default:true;index:idx_client_status" json:"online"`
}

// Task represents a command sent to a client
type Task struct {
	ID       string `gorm:"primaryKey" json:"id"`
	// composite index: beacon queries always filter by (client_id, status)
	ClientID  string    `gorm:"not null;index:idx_task_delivery" json:"client_id"`
	Status    string    `gorm:"default:'pending';index:idx_task_delivery" json:"status"`
	Command   string    `gorm:"type:text" json:"cmd"`
	CreatedAt time.Time `json:"created_at"`
}

// Result represents the output from a task
type Result struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	ClientID  string    `gorm:"index;not null" json:"client_id"`
	TaskID    string    `gorm:"index" json:"task_id"`
	Type      string    `json:"type"`
	Data      string    `gorm:"type:text" json:"data"`
	CreatedAt time.Time `json:"created_at"`
}

// Log represents a system event
type Log struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

// Ban represents a banned IP address
type Ban struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	IP        string    `gorm:"uniqueIndex;not null" json:"ip"`
	Reason    string    `json:"reason"`
	Until     time.Time `json:"until"`
	BannedBy  string    `json:"banned_by"`
	CreatedAt time.Time `json:"created_at"`
}

// BuildToken represents a one-time token generated during agent build
type BuildToken struct {
	Token     string    `gorm:"primaryKey" json:"token"`
	UsedAt    *time.Time `json:"used_at"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}
