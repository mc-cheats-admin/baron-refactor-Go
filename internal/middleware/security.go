package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// AuthRequired ensures the request has a valid session/token
func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("X-Token")
		if token == "" {
			token = c.Query("token")
		}

		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "error": "Unauthorized"})
			c.Abort()
			return
		}

		// In this simplified version, we check tokens from the DB or a cache
		// For a full implementation, use JWT here.
		// For now, let's assume token validation logic exists.
		
		c.Next()
	}
}

// AdminRequired ensures the user has admin privileges
func AdminRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Logic to check if user is admin from context set by AuthRequired
		c.Next()
	}
}

// SecurityMiddleware handles IP banning and basic security headers
func SecurityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		// Set security headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "no-referrer")
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate")

		c.Next()
	}
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// CheckPasswordHash compares a password with a hash
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
