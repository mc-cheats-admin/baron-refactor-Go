package workers

import (
	"runtime"
	"time"

	"baron-c2/internal/repo"
	"github.com/rs/zerolog/log"
)

// StartTaskCleaner runs a background goroutine that deletes stale pending tasks.
// Tasks older than 24h that were never delivered are considered abandoned.
func StartTaskCleaner() {
	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			cutoff := time.Now().Add(-24 * time.Hour)
			result := repo.DB.
				Where("status = ? AND created_at < ?", "pending", cutoff).
				Delete(&repo.Task{})
			if result.Error != nil {
				log.Error().Err(result.Error).Msg("task cleaner: db error")
			} else if result.RowsAffected > 0 {
				log.Info().Int64("deleted", result.RowsAffected).Msg("task cleaner: removed stale tasks")
			}
		}
	}()
}

// StartOfflineWorker marks agents offline if no beacon for >2 minutes.
func StartOfflineWorker() {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			cutoff := time.Now().Add(-2 * time.Minute)
			repo.DB.Model(&repo.Client{}).
				Where("last_seen < ? AND online = ?", cutoff, true).
				Update("online", false)
		}
	}()
}

// StartMetricsLogger periodically logs Go runtime stats for observability.
func StartMetricsLogger() {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			log.Info().
				Int("goroutines", runtime.NumGoroutine()).
				Uint64("heap_alloc_mb", ms.HeapAlloc/1024/1024).
				Uint64("sys_mb", ms.Sys/1024/1024).
				Uint32("gc_cycles", ms.NumGC).
				Msg("runtime metrics")
		}
	}()
}

// StartKeepAlive pings the server's own ping endpoint to keep Render alive.
func StartKeepAlive(serverURL string) {
	if serverURL == "" {
		return
	}
	client := &httpClient{timeout: 10 * time.Second}
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if err := client.ping(serverURL + "/api/ping"); err != nil {
				log.Warn().Err(err).Msg("keep-alive ping failed")
			} else {
				log.Debug().Str("url", serverURL).Msg("keep-alive ping ok")
			}
		}
	}()
}
