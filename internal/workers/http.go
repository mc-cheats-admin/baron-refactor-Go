package workers

import (
	"fmt"
	"net/http"
	"time"
)

type httpClient struct {
	timeout time.Duration
}

func (c *httpClient) ping(url string) error {
	client := &http.Client{Timeout: c.timeout}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	return nil
}
