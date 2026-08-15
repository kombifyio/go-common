package toolauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// usagePayload is the wire format for batched usage events.
type usagePayload struct {
	Tool   string       `json:"tool"`
	Events []UsageEvent `json:"events"`
}

// ReportUsage buffers usage events for asynchronous delivery. Events are held
// in memory until flushed by a UsageReporter. If no UsageReporter is running,
// events accumulate in memory without bound; callers should start a reporter
// for long-lived processes.
func (c *Client) ReportUsage(_ context.Context, events ...UsageEvent) error {
	if len(events) == 0 {
		return nil
	}
	c.usageMu.Lock()
	c.usageBuf = append(c.usageBuf, events...)
	c.usageMu.Unlock()
	return nil
}

// flushUsage sends all buffered usage events to the platform API.
// It is safe to call concurrently. Returns nil if the buffer is empty.
func (c *Client) flushUsage(ctx context.Context) error {
	c.usageMu.Lock()
	if len(c.usageBuf) == 0 {
		c.usageMu.Unlock()
		return nil
	}
	batch := c.usageBuf
	c.usageBuf = nil
	c.usageMu.Unlock()

	accessToken, err := c.GetAccessToken(ctx)
	if err != nil {
		// Put events back so they are not lost.
		c.usageMu.Lock()
		c.usageBuf = append(batch, c.usageBuf...)
		c.usageMu.Unlock()
		return fmt.Errorf("toolauth: get access token for usage flush: %w", err)
	}

	body, err := json.Marshal(usagePayload{
		Tool:   c.cfg.ToolName,
		Events: batch,
	})
	if err != nil {
		return fmt.Errorf("toolauth: marshal usage payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/api/v1/tools/usage", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("toolauth: create usage request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	c.setUserAgent(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Put events back so they can be retried on next flush.
		c.usageMu.Lock()
		c.usageBuf = append(batch, c.usageBuf...)
		c.usageMu.Unlock()
		return fmt.Errorf("toolauth: send usage events: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Put events back for retry.
		c.usageMu.Lock()
		c.usageBuf = append(batch, c.usageBuf...)
		c.usageMu.Unlock()
		return readAPIError(resp)
	}

	return nil
}

// UsageReporter runs a background goroutine that periodically flushes
// buffered usage events to the platform API.
type UsageReporter struct {
	client   *Client
	cancel   context.CancelFunc
	done     chan struct{}
	interval time.Duration
}

// StartUsageReporter starts a background goroutine that flushes usage events
// at the given interval. The reporter runs until Stop is called or the
// provided context is canceled.
func (c *Client) StartUsageReporter(ctx context.Context, flushInterval time.Duration) *UsageReporter {
	ctx, cancel := context.WithCancel(ctx)
	r := &UsageReporter{
		client:   c,
		cancel:   cancel,
		done:     make(chan struct{}),
		interval: flushInterval,
	}
	go r.run(ctx) // #nosec G118 -- reporter owns this derived context (cancel via Stop) and flushes with a bounded shutdown context.
	return r
}

// Stop signals the reporter to flush remaining events and stop.
// It blocks until the final flush completes.
func (r *UsageReporter) Stop() {
	r.cancel()
	<-r.done
}

func (r *UsageReporter) run(ctx context.Context) {
	defer close(r.done)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Final flush with a short deadline so we don't block forever.
			flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = r.client.flushUsage(flushCtx)
			flushCancel()
			return
		case <-ticker.C:
			_ = r.client.flushUsage(ctx)
		}
	}
}
