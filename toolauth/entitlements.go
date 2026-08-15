package toolauth

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// GetEntitlements fetches the tool entitlements for the authenticated user.
// Results are cached for 24 hours. Use InvalidateEntitlementCache to force
// a fresh fetch.
func (c *Client) GetEntitlements(ctx context.Context) (*Entitlements, error) {
	c.entMu.RLock()
	ent := c.entitlements
	stale := time.Since(c.entFetchedAt) > entitlementCacheTTL
	c.entMu.RUnlock()

	if ent != nil && !stale {
		return ent, nil
	}

	accessToken, err := c.GetAccessToken(ctx)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/api/v1/tools/entitlements?tool=%s", c.cfg.BaseURL, c.cfg.ToolName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("toolauth: create entitlements request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	c.setUserAgent(req)

	var resp Entitlements
	if err := c.doJSON(req, &resp); err != nil {
		return nil, fmt.Errorf("toolauth: fetch entitlements: %w", err)
	}

	c.entMu.Lock()
	c.entitlements = &resp
	c.entFetchedAt = time.Now()
	c.entMu.Unlock()

	return &resp, nil
}

// HasFeature checks whether the authenticated user has the named feature
// enabled for this tool. The entitlement cache is used if fresh, otherwise
// a fetch is triggered.
func (c *Client) HasFeature(ctx context.Context, feature string) (bool, error) {
	ent, err := c.GetEntitlements(ctx)
	if err != nil {
		return false, err
	}
	if ent.Features == nil {
		return false, nil
	}
	val, ok := ent.Features[feature]
	if !ok {
		return false, nil
	}
	// A feature is considered enabled if it is present and truthy.
	switch v := val.(type) {
	case bool:
		return v, nil
	case nil:
		return false, nil
	default:
		// Any non-nil, non-bool value means the feature is present (enabled).
		return true, nil
	}
}

// GetFeatureValue returns the raw value of a feature from the entitlements.
// Returns nil, nil if the feature does not exist.
func (c *Client) GetFeatureValue(ctx context.Context, feature string) (any, error) {
	ent, err := c.GetEntitlements(ctx)
	if err != nil {
		return nil, err
	}
	if ent.Features == nil {
		return nil, nil
	}
	val, ok := ent.Features[feature]
	if !ok {
		return nil, nil
	}
	return val, nil
}

// InvalidateEntitlementCache clears the cached entitlements so the next call
// to GetEntitlements, HasFeature, or GetFeatureValue triggers a fresh fetch.
func (c *Client) InvalidateEntitlementCache() {
	c.entMu.Lock()
	c.entitlements = nil
	c.entFetchedAt = time.Time{}
	c.entMu.Unlock()
}
