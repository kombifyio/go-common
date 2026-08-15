package toolauth

import (
	"testing"
	"time"
)

func TestTokenPair_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "token not expired (1 hour in the future)",
			expiresAt: time.Now().Add(1 * time.Hour),
			want:      false,
		},
		{
			name:      "token expired (1 hour in the past)",
			expiresAt: time.Now().Add(-1 * time.Hour),
			want:      true,
		},
		{
			name:      "token expired (exactly now, within 30s buffer)",
			expiresAt: time.Now(),
			want:      true,
		},
		{
			name:      "token within 30s buffer is considered expired",
			expiresAt: time.Now().Add(29 * time.Second),
			want:      true,
		},
		{
			name:      "token just outside 30s buffer is not expired",
			expiresAt: time.Now().Add(31 * time.Second),
			want:      false,
		},
		{
			name:      "token with zero time is expired",
			expiresAt: time.Time{},
			want:      true,
		},
		{
			name:      "token far in the future is not expired",
			expiresAt: time.Now().Add(24 * 365 * time.Hour),
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp := &TokenPair{
				AccessToken:  "test-access",
				RefreshToken: "test-refresh",
				ExpiresAt:    tt.expiresAt,
				UserID:       "usr-123",
			}
			got := tp.IsExpired()
			if got != tt.want {
				t.Errorf("IsExpired() = %v, want %v (expiresAt=%v, now=%v)",
					got, tt.want, tt.expiresAt, time.Now())
			}
		})
	}
}
