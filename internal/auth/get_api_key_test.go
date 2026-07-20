package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantKey    string
		wantErr    error
		wantErrMsg string
	}{
		{
			name:    "no authorization header",
			headers: http.Header{},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header - missing ApiKey prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer sometoken"},
			},
			wantErrMsg: "malformed authorization header",
		},
		{
			name: "malformed header - no key provided",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantErrMsg: "malformed authorization header",
		},
		{
			name: "valid authorization header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			wantKey: "my-secret-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if tt.wantErrMsg != "" {
				if err == nil || err.Error() != tt.wantErrMsg {
					t.Errorf("expected error message %q, got %v", tt.wantErrMsg, err)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if key != tt.wantKey {
				t.Errorf("expected key %q, got %q", tt.wantKey, key)
			}
		})
	}
}
