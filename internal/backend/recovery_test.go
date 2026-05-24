package backend

import "testing"

func TestRecovery401CandidateFilterRequiresAuthFailureSignal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		file map[string]any
		want bool
	}{
		{
			name: "explicit 401",
			file: map[string]any{
				"status":         "error",
				"status_message": "upstream HTTP 401 unauthorized",
				"unavailable":    true,
			},
			want: true,
		},
		{
			name: "token invalidated authentication error",
			file: map[string]any{
				"status":         "error",
				"status_message": `{"error":{"message":"Your authentication token has been invalidated. Please try signing in again.","type":"authentication_error","code":"auth_unavailable"}}`,
				"unavailable":    true,
			},
			want: true,
		},
		{
			name: "usage limit unavailable is not 401 recovery",
			file: map[string]any{
				"status":         "error",
				"status_message": `{"error":{"type":"usage_limit_reached","message":"The usage limit has been reached","plan_type":"plus"}}`,
				"unavailable":    true,
			},
			want: false,
		},
		{
			name: "stream disconnect unavailable is not 401 recovery",
			file: map[string]any{
				"status":         "error",
				"status_message": "stream error: stream disconnected before completion: stream closed before response.completed",
				"unavailable":    true,
			},
			want: false,
		},
		{
			name: "plain unavailable flag alone is not 401 recovery",
			file: map[string]any{
				"status":      "error",
				"unavailable": true,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isRecovery401AuthFile(tt.file); got != tt.want {
				t.Fatalf("isRecovery401AuthFile() = %v, want %v", got, tt.want)
			}
		})
	}
}
