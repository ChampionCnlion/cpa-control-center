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

func TestRecovery401CandidateDetectionPrefersLiveProbe(t *testing.T) {
	t.Parallel()

	auth401 := map[string]any{
		"name":           "stale-401.codex.json",
		"status":         "error",
		"status_message": "upstream HTTP 401 unauthorized",
	}

	tests := []struct {
		name       string
		file       map[string]any
		probe      UsageProbeResult
		wantSource string
		wantOK     bool
	}{
		{
			name: "live 401 is candidate",
			file: map[string]any{"name": "live-401.codex.json", "status": "ok"},
			probe: UsageProbeResult{Record: AccountRecord{
				Name:          "live-401.codex.json",
				StateKey:      stateInvalid401,
				APIStatusCode: intPtr(401),
			}},
			wantSource: "usage_probe",
			wantOK:     true,
		},
		{
			name: "live quota limited excludes stale auth 401",
			file: auth401,
			probe: UsageProbeResult{Record: AccountRecord{
				Name:           "stale-401.codex.json",
				StateKey:       stateQuotaLimited,
				APIStatusCode:  intPtr(401),
				ProbeErrorKind: "usage_limit_reached",
			}},
			wantOK: false,
		},
		{
			name: "live normal excludes stale auth 401",
			file: auth401,
			probe: UsageProbeResult{Record: AccountRecord{
				Name:          "stale-401.codex.json",
				StateKey:      stateNormal,
				APIStatusCode: intPtr(200),
			}},
			wantOK: false,
		},
		{
			name: "missing chatgpt account id wins over stale auth",
			file: auth401,
			probe: UsageProbeResult{Record: AccountRecord{
				Name:           "stale-401.codex.json",
				StateKey:       stateError,
				ProbeErrorKind: "missing_chatgpt_account_id",
			}},
			wantSource: "usage_probe",
			wantOK:     true,
		},
		{
			name: "missing chatgpt account id with weak file signal is still candidate",
			file: map[string]any{
				"name":           "missing-id.codex.json",
				"status":         "error",
				"status_message": "upstream stream closed before first payload",
			},
			probe: UsageProbeResult{Record: AccountRecord{
				Name:           "missing-id.codex.json",
				StateKey:       stateError,
				ProbeErrorKind: "missing_chatgpt_account_id",
			}},
			wantSource: "usage_probe",
			wantOK:     true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			source, ok := recovery401CandidateDetectionSource(tt.file, tt.probe)
			if ok != tt.wantOK {
				t.Fatalf("recovery401CandidateDetectionSource() ok = %v, want %v", ok, tt.wantOK)
			}
			if source != tt.wantSource {
				t.Fatalf("recovery401CandidateDetectionSource() source = %q, want %q", source, tt.wantSource)
			}
		})
	}
}
