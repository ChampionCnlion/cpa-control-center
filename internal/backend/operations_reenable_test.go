package backend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestBackendMaintainRequiresRecoveredReconfirmationBeforeReenable(t *testing.T) {
	var (
		mu         sync.Mutex
		probeCalls int
		reenabled  []string
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v0/management/auth-files":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"files": []map[string]any{
					{
						"name":       "flaky-recovered.json",
						"type":       "codex",
						"provider":   "codex",
						"auth_index": "flaky-recovered",
						"disabled":   true,
						"id_token":   `{"chatgpt_account_id":"acct-flaky-recovered","plan_type":"pro"}`,
					},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v0/management/api-call":
			mu.Lock()
			probeCalls++
			call := probeCalls
			mu.Unlock()

			if call == 1 {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status_code": 200,
					"body":        `{"plan_type":"pro","rate_limit":{"allowed":true,"limit_reached":false}}`,
				})
				return
			}

			_ = json.NewEncoder(w).Encode(map[string]any{
				"status_code": 200,
				"body":        `{"plan_type":"pro","rate_limit":{"allowed":true,"limit_reached":true}}`,
			})
		case r.Method == http.MethodPatch && r.URL.Path == "/v0/management/auth-files/status":
			var body struct {
				Name     string `json:"name"`
				Disabled bool   `json:"disabled"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if !body.Disabled {
				reenabled = append(reenabled, body.Name)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	dataDir := t.TempDir()
	service, err := New(dataDir, nil)
	if err != nil {
		t.Fatalf("New backend: %v", err)
	}
	defer service.Close()

	_, err = service.SaveSettings(AppSettings{
		BaseURL:         server.URL,
		ManagementToken: "token",
		Locale:          localeEnglish,
		TargetType:      "codex",
		ProbeWorkers:    2,
		ActionWorkers:   1,
		TimeoutSeconds:  5,
		Retries:         0,
		UserAgent:       defaultUserAgent,
		QuotaAction:     "disable",
		AutoReenable:    true,
	})
	if err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	if err := service.store.UpsertCurrentAccount(AccountRecord{
		Name:             "flaky-recovered.json",
		Type:             "codex",
		Provider:         "codex",
		State:            stateQuotaLimited,
		StateKey:         stateQuotaLimited,
		Disabled:         true,
		ManagedReason:    "quota_disabled",
		AuthIndex:        "flaky-recovered",
		ChatGPTAccountID: "acct-flaky-recovered",
		UpdatedAt:        nowISO(),
		LastSeenAt:       nowISO(),
	}); err != nil {
		t.Fatalf("UpsertCurrentAccount: %v", err)
	}

	result, err := service.RunMaintain(MaintainOptions{
		QuotaAction:  "disable",
		AutoReenable: true,
	})
	if err != nil {
		t.Fatalf("RunMaintain: %v", err)
	}
	if len(result.ReenableResults) != 0 {
		t.Fatalf("expected no reenable results after recovered reconfirmation failed, got %+v", result.ReenableResults)
	}

	records, err := service.ListAccounts(AccountFilter{Type: "codex"})
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one record, got %d", len(records))
	}
	if records[0].StateKey != stateQuotaLimited || !records[0].Disabled {
		t.Fatalf("expected account to remain quota-limited and disabled after failed reconfirmation, got %+v", records[0])
	}

	mu.Lock()
	defer mu.Unlock()
	if probeCalls != 2 {
		t.Fatalf("expected 2 probe calls, got %d", probeCalls)
	}
	if len(reenabled) != 0 {
		t.Fatalf("expected no reenable API calls, got %+v", reenabled)
	}
}
