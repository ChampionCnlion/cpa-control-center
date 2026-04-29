package backend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestLimitQuotaRecoveryProbeCandidatesPrefersDueOverUninitialized(t *testing.T) {
	now := time.Now().UTC()
	candidates := []AccountRecord{
		{
			Name:          "uninitialized.json",
			Disabled:      true,
			ManagedReason: "quota_disabled",
			StateKey:      stateQuotaLimited,
		},
		{
			Name:                "due.json",
			Disabled:            true,
			ManagedReason:       "quota_disabled",
			StateKey:            stateQuotaLimited,
			RecoveryNextProbeAt: now.Add(-time.Minute).Format(time.RFC3339),
		},
		{
			Name:          "regular.json",
			StateKey:      stateNormal,
			ManagedReason: "",
		},
	}

	selected, indexes := limitQuotaRecoveryProbeCandidates(AppSettings{QuotaRecoveryProbeLimit: 1}, candidates, []int{0, 1, 2})

	if len(selected) != 2 || selected[0].Name != "regular.json" || selected[1].Name != "due.json" {
		t.Fatalf("expected regular candidate plus due recovery candidate, got %+v", selected)
	}
	if len(indexes) != 2 || indexes[0] != 2 || indexes[1] != 1 {
		t.Fatalf("expected selected indexes [2 1], got %+v", indexes)
	}
}

func TestBackendMaintainRequiresMultipleRecoveredPassesBeforeReenable(t *testing.T) {
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
						"id_token":   `{"chatgpt_account_id":"acct-flaky-recovered","plan_type":"free"}`,
					},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v0/management/api-call":
			mu.Lock()
			probeCalls++
			mu.Unlock()

			_ = json.NewEncoder(w).Encode(map[string]any{
				"status_code": 200,
				"body":        `{"plan_type":"free","rate_limit":{"allowed":true,"limit_reached":false},"rate_limits":{"weekly":{"used_percent":0,"reset_at":"2026-05-03T00:00:00Z"}}}`,
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
		BaseURL:                          server.URL,
		ManagementToken:                  "token",
		Locale:                           localeEnglish,
		TargetType:                       "codex",
		ProbeWorkers:                     2,
		ActionWorkers:                    1,
		TimeoutSeconds:                   5,
		Retries:                          0,
		UserAgent:                        defaultUserAgent,
		QuotaAction:                      "disable",
		AutoReenable:                     true,
		QuotaRecoveryConfirmationPasses:  2,
		QuotaRecoveryMinRemainingPercent: 2,
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
		PlanType:         "free",
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
		t.Fatalf("expected no reenable results after first recovered pass, got %+v", result.ReenableResults)
	}

	records, err := service.ListAccounts(AccountFilter{Type: "codex"})
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one record, got %d", len(records))
	}
	if records[0].StateKey != stateQuotaLimited || !records[0].Disabled || records[0].RecoveryPassCount != 1 {
		t.Fatalf("expected account to remain quota-limited and disabled after first recovered pass, got %+v", records[0])
	}

	secondResult, err := service.RunMaintain(MaintainOptions{
		QuotaAction:  "disable",
		AutoReenable: true,
	})
	if err != nil {
		t.Fatalf("RunMaintain second pass: %v", err)
	}
	if len(secondResult.ReenableResults) != 1 || !secondResult.ReenableResults[0].OK {
		t.Fatalf("expected second maintain to reenable the account, got %+v", secondResult.ReenableResults)
	}

	records, err = service.ListAccounts(AccountFilter{Type: "codex"})
	if err != nil {
		t.Fatalf("ListAccounts second pass: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one record after second pass, got %d", len(records))
	}
	if records[0].StateKey != stateNormal || records[0].Disabled || records[0].RecoveryPassCount != 0 {
		t.Fatalf("expected account to be reenabled after second recovered pass, got %+v", records[0])
	}

	mu.Lock()
	defer mu.Unlock()
	if probeCalls != 2 {
		t.Fatalf("expected one probe per maintain run, got %d", probeCalls)
	}
	if len(reenabled) != 1 || reenabled[0] != "flaky-recovered.json" {
		t.Fatalf("expected one reenable API call, got %+v", reenabled)
	}
}
