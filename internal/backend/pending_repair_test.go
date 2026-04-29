package backend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestQuotaManagedInventoryFingerprintIgnoresVolatileFields(t *testing.T) {
	previous := AccountRecord{
		Name:             "quota.json",
		AuthIndex:        "auth-old",
		Email:            "old@example.com",
		Provider:         "codex",
		Type:             "codex",
		Account:          "old@example.com",
		Source:           "file",
		State:            stateQuotaLimited,
		StateKey:         stateQuotaLimited,
		Status:           stateQuotaLimited,
		Disabled:         true,
		Unavailable:      true,
		ManagedReason:    "quota_disabled",
		ChatGPTAccountID: "acct-quota",
		AuthUpdatedAt:    "2026-04-29T00:00:00Z",
		AuthModTime:      "2026-04-29T00:00:01Z",
		AuthLastRefresh:  "",
		LastProbedAt:     "2026-04-29T00:10:00Z",
		UpdatedAt:        "2026-04-29T00:10:01Z",
	}

	current := previous
	current.Email = "new@example.com"
	current.Account = "new@example.com"
	current.Disabled = false
	current.Unavailable = false
	current.AuthIndex = "auth-new"
	current.AuthUpdatedAt = "2026-04-29T01:00:00Z"
	current.AuthModTime = "2026-04-29T01:00:01Z"
	current.AuthLastRefresh = "2026-04-29T01:00:02Z"

	if inventoryFingerprintChanged(current, previous) {
		t.Fatalf("expected quota-managed inventory change with same account identity to preserve last known state")
	}

	current.ChatGPTAccountID = "acct-replaced"
	if !inventoryFingerprintChanged(current, previous) {
		t.Fatalf("expected account identity change to force a reprobe")
	}
}

func TestCarryInventorySnapshotForPendingQuotaManagedState(t *testing.T) {
	previous := AccountRecord{
		Name:                "quota.json",
		AuthIndex:           "auth-old",
		Email:               "old@example.com",
		Provider:            "codex",
		Type:                "codex",
		Account:             "old@example.com",
		Source:              "file",
		State:               statePending,
		StateKey:            statePending,
		Status:              statePending,
		Disabled:            true,
		ManagedReason:       "quota_disabled",
		PlanType:            "free",
		ChatGPTAccountID:    "acct-quota",
		QuotaBlockedUntil:   "2026-05-03T00:00:00Z",
		RecoveryNextProbeAt: "2026-05-02T23:30:00Z",
	}

	current := AccountRecord{
		Name:             "quota.json",
		AuthIndex:        "auth-new",
		Email:            "new@example.com",
		Provider:         "codex",
		Type:             "codex",
		Account:          "new@example.com",
		Source:           "file",
		Disabled:         false,
		Unavailable:      false,
		ManagedReason:    "quota_disabled",
		PlanType:         "",
		ChatGPTAccountID: "acct-quota",
	}

	carried := carryInventorySnapshot(current, &previous)
	if carried.StateKey != stateQuotaLimited || !carried.QuotaLimited {
		t.Fatalf("expected pending managed account with same identity to keep quota-limited state, got %+v", carried)
	}
	if carried.RecoveryNextProbeAt != previous.RecoveryNextProbeAt {
		t.Fatalf("expected recovery schedule to be preserved, got %+v", carried)
	}

	current.ChatGPTAccountID = "acct-replaced"
	reprobed := carryInventorySnapshot(current, &previous)
	if reprobed.StateKey != statePending || reprobed.LastProbedAt != "" {
		t.Fatalf("expected identity change to force reprobe, got %+v", reprobed)
	}
}

func TestRunScanRestoresPendingQuotaManagedStateFromHistory(t *testing.T) {
	apiCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v0/management/auth-files":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"files": []map[string]any{
					{
						"name":        "quota.json",
						"type":        "codex",
						"provider":    "codex",
						"auth_index":  "auth-new",
						"disabled":    false,
						"unavailable": false,
						"updated_at":  "2026-04-29T01:00:00Z",
						"modtime":     "2026-04-29T01:00:01Z",
						"id_token":    `{"chatgpt_account_id":"acct-quota","plan_type":"free"}`,
					},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v0/management/api-call":
			apiCalls++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status_code": 200,
				"body":        `{"plan_type":"free","rate_limit":{"allowed":false,"limit_reached":true},"rate_limits":{"weekly":{"used_percent":100,"reset_at":"2026-05-03T00:00:00Z"}}}`,
			})
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
		ExportDirectory: filepath.Join(dataDir, "exports"),
	})
	if err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	historical := AccountRecord{
		Name:                "quota.json",
		AuthIndex:           "auth-old",
		Email:               "old@example.com",
		Provider:            "codex",
		Type:                "codex",
		Account:             "old@example.com",
		Source:              "file",
		State:               stateQuotaLimited,
		StateKey:            stateQuotaLimited,
		Status:              stateQuotaLimited,
		Disabled:            true,
		ManagedReason:       "quota_disabled",
		Allowed:             boolPtr(false),
		LimitReached:        boolPtr(true),
		APIStatusCode:       intPtr(http.StatusOK),
		PlanType:            "free",
		ChatGPTAccountID:    "acct-quota",
		LastSeenAt:          nowISO(),
		LastProbedAt:        nowISO(),
		UpdatedAt:           nowISO(),
		QuotaBlockedUntil:   "2026-05-03T00:00:00Z",
		RecoveryNextProbeAt: time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339),
	}

	runID, err := service.store.StartScanRun(AppSettings{})
	if err != nil {
		t.Fatalf("StartScanRun: %v", err)
	}
	if err := service.store.SaveScanRecords(runID, []AccountRecord{historical}); err != nil {
		t.Fatalf("SaveScanRecords: %v", err)
	}
	if err := service.store.FinishScanRun(ScanSummary{
		RunID:             runID,
		Status:            "success",
		StartedAt:         nowISO(),
		FinishedAt:        nowISO(),
		TotalAccounts:     1,
		FilteredAccounts:  1,
		ProbedAccounts:    1,
		QuotaLimitedCount: 1,
		Message:           "seed history",
	}); err != nil {
		t.Fatalf("FinishScanRun: %v", err)
	}

	pending := historical
	pending.State = statePending
	pending.StateKey = statePending
	pending.Status = statePending
	pending.LastProbedAt = ""
	pending.APIStatusCode = nil
	pending.Allowed = nil
	pending.LimitReached = nil
	pending.QuotaBlockedUntil = ""
	pending.RecoveryNextProbeAt = ""
	pending.RecoveryPassCount = 0
	pending.RecoveryLastPassedAt = ""
	pending.AuthUpdatedAt = "2026-04-29T01:00:00Z"
	pending.AuthModTime = "2026-04-29T01:00:01Z"
	pending.Disabled = true
	pending.Unavailable = true
	if err := service.store.UpsertCurrentAccount(pending); err != nil {
		t.Fatalf("UpsertCurrentAccount: %v", err)
	}

	summary, err := service.RunScan()
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	if summary.QuotaLimitedCount != 1 {
		t.Fatalf("expected restored managed account to count as quota-limited, got %+v", summary)
	}
	if summary.ProbedAccounts != 0 {
		t.Fatalf("expected restored managed account with future recovery probe time to skip probing, got %+v", summary)
	}
	if apiCalls != 0 {
		t.Fatalf("expected no probe call for restored managed account, got %d", apiCalls)
	}

	snapshot, err := service.GetDashboardSnapshot()
	if err != nil {
		t.Fatalf("GetDashboardSnapshot: %v", err)
	}
	if snapshot.Summary.PendingCount != 0 || snapshot.Summary.QuotaLimitedCount != 1 {
		t.Fatalf("expected dashboard to reflect restored quota-limited state, got %+v", snapshot.Summary)
	}

	records, err := service.ListAccounts(AccountFilter{Type: "codex"})
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one record, got %d", len(records))
	}
	if records[0].StateKey != stateQuotaLimited || records[0].LastProbedAt == "" {
		t.Fatalf("expected restored quota-limited record with preserved last probe, got %+v", records[0])
	}
}

func TestNewRepairsPendingQuotaManagedStateFromHistory(t *testing.T) {
	dataDir := t.TempDir()
	service, err := New(dataDir, nil)
	if err != nil {
		t.Fatalf("New backend: %v", err)
	}

	historical := AccountRecord{
		Name:                "quota.json",
		AuthIndex:           "auth-old",
		Email:               "old@example.com",
		Provider:            "codex",
		Type:                "codex",
		Account:             "old@example.com",
		Source:              "file",
		State:               stateQuotaLimited,
		StateKey:            stateQuotaLimited,
		Status:              stateQuotaLimited,
		Disabled:            true,
		ManagedReason:       "quota_disabled",
		Allowed:             boolPtr(false),
		LimitReached:        boolPtr(true),
		APIStatusCode:       intPtr(http.StatusOK),
		PlanType:            "free",
		ChatGPTAccountID:    "acct-quota",
		LastSeenAt:          nowISO(),
		LastProbedAt:        nowISO(),
		UpdatedAt:           nowISO(),
		QuotaBlockedUntil:   "2026-05-03T00:00:00Z",
		RecoveryNextProbeAt: time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339),
	}

	runID, err := service.store.StartScanRun(AppSettings{})
	if err != nil {
		t.Fatalf("StartScanRun: %v", err)
	}
	if err := service.store.SaveScanRecords(runID, []AccountRecord{historical}); err != nil {
		t.Fatalf("SaveScanRecords: %v", err)
	}
	if err := service.store.FinishScanRun(ScanSummary{
		RunID:             runID,
		Status:            "success",
		StartedAt:         nowISO(),
		FinishedAt:        nowISO(),
		TotalAccounts:     1,
		FilteredAccounts:  1,
		ProbedAccounts:    1,
		QuotaLimitedCount: 1,
		Message:           "seed history",
	}); err != nil {
		t.Fatalf("FinishScanRun: %v", err)
	}

	pending := historical
	pending.State = statePending
	pending.StateKey = statePending
	pending.Status = statePending
	pending.LastProbedAt = ""
	pending.APIStatusCode = nil
	pending.Allowed = nil
	pending.LimitReached = nil
	pending.QuotaBlockedUntil = ""
	pending.RecoveryNextProbeAt = ""
	pending.RecoveryPassCount = 0
	pending.RecoveryLastPassedAt = ""
	if err := service.store.UpsertCurrentAccount(pending); err != nil {
		t.Fatalf("UpsertCurrentAccount: %v", err)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := New(dataDir, nil)
	if err != nil {
		t.Fatalf("reopen backend: %v", err)
	}
	defer reopened.Close()

	snapshot, err := reopened.GetDashboardSnapshot()
	if err != nil {
		t.Fatalf("GetDashboardSnapshot: %v", err)
	}
	if snapshot.Summary.PendingCount != 0 || snapshot.Summary.QuotaLimitedCount != 1 {
		t.Fatalf("expected startup repair to clear pending quota-managed state, got %+v", snapshot.Summary)
	}

	records, err := reopened.ListAccounts(AccountFilter{Type: "codex"})
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one record, got %d", len(records))
	}
	if records[0].StateKey != stateQuotaLimited || records[0].LastProbedAt == "" {
		t.Fatalf("expected repaired quota-limited record with probe snapshot on reopen, got %+v", records[0])
	}
}
