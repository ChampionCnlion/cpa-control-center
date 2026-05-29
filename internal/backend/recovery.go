package backend

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	xproxy "golang.org/x/net/proxy"
)

const (
	defaultRecoveryBrowserUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	defaultRecoveryEmailServiceURL  = "https://postinbox.org/mailbox"
	chatGPTSessionURL               = "https://chatgpt.com/api/auth/session"
	chatGPTCSRFURL                  = "https://chatgpt.com/api/auth/csrf"
	authOpenAIOrigin                = "https://auth.openai.com"
	openAISentinelVersion           = "20260219f9f6"
	openAISentinelSDKURL            = "https://sentinel.openai.com/sentinel/" + openAISentinelVersion + "/sdk.js"
	openAISentinelReqURL            = "https://sentinel.openai.com/backend-api/sentinel/req"
	openAISentinelReferer           = "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=" + openAISentinelVersion
	recoveryKind                    = "recovery"
)

var (
	emailPattern         = regexp.MustCompile(`(?i)[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}`)
	otpPattern           = regexp.MustCompile(`\b(\d{6})\b`)
	recovery401Pattern   = regexp.MustCompile(`\b401\b`)
	csrfPattern          = regexp.MustCompile(`<meta\s+name="csrf-token"\s+content="([^"]+)"`)
	livewireSnapshotExpr = regexp.MustCompile(`wire:snapshot="([^"]+)".{0,900}?wire:id="([^"]+)"`)
)

func (b *Backend) Scan401Recovery() (Recovery401ScanResult, error) {
	settings, err := b.store.LoadSettings()
	if err != nil {
		return Recovery401ScanResult{}, err
	}
	if err := ensureConfigured(settings); err != nil {
		return Recovery401ScanResult{}, err
	}

	ctx, err := b.beginTask(recoveryKind, settings.Locale)
	if err != nil {
		return Recovery401ScanResult{}, err
	}
	defer b.endTask()

	status := "success"
	finishMessage := "401 scan completed"
	defer func() {
		b.emitTaskFinished(recoveryKind, status, finishMessage)
	}()

	b.emitLog(recoveryKind, "info", "Starting probe-based 401 recovery scan")
	b.emitProgress(recoveryKind, "fetch", 0, 1, "Loading CPA auth inventory", false)
	files, err := b.client.FetchAuthFiles(ctx, settings)
	if err != nil {
		status = taskStatus(err)
		finishMessage = err.Error()
		b.emitLog(recoveryKind, "error", finishMessage)
		b.emitProgress(recoveryKind, "fetch", 0, 1, finishMessage, true)
		return Recovery401ScanResult{}, err
	}
	b.emitProgress(recoveryKind, "fetch", 1, 1, fmt.Sprintf("Loaded %d auth records", len(files)), true)

	result, _, err := b.buildRecovery401ProbeScanResult(ctx, settings, files)
	if err != nil {
		status = taskStatus(err)
		finishMessage = err.Error()
		b.emitLog(recoveryKind, "warning", finishMessage)
		return Recovery401ScanResult{}, err
	}
	finishMessage = fmt.Sprintf("401 scan completed: %d candidates from %d probed accounts", len(result.Candidates), result.Probed)
	b.emitLog(recoveryKind, "info", finishMessage)
	b.emitProgress(recoveryKind, "complete", result.Probed, result.Probed, finishMessage, true)
	return result, nil
}

func (b *Backend) Run401Recovery(options Recovery401Options) (Recovery401Result, error) {
	settings, err := b.store.LoadSettings()
	if err != nil {
		return Recovery401Result{}, err
	}
	if err := ensureConfigured(settings); err != nil {
		return Recovery401Result{}, err
	}

	ctx, err := b.beginTask(recoveryKind, settings.Locale)
	if err != nil {
		return Recovery401Result{}, err
	}
	defer b.endTask()

	status := "success"
	finishMessage := "401 recovery completed"
	defer func() {
		b.emitTaskFinished(recoveryKind, status, finishMessage)
	}()

	b.emitLog(recoveryKind, "info", "Starting 401 account recovery")
	b.emitProgress(recoveryKind, "fetch", 0, 1, "Loading CPA auth inventory", false)
	files, err := b.client.FetchAuthFiles(ctx, settings)
	if err != nil {
		status = taskStatus(err)
		finishMessage = err.Error()
		b.emitLog(recoveryKind, "error", finishMessage)
		b.emitProgress(recoveryKind, "fetch", 0, 1, finishMessage, true)
		return Recovery401Result{}, err
	}
	b.emitProgress(recoveryKind, "fetch", 1, 1, fmt.Sprintf("Loaded %d auth records", len(files)), true)

	scanResult, candidates, err := b.buildRecovery401ProbeScanResult(ctx, settings, files)
	if err != nil {
		status = taskStatus(err)
		finishMessage = err.Error()
		b.emitLog(recoveryKind, "warning", finishMessage)
		return Recovery401Result{}, err
	}
	limit := options.MaxAccounts
	if limit <= 0 || limit > len(candidates) {
		limit = len(candidates)
	}
	selected := candidates[:limit]

	result := Recovery401Result{
		Summary: Recovery401Summary{
			Total:      scanResult.Total,
			Candidates: len(candidates),
		},
		Results: make([]Recovery401ItemResult, 0, len(selected)),
	}
	b.emitLog(recoveryKind, "info", fmt.Sprintf("Prepared %d 401 candidates from %d auth records after probing %d accounts", len(candidates), scanResult.Total, scanResult.Probed))
	if len(selected) == 0 {
		finishMessage = "No 401 candidates found"
		b.emitProgress(recoveryKind, "complete", 0, 0, finishMessage, true)
		return result, nil
	}

	emailServiceURL := strings.TrimSpace(options.EmailServiceURL)
	if emailServiceURL == "" {
		emailServiceURL = defaultRecoveryEmailServiceURL
	}

	for index, file := range selected {
		if err := ctx.Err(); err != nil {
			status = taskStatus(err)
			finishMessage = err.Error()
			return result, err
		}
		name := strings.TrimSpace(stringValue(file["name"]))
		b.emitProgress(recoveryKind, "repair", index, len(selected), fmt.Sprintf("Recovering %s", stringOr(name, "(unnamed)")), false)

		item := b.recoverOne401Credential(ctx, settings, file, emailServiceURL)
		result.Results = append(result.Results, item)
		result.Summary.Processed++
		switch {
		case item.OK && item.Action == "uploaded":
			result.Summary.Uploaded++
		case item.Action == "skipped":
			result.Summary.Skipped++
		default:
			result.Summary.Failed++
		}
		level := "info"
		if !item.OK {
			level = "warning"
		}
		b.emitLog(recoveryKind, level, fmt.Sprintf("%s: %s", stringOr(item.Email, item.Name, "401 credential"), item.Message))
		b.emitProgress(recoveryKind, "repair", index+1, len(selected), item.Message, index+1 == len(selected))
	}

	if result.Summary.Failed > 0 {
		finishMessage = fmt.Sprintf("401 recovery completed with %d failures", result.Summary.Failed)
	} else {
		finishMessage = "401 recovery completed"
	}
	b.emitProgress(recoveryKind, "complete", result.Summary.Processed, len(selected), finishMessage, true)

	if refreshedFiles, syncErr := b.client.FetchAuthFiles(ctx, settings); syncErr == nil {
		syncResult, syncErr := b.syncInventoryFromFiles(settings, refreshedFiles)
		if syncErr == nil {
			b.emitLog(recoveryKind, "info", fmt.Sprintf("Inventory refreshed after recovery: %d/%d", syncResult.FilteredAccounts, syncResult.TotalAccounts))
		} else {
			b.emitLog(recoveryKind, "warning", fmt.Sprintf("Inventory refresh after recovery failed: %s", syncErr.Error()))
		}
	} else {
		b.emitLog(recoveryKind, "warning", fmt.Sprintf("Inventory refresh after recovery failed: %s", syncErr.Error()))
	}

	return result, nil
}

func (b *Backend) recoverOne401Credential(ctx context.Context, settings AppSettings, file map[string]any, emailServiceURL string) Recovery401ItemResult {
	name := strings.TrimSpace(stringValue(file["name"]))
	if name == "" {
		return Recovery401ItemResult{Action: "skipped", OK: false, Message: "auth file has no name"}
	}
	if boolValueFromAny(file["runtime_only"]) {
		return Recovery401ItemResult{Name: name, Action: "skipped", OK: false, Message: "runtime-only auth file cannot be overwritten"}
	}

	authJSON, err := b.client.DownloadAuthFile(ctx, settings, name)
	if err != nil {
		return Recovery401ItemResult{Name: name, Action: "download_failed", OK: false, Message: "download failed: " + err.Error()}
	}

	email := inferRecoveryEmail(file, authJSON)
	if email == "" {
		return Recovery401ItemResult{Name: name, Action: "skipped", OK: false, Message: "could not infer account email"}
	}
	if !looksLikeRecoveryCodexFile(file, authJSON) {
		return Recovery401ItemResult{Name: name, Email: email, Action: "skipped", OK: false, Message: "not a codex/openai auth file"}
	}

	session, err := loginChatGPTWithPostInBox(ctx, email, emailServiceURL, settings.UserAgent, func(status string, detail string) {
		b.emitDetailedLog(settings.DetailedLogs, recoveryKind, "info", fmt.Sprintf("%s %s: %s", email, status, detail))
	})
	if err != nil {
		return recoveryOAuthFailureResult(name, email, err)
	}

	sessionToken := strings.TrimSpace(stringValue(session["sessionToken"]))
	if sessionToken == "" {
		sessionToken = extractSessionToken(authJSON)
	}
	cpa := buildCPAAuthJSONFromSession(session, email, sessionToken, authJSON)
	if err := validateCPAAuthJSON(cpa); err != nil {
		return Recovery401ItemResult{Name: name, Email: email, Action: "convert_failed", OK: false, Message: err.Error()}
	}
	return b.uploadAndVerifyRecoveredAuthFile(ctx, settings, name, email, cpa, "OAuth re-login succeeded and verified by Codex usage probe")
}

func (b *Backend) uploadAndVerifyRecoveredAuthFile(ctx context.Context, settings AppSettings, name string, email string, cpa map[string]any, successMessage string) Recovery401ItemResult {
	if err := b.client.UploadAuthFile(ctx, settings, name, cpa); err != nil {
		return Recovery401ItemResult{Name: name, Email: email, Action: "upload_failed", OK: false, Message: "upload failed: " + err.Error()}
	}

	probe, err := b.verifyRecoveredAuthFile(ctx, settings, name, cpa)
	if err != nil {
		return Recovery401ItemResult{Name: name, Email: email, Action: "verify_failed", OK: false, Message: "uploaded but verification failed: " + err.Error()}
	}
	if probe.Record.QuotaLimited {
		return Recovery401ItemResult{Name: name, Email: email, Action: "uploaded", OK: true, Message: successMessage + "; account is authenticated but quota-limited"}
	}
	return Recovery401ItemResult{Name: name, Email: email, Action: "uploaded", OK: true, Message: successMessage}
}

func (b *Backend) verifyRecoveredAuthFile(ctx context.Context, settings AppSettings, name string, cpa map[string]any) (UsageProbeResult, error) {
	files, err := b.client.FetchAuthFiles(ctx, settings)
	if err != nil {
		return UsageProbeResult{}, err
	}
	file, ok := findManagedAuthFileByName(files, name)
	if !ok {
		return UsageProbeResult{}, fmt.Errorf("uploaded auth file %q was not returned by CPA inventory", name)
	}

	record := b.client.BuildAccountRecord(file, nil, nowISO())
	if record.ChatGPTAccountID == "" {
		record.ChatGPTAccountID = extractChatGPTAccountID(cpa)
	}
	if record.PlanType == "" {
		record.PlanType = strings.TrimSpace(stringOr(stringValue(cpa["chatgpt_plan_type"]), stringValue(cpa["plan_type"])))
	}
	if record.Provider == "" {
		record.Provider = "codex"
	}
	if record.Type == "" {
		record.Type = "codex"
	}
	if strings.TrimSpace(record.AuthIndex) == "" {
		return UsageProbeResult{}, errors.New("uploaded auth file has no auth index for verification")
	}
	if strings.TrimSpace(record.ChatGPTAccountID) == "" {
		return UsageProbeResult{}, errors.New(msg(settings.Locale, "error.missing_chatgpt_account_id"))
	}

	probe := b.client.ProbeUsageResult(ctx, settings, record)
	if probe.Record.Invalid401 {
		return probe, fmt.Errorf("Codex usage probe still returned status_code=%d", intValue(probe.Record.APIStatusCode))
	}
	if probe.Record.ProbeErrorKind != "" && !probe.Record.QuotaLimited {
		if probe.Record.ProbeErrorText != "" {
			return probe, errors.New(probe.Record.ProbeErrorText)
		}
		return probe, errors.New(probe.Record.ProbeErrorKind)
	}
	if probe.UsageError != nil && !probe.Record.QuotaLimited {
		return probe, probe.UsageError
	}
	return probe, nil
}

type recoveryClassifiedError struct {
	Action  string
	Message string
	Cause   error
}

func (e recoveryClassifiedError) Error() string {
	if strings.TrimSpace(e.Message) != "" {
		return e.Message
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	return "OAuth recovery failed"
}

func (e recoveryClassifiedError) Unwrap() error {
	return e.Cause
}

func classifiedRecoveryError(action string, message string, cause error) error {
	return recoveryClassifiedError{
		Action:  strings.TrimSpace(action),
		Message: strings.TrimSpace(message),
		Cause:   cause,
	}
}

func recoveryOAuthFailureResult(name string, email string, err error) Recovery401ItemResult {
	action := "oauth_failed"
	message := "OAuth recovery failed"

	var classified recoveryClassifiedError
	if errors.As(err, &classified) {
		if classified.Action != "" {
			action = classified.Action
		}
		if classified.Message != "" {
			message = classified.Message
		}
	} else {
		action = classifyOAuthRecoveryFailureAction(err)
		if err != nil {
			message = "OAuth recovery failed: " + err.Error()
		}
	}

	return Recovery401ItemResult{Name: name, Email: email, Action: action, OK: false, Message: message}
}

func classifyOAuthRecoveryFailureAction(err error) string {
	if err == nil {
		return "oauth_failed"
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "access deactivated") ||
		strings.Contains(lower, "access_deactivated") ||
		strings.Contains(lower, "account deactivated") ||
		strings.Contains(lower, "account disabled") ||
		strings.Contains(lower, "account suspended"):
		return "oauth_access_deactivated"
	case strings.Contains(lower, "phone"):
		return "oauth_phone_required"
	case strings.Contains(lower, "cloudflare") || strings.Contains(lower, "challenge blocked"):
		return "oauth_cloudflare_blocked"
	case strings.Contains(lower, "verification code not found") ||
		strings.Contains(lower, "verification code is empty"):
		return "otp_not_found"
	case strings.Contains(lower, "invalid") && (strings.Contains(lower, "otp") || strings.Contains(lower, "code")):
		return "otp_invalid"
	case strings.Contains(lower, "continue url") || strings.Contains(lower, "continue_url"):
		return "oauth_continue_missing"
	case strings.Contains(lower, "callback"):
		return "oauth_callback_failed"
	case strings.Contains(lower, "access token"):
		return "oauth_no_access_token"
	case strings.Contains(lower, "legacy openai auth flow"):
		return "oauth_unsupported_flow"
	case strings.Contains(lower, "sentinel"):
		return "oauth_sentinel_failed"
	default:
		return "oauth_failed"
	}
}

func (b *Backend) buildRecovery401ProbeScanResult(ctx context.Context, settings AppSettings, files []map[string]any) (Recovery401ScanResult, []map[string]any, error) {
	records, probeRecords, filesByName, err := b.buildRecovery401ProbeRecords(settings, files)
	if err != nil {
		return Recovery401ScanResult{}, nil, err
	}

	probes, err := b.probeAccounts(ctx, recoveryKind, settings, probeRecords)
	if err != nil {
		return Recovery401ScanResult{}, nil, err
	}

	if len(probes) > 0 {
		recordsByName := make(map[string]AccountRecord, len(probes))
		for _, probe := range probes {
			recordsByName[probe.Record.Name] = probe.Record
		}
		for index, record := range records {
			if probed, ok := recordsByName[record.Name]; ok {
				records[index] = probed
			}
		}
	}

	if err := b.store.ReplaceCurrentAccounts(records); err != nil {
		return Recovery401ScanResult{}, nil, err
	}

	var quotaSnapshot *CodexQuotaSnapshot
	snapshot, ok, err := b.buildCodexQuotaSnapshotFromUsageProbes(settings, records, probes, nowISO(), recoveryKind)
	if err != nil {
		return Recovery401ScanResult{}, nil, err
	}
	if ok {
		if err := b.persistCodexQuotaSnapshot(snapshot); err != nil {
			return Recovery401ScanResult{}, nil, err
		}
		quotaSnapshot = &snapshot
	}

	candidates := make([]recovery401CandidateItem, 0)
	for _, probe := range probes {
		file, ok := filesByName[probe.Record.Name]
		if !ok {
			continue
		}
		source, ok := recovery401CandidateDetectionSource(file, probe)
		if !ok {
			continue
		}
		candidates = append(candidates, recovery401CandidateItem{
			file:      file,
			candidate: buildRecovery401Candidate(file, probe.Record, source),
		})
	}
	sort.SliceStable(candidates, func(i int, j int) bool {
		return candidates[i].candidate.Name < candidates[j].candidate.Name
	})

	result := Recovery401ScanResult{
		Total:      len(files),
		Probed:     len(probes),
		Quota:      quotaSnapshot,
		Candidates: make([]Recovery401Candidate, 0, len(candidates)),
	}
	candidateFiles := make([]map[string]any, 0, len(candidates))
	for _, item := range candidates {
		result.Candidates = append(result.Candidates, item.candidate)
		candidateFiles = append(candidateFiles, item.file)
	}

	return result, candidateFiles, nil
}

type recovery401CandidateItem struct {
	file      map[string]any
	candidate Recovery401Candidate
}

func (b *Backend) buildRecovery401ProbeRecords(settings AppSettings, files []map[string]any) ([]AccountRecord, []AccountRecord, map[string]map[string]any, error) {
	existing, err := b.store.LoadCurrentMap()
	if err != nil {
		return nil, nil, nil, err
	}

	timestamp := nowISO()
	records := make([]AccountRecord, 0, len(files))
	recordIndexes := make(map[string]int, len(files))
	filesByName := make(map[string]map[string]any, len(files))

	for _, item := range files {
		name := strings.TrimSpace(stringValue(item["name"]))
		if name == "" {
			continue
		}

		var previous *AccountRecord
		if current, ok := existing[name]; ok {
			currentCopy := current
			previous = &currentCopy
		}
		record := b.client.BuildAccountRecord(item, previous, timestamp)
		record = carryInventorySnapshot(record, previous)
		if record.Name == "" {
			continue
		}
		filesByName[record.Name] = item
		if index, ok := recordIndexes[record.Name]; ok {
			records[index] = record
			continue
		}
		recordIndexes[record.Name] = len(records)
		records = append(records, record)
	}

	probeRecords := make([]AccountRecord, 0, len(records))
	for _, record := range records {
		if matchesInventoryFilter(record, settings) {
			probeRecords = append(probeRecords, record)
		}
	}

	return records, probeRecords, filesByName, nil
}

func buildRecovery401ScanResult(files []map[string]any) Recovery401ScanResult {
	candidates := filterRecovery401Candidates(files)
	items := make([]Recovery401Candidate, 0, len(candidates))
	for _, file := range candidates {
		items = append(items, buildRecovery401Candidate(file, AccountRecord{
			Name:          strings.TrimSpace(stringValue(file["name"])),
			Email:         strings.TrimSpace(stringValue(file["email"])),
			Provider:      strings.TrimSpace(stringValue(file["provider"])),
			Status:        strings.TrimSpace(stringValue(file["status"])),
			StatusMessage: strings.TrimSpace(stringValue(file["status_message"])),
			StateKey:      stateInvalid401,
			Disabled:      boolValueFromAny(file["disabled"]),
			Unavailable:   boolValueFromAny(file["unavailable"]),
			RuntimeOnly:   boolValueFromAny(file["runtime_only"]),
		}, "auth_status"))
	}
	return Recovery401ScanResult{Total: len(files), Candidates: items}
}

func recovery401CandidateDetectionSource(file map[string]any, probe UsageProbeResult) (string, bool) {
	if strings.TrimSpace(probe.Record.ProbeErrorKind) == "missing_chatgpt_account_id" {
		return "usage_probe", true
	}
	state := normalizeStateKey(probe.Record.StateKey)
	switch state {
	case stateInvalid401:
		return "usage_probe", true
	case stateNormal, stateQuotaLimited, stateRecovered:
		return "", false
	}
	if intValue(probe.Record.APIStatusCode) == http.StatusUnauthorized && probe.Record.ProbeErrorKind != "usage_limit_reached" {
		return "usage_probe", true
	}
	if isRecovery401AuthFile(file) {
		return "auth_status", true
	}
	return "", false
}

func buildRecovery401Candidate(file map[string]any, record AccountRecord, source string) Recovery401Candidate {
	return Recovery401Candidate{
		Name:            strings.TrimSpace(stringOr(record.Name, stringValue(file["name"]))),
		Email:           strings.TrimSpace(stringOr(record.Email, stringValue(file["email"]))),
		Provider:        strings.TrimSpace(stringOr(record.Provider, stringValue(file["provider"]))),
		PlanType:        strings.TrimSpace(record.PlanType),
		Status:          strings.TrimSpace(stringOr(record.Status, stringValue(file["status"]))),
		StatusMessage:   strings.TrimSpace(stringOr(record.StatusMessage, stringValue(file["status_message"]))),
		StateKey:        normalizeStateKey(record.StateKey),
		DetectionSource: source,
		APIStatusCode:   record.APIStatusCode,
		ProbeErrorKind:  strings.TrimSpace(record.ProbeErrorKind),
		ProbeErrorText:  strings.TrimSpace(record.ProbeErrorText),
		Disabled:        record.Disabled || boolValueFromAny(file["disabled"]),
		Unavailable:     record.Unavailable || boolValueFromAny(file["unavailable"]),
		RuntimeOnly:     record.RuntimeOnly || boolValueFromAny(file["runtime_only"]),
	}
}

func filterRecovery401Candidates(files []map[string]any) []map[string]any {
	candidates := make([]map[string]any, 0)
	for _, file := range files {
		if isRecovery401AuthFile(file) {
			candidates = append(candidates, file)
		}
	}
	sort.SliceStable(candidates, func(i int, j int) bool {
		return strings.TrimSpace(stringValue(candidates[i]["name"])) < strings.TrimSpace(stringValue(candidates[j]["name"]))
	})
	return candidates
}

func findManagedAuthFileByName(files []map[string]any, name string) (map[string]any, bool) {
	candidates := managedAccountNameCandidates(name, false, true)
	candidateSet := make(map[string]struct{}, len(candidates)*2)
	for _, candidate := range candidates {
		trimmed := strings.TrimSpace(candidate)
		if trimmed == "" {
			continue
		}
		candidateSet[trimmed] = struct{}{}
		if normalized := normalizeManagedAccountName(trimmed); normalized != "" {
			candidateSet[normalized] = struct{}{}
		}
	}

	for _, file := range files {
		fileName := strings.TrimSpace(stringValue(file["name"]))
		if fileName == "" {
			fileName = strings.TrimSpace(stringValue(file["id"]))
		}
		if _, ok := candidateSet[fileName]; ok {
			return file, true
		}
		if normalized := normalizeManagedAccountName(fileName); normalized != "" {
			if _, ok := candidateSet[normalized]; ok {
				return file, true
			}
		}
	}
	return nil, false
}

func isRecovery401AuthFile(file map[string]any) bool {
	text := strings.ToLower(strings.Join([]string{
		stringValue(file["status"]),
		stringValue(file["status_message"]),
		stringValue(file["error"]),
		stringValue(file["message"]),
		stringValue(file["code"]),
		stringValue(file["type"]),
	}, " "))
	if isRecoveryNonAuthLimit(text) {
		return false
	}
	return hasRecoveryAuthFailureSignal(text)
}

func hasRecoveryAuthFailureSignal(text string) bool {
	return recovery401Pattern.MatchString(text) ||
		strings.Contains(text, "unauthorized") ||
		strings.Contains(text, "authentication_error") ||
		strings.Contains(text, "auth_unavailable") ||
		strings.Contains(text, "authentication token has been invalidated") ||
		strings.Contains(text, "token has been invalidated") ||
		strings.Contains(text, "signing in again") ||
		strings.Contains(text, "sign in again") ||
		strings.Contains(text, "not authenticated") ||
		strings.Contains(text, "login required")
}

func isRecoveryNonAuthLimit(text string) bool {
	return strings.Contains(text, "usage_limit_reached") ||
		strings.Contains(text, "limit_reached") ||
		strings.Contains(text, "rate_limit") ||
		strings.Contains(text, "quota") ||
		strings.Contains(text, "stream disconnected")
}

func looksLikeRecoveryCodexFile(file map[string]any, authJSON map[string]any) bool {
	text := strings.ToLower(strings.Join([]string{
		stringValue(file["provider"]),
		stringValue(file["type"]),
		stringValue(file["account_type"]),
		stringValue(file["name"]),
		stringValue(authJSON["type"]),
		stringValue(authJSON["auth_mode"]),
	}, " "))
	return strings.Contains(text, "codex") || strings.Contains(text, "openai") ||
		strings.TrimSpace(stringValue(authJSON["access_token"])) != "" ||
		strings.TrimSpace(stringValue(authJSON["accessToken"])) != ""
}

func inferRecoveryEmail(file map[string]any, authJSON map[string]any) string {
	candidates := []string{
		stringValue(authJSON["email"]),
		stringValue(authJSON["name"]),
		stringValue(authJSON["account"]),
		stringValue(file["email"]),
		stringValue(file["name"]),
		stringValue(file["id"]),
	}
	for _, candidate := range candidates {
		if match := emailPattern.FindString(candidate); match != "" {
			return strings.ToLower(match)
		}
	}
	return ""
}

func extractSessionToken(authJSON map[string]any) string {
	for _, key := range []string{"session_token", "sessionToken"} {
		if value := strings.TrimSpace(stringValue(authJSON[key])); value != "" {
			return value
		}
	}
	if tokens, ok := authJSON["tokens"].(map[string]any); ok {
		for _, key := range []string{"session_token", "sessionToken"} {
			if value := strings.TrimSpace(stringValue(tokens[key])); value != "" {
				return value
			}
		}
	}
	return ""
}

func recoveryBrowserUserAgent(configured string) string {
	lower := strings.ToLower(configured)
	if strings.Contains(lower, "chrome/") || strings.Contains(lower, "safari/") || strings.Contains(lower, "firefox/") {
		return strings.TrimSpace(configured)
	}
	return defaultRecoveryBrowserUserAgent
}

func newOpenAIRecoveryHTTPClient(timeout time.Duration, jar http.CookieJar, stopRedirects bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	proxyURL := recoveryProxyURL()
	var roundTripper http.RoundTripper = transport
	if curlBin := recoveryCurlImpersonateBin(); curlBin != "" {
		roundTripper = curlImpersonateTransport{bin: curlBin, proxyURL: proxyURL}
	} else if proxyURL != "" {
		if err := applyRecoveryProxy(transport, proxyURL); err != nil {
			// Keep direct networking available; the request error will still expose
			// upstream Cloudflare/proxy failures to the recovery result.
			_ = err
		}
	}
	client := &http.Client{
		Timeout:   timeout,
		Jar:       jar,
		Transport: roundTripper,
	}
	if stopRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}

type curlImpersonateTransport struct {
	bin      string
	proxyURL string
}

func recoveryCurlImpersonateBin() string {
	for _, candidate := range []string{
		strings.TrimSpace(os.Getenv("CPA_CONTROL_CENTER_CURL_IMPERSONATE_BIN")),
		"/usr/local/bin/curl_ff117",
		"curl_ff117",
	} {
		if candidate == "" {
			continue
		}
		if path, err := exec.LookPath(candidate); err == nil {
			return path
		}
	}
	return ""
}

func (t curlImpersonateTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("nil request")
	}
	headerFile, err := os.CreateTemp("", "cpa-recovery-curl-headers-*")
	if err != nil {
		return nil, err
	}
	headerPath := headerFile.Name()
	_ = headerFile.Close()
	defer os.Remove(headerPath)

	bodyFile, err := os.CreateTemp("", "cpa-recovery-curl-body-*")
	if err != nil {
		return nil, err
	}
	bodyPath := bodyFile.Name()
	_ = bodyFile.Close()
	defer os.Remove(bodyPath)

	args := []string{
		"--silent",
		"--show-error",
		"--compressed",
		"--http2",
		"--request", req.Method,
		"--dump-header", headerPath,
		"--output", bodyPath,
	}
	if t.proxyURL != "" {
		args = append(args, "--proxy", t.proxyURL)
	}
	for key, values := range req.Header {
		if strings.EqualFold(key, "Content-Length") || strings.EqualFold(key, "Accept-Encoding") {
			continue
		}
		for _, value := range values {
			args = append(args, "--header", key+": "+value)
		}
	}
	var requestBodyPath string
	if req.Body != nil {
		data, readErr := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if len(data) > 0 {
			bodyInput, createErr := os.CreateTemp("", "cpa-recovery-curl-input-*")
			if createErr != nil {
				return nil, createErr
			}
			requestBodyPath = bodyInput.Name()
			if _, writeErr := bodyInput.Write(data); writeErr != nil {
				_ = bodyInput.Close()
				_ = os.Remove(requestBodyPath)
				return nil, writeErr
			}
			if closeErr := bodyInput.Close(); closeErr != nil {
				_ = os.Remove(requestBodyPath)
				return nil, closeErr
			}
			defer os.Remove(requestBodyPath)
			args = append(args, "--data-binary", "@"+requestBodyPath)
		}
	}
	args = append(args, req.URL.String())

	cmd := exec.CommandContext(req.Context(), t.bin, args...)
	stderr, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("curl impersonate request failed: %w: %s", err, normalizeText(string(stderr), 260))
	}

	headerBytes, err := os.ReadFile(headerPath)
	if err != nil {
		return nil, err
	}
	responseBody, err := os.ReadFile(bodyPath)
	if err != nil {
		return nil, err
	}
	statusCode, status, headers, err := parseCurlResponseHeaders(string(headerBytes))
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode:    statusCode,
		Status:        status,
		Header:        headers,
		Body:          io.NopCloser(bytes.NewReader(responseBody)),
		ContentLength: int64(len(responseBody)),
		Request:       req,
	}, nil
}

func parseCurlResponseHeaders(raw string) (int, string, http.Header, error) {
	blocks := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n\n")
	var block string
	for i := len(blocks) - 1; i >= 0; i-- {
		if strings.TrimSpace(blocks[i]) != "" {
			block = strings.TrimSpace(blocks[i])
			break
		}
	}
	if block == "" {
		return 0, "", nil, errors.New("curl returned no response headers")
	}
	reader := bufio.NewReader(strings.NewReader(block + "\n\n"))
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return 0, "", nil, err
	}
	statusLine = strings.TrimSpace(statusLine)
	parts := strings.Fields(statusLine)
	if len(parts) < 2 {
		return 0, "", nil, fmt.Errorf("invalid curl status line %q", statusLine)
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, "", nil, fmt.Errorf("invalid curl status code %q: %w", parts[1], err)
	}
	mimeHeader, err := textproto.NewReader(reader).ReadMIMEHeader()
	if err != nil {
		return 0, "", nil, err
	}
	statusText := strings.TrimSpace(strings.TrimPrefix(statusLine, parts[0]+" "+parts[1]))
	if statusText == "" {
		statusText = http.StatusText(code)
	}
	return code, fmt.Sprintf("%d %s", code, statusText), http.Header(mimeHeader), nil
}

func recoveryProxyURL() string {
	for _, key := range []string{
		"CPA_CONTROL_CENTER_RECOVERY_PROXY_URL",
		"ALL_PROXY",
		"HTTPS_PROXY",
		"HTTP_PROXY",
		"all_proxy",
		"https_proxy",
		"http_proxy",
	} {
		value := strings.TrimSpace(os.Getenv(key))
		if value != "" {
			return value
		}
	}
	return ""
}

func applyRecoveryProxy(transport *http.Transport, rawProxy string) error {
	proxyURL, err := url.Parse(rawProxy)
	if err != nil {
		return err
	}
	switch strings.ToLower(proxyURL.Scheme) {
	case "socks5", "socks5h":
		var auth *xproxy.Auth
		if proxyURL.User != nil {
			password, _ := proxyURL.User.Password()
			auth = &xproxy.Auth{User: proxyURL.User.Username(), Password: password}
		}
		dialer, err := xproxy.SOCKS5("tcp", proxyURL.Host, auth, xproxy.Direct)
		if err != nil {
			return err
		}
		if contextDialer, ok := dialer.(xproxy.ContextDialer); ok {
			transport.DialContext = contextDialer.DialContext
		} else {
			transport.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
				type result struct {
					conn net.Conn
					err  error
				}
				ch := make(chan result, 1)
				go func() {
					conn, err := dialer.Dial(network, address)
					ch <- result{conn: conn, err: err}
				}()
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case result := <-ch:
					return result.conn, result.err
				}
			}
		}
		return nil
	case "http", "https":
		transport.Proxy = http.ProxyURL(proxyURL)
		return nil
	default:
		return fmt.Errorf("unsupported recovery proxy scheme %q", proxyURL.Scheme)
	}
}

func isCloudflareChallenge(resp *http.Response, body []byte) bool {
	if resp == nil {
		return false
	}
	if strings.EqualFold(resp.Header.Get("cf-mitigated"), "challenge") {
		return true
	}
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "enable javascript and cookies to continue") ||
		strings.Contains(lower, "just a moment") && strings.Contains(lower, "cloudflare")
}

func cloudflareChallengeError(target string, statusCode int) error {
	return fmt.Errorf("%s HTTP %d: ChatGPT/OpenAI Cloudflare challenge blocked server-side recovery; configure CPA_CONTROL_CENTER_RECOVERY_PROXY_URL with a proxy that can pass chatgpt.com/auth.openai.com or recover the account from a browser-authenticated environment", target, statusCode)
}

func refreshChatGPTSession(ctx context.Context, sessionToken string, userAgent string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, chatGPTSessionURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", recoveryBrowserUserAgent(userAgent))
	req.AddCookie(&http.Cookie{Name: "__Secure-next-auth.session-token", Value: sessionToken, Path: "/"})
	req.AddCookie(&http.Cookie{Name: "next-auth.session-token", Value: sessionToken, Path: "/"})

	client := newOpenAIRecoveryHTTPClient(30*time.Second, nil, false)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		if isCloudflareChallenge(resp, data) {
			return nil, cloudflareChallengeError("chatgpt session refresh", resp.StatusCode)
		}
		return nil, fmt.Errorf("chatgpt session refresh HTTP %d: %s", resp.StatusCode, normalizeText(string(data), 220))
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, err
	}
	if strings.TrimSpace(stringValue(parsed["accessToken"])) == "" && strings.TrimSpace(stringValue(parsed["access_token"])) == "" {
		return nil, errors.New("chatgpt session refresh returned no access token")
	}
	parsed["sessionToken"] = sessionToken
	return parsed, nil
}

func validateCPAAuthJSON(authJSON map[string]any) error {
	if strings.TrimSpace(stringValue(authJSON["access_token"])) == "" {
		return errors.New("converted auth JSON has no access_token")
	}
	if strings.TrimSpace(stringValue(authJSON["chatgpt_account_id"])) == "" && strings.TrimSpace(stringValue(authJSON["account_id"])) == "" {
		return errors.New("converted auth JSON has no account id")
	}
	return nil
}

type chatGPTSessionInfo struct {
	Email          string
	AccessToken    string
	SessionToken   string
	IDToken        string
	AccountID      string
	UserID         string
	OrganizationID string
	PlanType       string
	ExpiresAt      string
	ExpiresAtUnix  int64
}

func buildCPAAuthJSONFromSession(session map[string]any, fallbackEmail string, sessionToken string, existing map[string]any) map[string]any {
	info := extractChatGPTSessionInfo(session)
	if info.Email == "" {
		info.Email = fallbackEmail
	}
	if info.SessionToken == "" {
		info.SessionToken = sessionToken
	}
	idToken, synthetic := resolveCodexIDToken(info)
	expired := info.ExpiresAt
	if expired == "" && info.ExpiresAtUnix > 0 {
		expired = time.Unix(info.ExpiresAtUnix, 0).UTC().Format(time.RFC3339)
	}

	output := make(map[string]any, len(existing)+16)
	for key, value := range existing {
		output[key] = value
	}
	output["type"] = "codex"
	output["email"] = info.Email
	output["account_id"] = info.AccountID
	output["chatgpt_account_id"] = info.AccountID
	output["organization_id"] = info.OrganizationID
	output["plan_type"] = info.PlanType
	output["chatgpt_plan_type"] = info.PlanType
	output["id_token"] = idToken
	output["access_token"] = info.AccessToken
	output["refresh_token"] = stringValue(existing["refresh_token"])
	output["session_token"] = info.SessionToken
	output["last_refresh"] = nowISO()
	output["expired"] = expired
	output["disabled"] = false
	output["id_token_synthetic"] = synthetic
	return output
}

func extractChatGPTSessionInfo(session map[string]any) chatGPTSessionInfo {
	info := chatGPTSessionInfo{
		AccessToken:  strings.TrimSpace(stringOr(stringValue(session["accessToken"]), stringValue(session["access_token"]))),
		SessionToken: strings.TrimSpace(stringOr(stringValue(session["sessionToken"]), stringValue(session["session_token"]))),
		IDToken:      strings.TrimSpace(stringOr(stringValue(session["idToken"]), stringValue(session["id_token"]))),
		ExpiresAt:    strings.TrimSpace(stringValue(session["expires"])),
		Email:        strings.TrimSpace(stringValue(session["email"])),
	}

	if user, ok := session["user"].(map[string]any); ok && info.Email == "" {
		info.Email = strings.TrimSpace(stringValue(user["email"]))
	}
	if account, ok := session["account"].(map[string]any); ok {
		info.AccountID = strings.TrimSpace(stringOr(stringValue(account["id"]), stringValue(account["account_id"])))
		info.PlanType = strings.TrimSpace(stringOr(stringValue(account["planType"]), stringValue(account["plan_type"])))
	}
	if accounts, ok := session["accounts"].(map[string]any); ok {
		for _, rawAccount := range accounts {
			acc, ok := rawAccount.(map[string]any)
			if !ok {
				continue
			}
			if nested, ok := acc["account"].(map[string]any); ok {
				if info.AccountID == "" {
					info.AccountID = strings.TrimSpace(stringOr(stringValue(nested["account_id"]), stringValue(nested["id"])))
				}
				if info.PlanType == "" {
					info.PlanType = strings.TrimSpace(stringOr(stringValue(nested["plan_type"]), stringValue(nested["planType"])))
				}
			}
			if info.PlanType == "" {
				info.PlanType = strings.TrimSpace(stringOr(stringValue(acc["plan_type"]), stringValue(acc["planType"])))
			}
			break
		}
	}

	if claims := decodeJWTPayload(info.AccessToken); claims != nil {
		authClaims, _ := claims["https://api.openai.com/auth"].(map[string]any)
		profileClaims, _ := claims["https://api.openai.com/profile"].(map[string]any)
		if info.Email == "" {
			info.Email = strings.TrimSpace(stringOr(stringValue(claims["email"]), stringValue(profileClaims["email"]), stringValue(authClaims["email"])))
		}
		if claimAccountID := strings.TrimSpace(stringOr(stringValue(authClaims["chatgpt_account_id"]), stringValue(authClaims["account_id"]))); claimAccountID != "" {
			info.AccountID = claimAccountID
		}
		if claimUserID := strings.TrimSpace(stringOr(stringValue(authClaims["chatgpt_user_id"]), stringValue(authClaims["user_id"]), stringValue(claims["sub"]))); claimUserID != "" {
			info.UserID = claimUserID
		}
		if claimOrganizationID := strings.TrimSpace(stringValue(authClaims["organization_id"])); claimOrganizationID != "" {
			info.OrganizationID = claimOrganizationID
		}
		if claimPlanType := strings.TrimSpace(stringOr(stringValue(authClaims["chatgpt_plan_type"]), stringValue(authClaims["plan_type"]))); claimPlanType != "" {
			info.PlanType = claimPlanType
		}
		if exp, ok := intValueFromAny(claims["exp"]); ok && exp > 0 {
			info.ExpiresAtUnix = int64(exp)
			if info.ExpiresAt == "" {
				info.ExpiresAt = time.Unix(int64(exp), 0).UTC().Format(time.RFC3339)
			}
		}
	}

	return info
}

func resolveCodexIDToken(info chatGPTSessionInfo) (string, bool) {
	if strings.TrimSpace(info.IDToken) != "" {
		return normalizeSyntheticCodexIDToken(info.IDToken), isSyntheticCodexIDToken(info.IDToken)
	}
	if info.AccountID == "" {
		return "", false
	}
	return buildSyntheticCodexIDToken(info), true
}

func decodeJWTPayload(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
	}
	if err != nil {
		return nil
	}
	var parsed map[string]any
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return nil
	}
	return parsed
}

func decodeJWTHeader(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[0])
	}
	if err != nil {
		return nil
	}
	var parsed map[string]any
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return nil
	}
	return parsed
}

func isSyntheticCodexIDToken(token string) bool {
	header := decodeJWTHeader(token)
	return strings.EqualFold(stringValue(header["alg"]), "none") && boolValueFromAny(header["cpa_synthetic"])
}

func normalizeSyntheticCodexIDToken(token string) string {
	if !isSyntheticCodexIDToken(token) {
		return token
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return token
	}
	return parts[0] + "." + parts[1] + "."
}

func buildSyntheticCodexIDToken(info chatGPTSessionInfo) string {
	now := time.Now().UTC().Unix()
	exp := info.ExpiresAtUnix
	if exp <= 0 {
		if parsed, err := time.Parse(time.RFC3339, info.ExpiresAt); err == nil {
			exp = parsed.UTC().Unix()
		}
	}
	if exp <= 0 {
		exp = now + int64((90*24*time.Hour)/time.Second)
	}
	authInfo := map[string]any{
		"account_id":         info.AccountID,
		"chatgpt_account_id": info.AccountID,
	}
	if info.PlanType != "" {
		authInfo["chatgpt_plan_type"] = info.PlanType
	}
	if info.OrganizationID != "" {
		authInfo["organization_id"] = info.OrganizationID
	}
	if info.UserID != "" {
		authInfo["chatgpt_user_id"] = info.UserID
		authInfo["user_id"] = info.UserID
	}
	payload := map[string]any{
		"iat":                         now,
		"exp":                         exp,
		"https://api.openai.com/auth": authInfo,
	}
	if info.Email != "" {
		payload["email"] = info.Email
	}
	headerJSON, _ := json.Marshal(map[string]any{"alg": "none", "typ": "JWT", "cpa_synthetic": true})
	payloadJSON, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON) + "."
}

type postInBoxMailbox struct {
	client      *http.Client
	baseURL     string
	csrf        string
	appSnapshot string
}

func newPostInBoxMailbox(ctx context.Context, emailAddress string, serviceURL string) (*postInBoxMailbox, error) {
	baseURL := strings.TrimSpace(serviceURL)
	if baseURL == "" {
		baseURL = defaultRecoveryEmailServiceURL
	}
	parsedEmail := strings.Split(emailAddress, "@")
	if len(parsedEmail) != 2 || parsedEmail[0] == "" || parsedEmail[1] == "" {
		return nil, fmt.Errorf("invalid email address: %s", emailAddress)
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	page, err := postInBoxGET(ctx, client, baseURL)
	if err != nil {
		return nil, err
	}
	csrf := extractCSRFToken(page)
	if csrf == "" {
		return nil, errors.New("postinbox csrf token not found")
	}
	actionsSnapshot, err := extractLivewireSnapshot(page, "frontend.actions")
	if err != nil {
		return nil, err
	}
	createPayload := livewirePayload(csrf, actionsSnapshot, map[string]any{
		"user":   parsedEmail[0],
		"domain": parsedEmail[1],
	}, []map[string]any{{
		"path":   "",
		"method": "create",
		"params": []any{},
	}})
	if _, err := postInBoxUpdate(ctx, client, baseURL, csrf, createPayload); err != nil {
		return nil, err
	}
	page, err = postInBoxGET(ctx, client, baseURL)
	if err != nil {
		return nil, err
	}
	if refreshed := extractCSRFToken(page); refreshed != "" {
		csrf = refreshed
	}
	appSnapshot, err := extractLivewireSnapshot(page, "frontend.app")
	if err != nil {
		return nil, err
	}
	if !strings.Contains(appSnapshot, emailAddress) {
		return nil, fmt.Errorf("postinbox did not open mailbox %s", emailAddress)
	}
	return &postInBoxMailbox{client: client, baseURL: baseURL, csrf: csrf, appSnapshot: appSnapshot}, nil
}

func (m *postInBoxMailbox) pollCode(ctx context.Context, issuedAfter time.Time, onStatus func(string, string)) (string, error) {
	const retries = 20
	for attempt := 1; attempt <= retries; attempt++ {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if onStatus != nil {
			onStatus("checking_code", fmt.Sprintf("checking postinbox mail (%d/%d)", attempt, retries))
		}
		body, err := m.fetchMessages(ctx)
		if err == nil {
			if code := extractOTPCodeFromText(body, issuedAfter); code != "" {
				return code, nil
			}
		}
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
	}
	return "", errors.New("verification code not found in postinbox")
}

func (m *postInBoxMailbox) fetchMessages(ctx context.Context) (string, error) {
	payload := livewirePayload(m.csrf, m.appSnapshot, map[string]any{}, []map[string]any{{
		"path":   "",
		"method": "__dispatch",
		"params": []any{"fetchMessages", []any{}},
	}})
	body, err := postInBoxUpdate(ctx, m.client, m.baseURL, m.csrf, payload)
	if err != nil {
		return "", err
	}
	if snapshot, ok := firstLivewireComponentSnapshot(body, "frontend.app"); ok {
		m.appSnapshot = snapshot
	}
	return body, nil
}

func postInBoxGET(ctx context.Context, client *http.Client, endpoint string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("postinbox HTTP %d: %s", resp.StatusCode, normalizeText(string(data), 220))
	}
	return string(data), nil
}

func postInBoxUpdate(ctx context.Context, client *http.Client, referer string, csrf string, payload any) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://postinbox.org/livewire/update", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-TOKEN", csrf)
	req.Header.Set("X-Livewire", "")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Referer", referer)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("postinbox livewire HTTP %d: %s", resp.StatusCode, normalizeText(string(body), 220))
	}
	return string(body), nil
}

func livewirePayload(csrf string, snapshot string, updates map[string]any, calls []map[string]any) map[string]any {
	return map[string]any{
		"_token": csrf,
		"components": []map[string]any{{
			"snapshot": snapshot,
			"updates":  updates,
			"calls":    calls,
		}},
	}
}

func extractCSRFToken(page string) string {
	matches := csrfPattern.FindStringSubmatch(page)
	if len(matches) < 2 {
		return ""
	}
	return strings.TrimSpace(matches[1])
}

func extractLivewireSnapshot(page string, name string) (string, error) {
	for _, match := range livewireSnapshotExpr.FindAllStringSubmatch(page, -1) {
		if len(match) < 2 {
			continue
		}
		snapshot := html.UnescapeString(match[1])
		var parsed struct {
			Memo struct {
				Name string `json:"name"`
			} `json:"memo"`
		}
		if err := json.Unmarshal([]byte(snapshot), &parsed); err != nil {
			continue
		}
		if parsed.Memo.Name == name {
			return snapshot, nil
		}
	}
	return "", fmt.Errorf("postinbox livewire component %s not found", name)
}

func firstLivewireComponentSnapshot(body string, name string) (string, bool) {
	var parsed struct {
		Components []struct {
			Snapshot string `json:"snapshot"`
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return "", false
	}
	for _, component := range parsed.Components {
		var snapshot struct {
			Memo struct {
				Name string `json:"name"`
			} `json:"memo"`
		}
		if err := json.Unmarshal([]byte(component.Snapshot), &snapshot); err == nil && snapshot.Memo.Name == name {
			return component.Snapshot, true
		}
	}
	return "", false
}

func extractOTPCodeFromText(input string, issuedAfter time.Time) string {
	texts := []string{input}
	var response struct {
		Components []struct {
			Snapshot string `json:"snapshot"`
			Effects  struct {
				HTML string `json:"html"`
			} `json:"effects"`
		} `json:"components"`
	}
	if err := json.Unmarshal([]byte(input), &response); err == nil {
		for _, component := range response.Components {
			if component.Snapshot != "" {
				var snapshot any
				if err := json.Unmarshal([]byte(component.Snapshot), &snapshot); err == nil {
					collected := make([]string, 0)
					collectStrings(snapshot, &collected)
					texts = append(texts, collected...)
				}
			}
			if component.Effects.HTML != "" {
				texts = append(texts, component.Effects.HTML)
			}
		}
	}
	for _, text := range texts {
		lower := strings.ToLower(text)
		if !(strings.Contains(lower, "openai") ||
			strings.Contains(lower, "chatgpt") ||
			strings.Contains(lower, "verification") ||
			strings.Contains(lower, "verify") ||
			strings.Contains(lower, "code") ||
			strings.Contains(lower, "login") ||
			strings.Contains(lower, "otp")) {
			continue
		}
		if match := otpPattern.FindStringSubmatch(text); len(match) > 1 {
			return match[1]
		}
	}
	return ""
}

func collectStrings(value any, out *[]string) {
	switch typed := value.(type) {
	case string:
		if strings.TrimSpace(typed) != "" {
			*out = append(*out, typed)
		}
	case []any:
		for _, item := range typed {
			collectStrings(item, out)
		}
	case map[string]any:
		for _, item := range typed {
			collectStrings(item, out)
		}
	}
}

func loginChatGPTWithPostInBox(ctx context.Context, email string, emailServiceURL string, userAgent string, onStatus func(string, string)) (map[string]any, error) {
	issuedAfter := time.Now().Add(-10 * time.Second)
	mailbox, err := newPostInBoxMailbox(ctx, email, emailServiceURL)
	if err != nil {
		return nil, err
	}
	return loginChatGPTWithEmailOTP(ctx, email, userAgent, func() (string, error) {
		return mailbox.pollCode(ctx, issuedAfter, onStatus)
	}, onStatus)
}

func loginChatGPTWithEmailOTP(ctx context.Context, email string, userAgent string, fetchCode func() (string, error), onStatus func(string, string)) (map[string]any, error) {
	jar, _ := cookiejar.New(nil)
	client := newOpenAIRecoveryHTTPClient(120*time.Second, jar, true)
	if onStatus != nil {
		onStatus("csrf", "getting csrf token")
	}
	csrf, err := getChatGPTCSRF(ctx, client, userAgent)
	if err != nil {
		return nil, err
	}
	if onStatus != nil {
		onStatus("signin", "starting chatgpt signin")
	}
	authURL, err := signinOpenAI(ctx, client, csrf, userAgent)
	if err != nil {
		return nil, err
	}
	if onStatus != nil {
		onStatus("authorize", "following authorization chain")
	}
	state, err := followOpenAIAuthorize(ctx, client, authURL, userAgent)
	if err != nil {
		return nil, err
	}
	if !state.isModern {
		return nil, classifiedRecoveryError("oauth_unsupported_flow", "OAuth recovery failed: legacy OpenAI auth flow is not supported by the recovery worker", nil)
	}
	if onStatus != nil {
		onStatus("sentinel", "generating OpenAI sentinel token")
	}
	if token, err := getOpenAISentinelToken(ctx, client, &state, "authorize_continue", userAgent); err == nil {
		state.sentinelToken = token
	} else if onStatus != nil {
		onStatus("sentinel_warning", err.Error())
	}
	if onStatus != nil {
		onStatus("identifier", "submitting email")
	}
	firstStep, err := authorizeContinue(ctx, client, &state, email, userAgent)
	if err != nil {
		return nil, err
	}
	callbackURL, err := completeModernOpenAILogin(ctx, client, &state, firstStep, fetchCode, userAgent, onStatus)
	if err != nil {
		return nil, err
	}
	if callbackURL != "" {
		if onStatus != nil {
			onStatus("callback", "following callback")
		}
		if err := followOpenAICallback(ctx, client, callbackURL, userAgent); err != nil {
			return nil, err
		}
	}
	if onStatus != nil {
		onStatus("oauth_session", "checking OAuth-issued ChatGPT token")
	}
	session, err := getChatGPTSession(ctx, client, userAgent)
	if err != nil {
		return nil, err
	}
	if !chatGPTSessionHasAccessToken(session) && callbackURL == "" {
		if onStatus != nil {
			onStatus("callback", "resolving callback after OTP validation")
		}
		resolvedCallbackURL, resolveErr := resolveOpenAICallbackAfterOTP(ctx, client, &state, userAgent)
		if resolveErr != nil {
			return nil, resolveErr
		}
		if resolvedCallbackURL != "" {
			if onStatus != nil {
				onStatus("callback", "following resolved callback")
			}
			if err := followOpenAICallback(ctx, client, resolvedCallbackURL, userAgent); err != nil {
				return nil, classifiedRecoveryError("oauth_callback_failed", "OAuth callback failed after OTP validation: "+err.Error(), err)
			}
			session, err = getChatGPTSession(ctx, client, userAgent)
			if err != nil {
				return nil, err
			}
		}
	}
	if !chatGPTSessionHasAccessToken(session) {
		return nil, classifiedRecoveryError("oauth_no_access_token", "OAuth did not issue a ChatGPT access token after OTP validation", nil)
	}
	if onStatus != nil {
		onStatus("success", "login succeeded")
	}
	return session, nil
}

func chatGPTSessionHasAccessToken(session map[string]any) bool {
	return strings.TrimSpace(stringValue(session["accessToken"])) != "" || strings.TrimSpace(stringValue(session["access_token"])) != ""
}

type openAILoginState struct {
	authURL       string
	loginURL      string
	deviceID      string
	sentinelToken string
	isModern      bool
}

func getChatGPTCSRF(ctx context.Context, client *http.Client, userAgent string) (string, error) {
	var payload map[string]any
	if err := doOpenAIJSON(ctx, client, http.MethodGet, chatGPTCSRFURL, nil, userAgent, "", &payload); err != nil {
		return "", err
	}
	token := strings.TrimSpace(stringValue(payload["csrfToken"]))
	if token == "" {
		return "", errors.New("csrf token missing")
	}
	return token, nil
}

func signinOpenAI(ctx context.Context, client *http.Client, csrf string, userAgent string) (string, error) {
	attempts := []struct {
		URL         string
		CallbackURL string
		Referer     string
	}{
		{URL: "https://chatgpt.com/api/auth/signin/openai", CallbackURL: "https://chatgpt.com/", Referer: "https://chatgpt.com/auth/login"},
		{URL: "https://chatgpt.com/api/auth/signin/login-web?callbackUrl=%2F", CallbackURL: "/", Referer: "https://chatgpt.com/"},
	}
	for _, attempt := range attempts {
		form := url.Values{}
		form.Set("callbackUrl", attempt.CallbackURL)
		form.Set("csrfToken", csrf)
		form.Set("json", "true")
		var payload map[string]any
		if err := doOpenAIJSON(ctx, client, http.MethodPost, attempt.URL, strings.NewReader(form.Encode()), userAgent, attempt.Referer, &payload, "application/x-www-form-urlencoded"); err != nil {
			continue
		}
		authURL := strings.TrimSpace(stringValue(payload["url"]))
		if authURL != "" && !strings.Contains(authURL, "/api/auth/signin?csrf=true") {
			return authURL, nil
		}
	}
	return "", errors.New("could not obtain OpenAI authorization URL")
}

func followOpenAIAuthorize(ctx context.Context, client *http.Client, authURL string, userAgent string) (openAILoginState, error) {
	state := openAILoginState{authURL: authURL, loginURL: authURL, deviceID: extractOpenAIDeviceID(authURL)}
	current := authURL
	for i := 0; i < 10; i++ {
		req, err := newOpenAIRequest(ctx, http.MethodGet, current, nil, userAgent, "https://chatgpt.com/")
		if err != nil {
			return state, err
		}
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		resp, err := client.Do(req)
		if err != nil {
			return state, err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		parsedCurrent, _ := url.Parse(current)
		if parsedCurrent != nil && parsedCurrent.Host == "auth.openai.com" &&
			(strings.Contains(parsedCurrent.Path, "/api/accounts/authorize") || parsedCurrent.Path == "/log-in") {
			state.isModern = true
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if location == "" {
				break
			}
			current = normalizeURL(location, current)
			state.loginURL = current
			if strings.Contains(current, "auth.openai.com/log-in") {
				state.isModern = true
				if err := openAIWarmPage(ctx, client, current, userAgent); err != nil {
					return state, err
				}
				break
			}
			continue
		}
		if strings.Contains(current, "auth.openai.com") {
			state.loginURL = current
			state.isModern = true
		}
		break
	}
	return state, nil
}

func openAIWarmPage(ctx context.Context, client *http.Client, target string, userAgent string) error {
	req, err := newOpenAIRequest(ctx, http.MethodGet, target, nil, userAgent, "https://chatgpt.com/auth/login")
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func authorizeContinue(ctx context.Context, client *http.Client, state *openAILoginState, email string, userAgent string) (map[string]any, error) {
	payload := map[string]any{
		"username": map[string]any{
			"kind":  "email",
			"value": email,
		},
	}
	var parsed map[string]any
	headers := openAISentinelHeaders(state)
	referer := authOpenAIOrigin + "/log-in"
	if state != nil {
		referer = stringOr(state.loginURL, referer)
	}
	err := doOpenAIJSONWithHeaders(ctx, client, http.MethodPost, authOpenAIOrigin+"/api/accounts/authorize/continue", mustJSONReader(payload), userAgent, referer, &parsed, headers, "application/json")
	return parsed, err
}

func completeModernOpenAILogin(ctx context.Context, client *http.Client, state *openAILoginState, step map[string]any, fetchCode func() (string, error), userAgent string, onStatus func(string, string)) (string, error) {
	continueURL := normalizeURL(extractContinueURL(step), authOpenAIOrigin)
	pageType := strings.ToLower(strings.TrimSpace(stringValue(mapValue(step, "page.type"))))
	if continueURL != "" && !needsModernOTP(pageType, continueURL) {
		return continueURL, nil
	}
	if onStatus != nil {
		onStatus("waiting_code", "waiting for email verification code")
	}
	code, err := fetchCode()
	if err != nil || code == "" {
		if onStatus != nil {
			onStatus("send_code", "requesting another verification code")
		}
		if onStatus != nil {
			onStatus("sentinel", "generating email verification sentinel token")
		}
		if token, tokenErr := getOpenAISentinelToken(ctx, client, state, "email_verification", userAgent); tokenErr == nil && state != nil {
			state.sentinelToken = token
		} else if tokenErr != nil && onStatus != nil {
			onStatus("sentinel_warning", tokenErr.Error())
		}
		_ = kickoffModernOTP(ctx, client, state, userAgent)
		code, err = fetchCode()
	}
	if err != nil {
		return "", err
	}
	if code == "" {
		return "", classifiedRecoveryError("otp_not_found", "OAuth recovery failed: verification code is empty", nil)
	}
	if onStatus != nil {
		onStatus("verify_code", "submitting verification code")
	}
	if token, tokenErr := getOpenAISentinelToken(ctx, client, state, "email_verification", userAgent); tokenErr == nil && state != nil {
		state.sentinelToken = token
	} else if tokenErr != nil && onStatus != nil {
		onStatus("sentinel_warning", tokenErr.Error())
	}
	payload := map[string]any{"code": code}
	var parsed map[string]any
	if err := doOpenAIJSONWithHeaders(ctx, client, http.MethodPost, authOpenAIOrigin+"/api/accounts/email-otp/validate", mustJSONReader(payload), userAgent, authOpenAIOrigin+"/email-verification", &parsed, openAISentinelHeaders(state), "application/json"); err != nil {
		return "", classifyOpenAIOTPValidationError(err)
	}
	if openAIResponseIndicatesAccessDeactivated(parsed) {
		return "", classifiedRecoveryError("oauth_access_deactivated", "OpenAI returned Access Deactivated after OTP validation; this account cannot be recovered by OAuth recovery", nil)
	}
	continueURL = normalizeURL(extractContinueURL(parsed), authOpenAIOrigin)
	if openAIURLIndicatesAccessDeactivated(continueURL) {
		return "", classifiedRecoveryError("oauth_access_deactivated", "OpenAI redirected to Access Deactivated after OTP validation; this account cannot be recovered by OAuth recovery", nil)
	}
	if continueURL == "" {
		if openAIPageRequiresPhone(parsed) {
			return "", classifiedRecoveryError("oauth_phone_required", "OpenAI requested phone verification after OTP validation; finish the phone challenge in a browser before OAuth recovery", nil)
		}
		if openAIResponseLooksComplete(parsed) {
			if onStatus != nil {
				onStatus("oauth", "OTP validation returned no redirect; checking OAuth callback state")
			}
			return "", nil
		}
		return "", classifiedRecoveryError("oauth_continue_missing", fmt.Sprintf("OpenAI did not return an OAuth continue URL after OTP validation (%s)", openAIPageSummary(parsed)), nil)
	}
	return continueURL, nil
}

func classifyOpenAIOTPValidationError(err error) error {
	if err == nil {
		return nil
	}
	action := classifyOAuthRecoveryFailureAction(err)
	message := "OAuth OTP validation failed: " + err.Error()
	if action == "oauth_failed" {
		lower := strings.ToLower(err.Error())
		switch {
		case strings.Contains(lower, "400") || strings.Contains(lower, "401"):
			action = "otp_invalid"
		case strings.Contains(lower, "429") || strings.Contains(lower, "rate limit"):
			action = "oauth_rate_limited"
		}
	}
	return classifiedRecoveryError(action, message, err)
}

func kickoffModernOTP(ctx context.Context, client *http.Client, state *openAILoginState, userAgent string) error {
	endpoints := []struct {
		Method string
		URL    string
	}{
		{Method: http.MethodPost, URL: authOpenAIOrigin + "/api/accounts/passwordless/send-otp"},
		{Method: http.MethodPost, URL: authOpenAIOrigin + "/api/accounts/email-otp/resend"},
		{Method: http.MethodGet, URL: authOpenAIOrigin + "/api/accounts/email-otp/send"},
	}
	var lastErr error
	for _, endpoint := range endpoints {
		req, err := newOpenAIRequest(ctx, endpoint.Method, endpoint.URL, nil, userAgent, authOpenAIOrigin+"/email-verification")
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", authOpenAIOrigin)
		for key, value := range openAISentinelHeaders(state) {
			req.Header.Set(key, value)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		lastErr = fmt.Errorf("OTP kickoff HTTP %d", resp.StatusCode)
	}
	return lastErr
}

func followOpenAICallback(ctx context.Context, client *http.Client, callbackURL string, userAgent string) error {
	current := callbackURL
	for i := 0; i < 10; i++ {
		req, err := newOpenAIRequest(ctx, http.MethodGet, current, nil, userAgent, "")
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if location == "" {
				return nil
			}
			current = normalizeURL(location, current)
			if strings.Contains(current, "chatgpt.com") && !strings.Contains(current, "/api/auth/") {
				return nil
			}
			continue
		}
		return nil
	}
	return nil
}

func resolveOpenAICallbackAfterOTP(ctx context.Context, client *http.Client, state *openAILoginState, userAgent string) (string, error) {
	seen := make(map[string]struct{})
	for _, candidate := range openAIPostOTPResolutionURLs(state) {
		start := strings.TrimSpace(candidate)
		if start == "" {
			continue
		}
		if _, ok := seen[start]; ok {
			continue
		}
		seen[start] = struct{}{}
		callbackURL, err := resolveOpenAICallbackFromURL(ctx, client, start, userAgent)
		if err != nil || callbackURL != "" {
			return callbackURL, err
		}
	}
	return "", nil
}

func openAIPostOTPResolutionURLs(state *openAILoginState) []string {
	if state == nil {
		return nil
	}
	return []string{
		state.authURL,
		state.loginURL,
		authOpenAIOrigin + "/email-verification",
	}
}

func resolveOpenAICallbackFromURL(ctx context.Context, client *http.Client, startURL string, userAgent string) (string, error) {
	current := startURL
	for i := 0; i < 12; i++ {
		if openAIURLIndicatesAccessDeactivated(current) {
			return "", classifiedRecoveryError("oauth_access_deactivated", "OpenAI redirected to Access Deactivated after OTP validation; this account cannot be recovered by OAuth recovery", nil)
		}
		if isChatGPTCallbackURL(current) || isChatGPTLandingURL(current) {
			return current, nil
		}
		req, err := newOpenAIRequest(ctx, http.MethodGet, current, nil, userAgent, authOpenAIOrigin+"/email-verification")
		if err != nil {
			return "", err
		}
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json")
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		if readErr != nil {
			return "", readErr
		}
		if isCloudflareChallenge(resp, data) {
			err := cloudflareChallengeError(current, resp.StatusCode)
			return "", classifiedRecoveryError("oauth_cloudflare_blocked", "OAuth callback blocked by Cloudflare challenge: "+err.Error(), err)
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := strings.TrimSpace(resp.Header.Get("Location"))
			if location == "" {
				return "", nil
			}
			current = normalizeURL(location, current)
			continue
		}
		if openAITextIndicatesAccessDeactivated(string(data)) {
			return "", classifiedRecoveryError("oauth_access_deactivated", "OpenAI returned Access Deactivated after OTP validation; this account cannot be recovered by OAuth recovery", nil)
		}
		if callbackURL := extractContinueURLFromResponseBody(data, current); callbackURL != "" {
			current = callbackURL
			continue
		}
		return "", nil
	}
	return "", nil
}

func extractContinueURLFromResponseBody(data []byte, base string) string {
	if len(data) == 0 {
		return ""
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err == nil {
		if callbackURL := normalizeURL(extractContinueURL(parsed), base); callbackURL != "" {
			return callbackURL
		}
	}
	body := string(data)
	for _, marker := range []string{
		`https://chatgpt.com/api/auth/callback`,
		`https://chat.openai.com/api/auth/callback`,
		`/api/auth/callback`,
	} {
		index := strings.Index(body, marker)
		if index < 0 {
			continue
		}
		end := index
		for end < len(body) {
			switch body[end] {
			case '"', '\'', '<', '>', ' ', '\n', '\r', '\t', '\\':
				return normalizeURL(html.UnescapeString(body[index:end]), base)
			default:
				end++
			}
		}
		return normalizeURL(html.UnescapeString(body[index:end]), base)
	}
	return ""
}

func isChatGPTCallbackURL(rawURL string) bool {
	lower := strings.ToLower(strings.TrimSpace(rawURL))
	return strings.Contains(lower, "chatgpt.com/api/auth/callback") ||
		strings.Contains(lower, "chat.openai.com/api/auth/callback")
}

func isChatGPTLandingURL(rawURL string) bool {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Host == "" {
		return false
	}
	host := strings.ToLower(parsed.Host)
	if host != "chatgpt.com" && host != "chat.openai.com" {
		return false
	}
	path := strings.ToLower(parsed.Path)
	return path == "" || path == "/" || !strings.HasPrefix(path, "/api/auth/")
}

func getChatGPTSession(ctx context.Context, client *http.Client, userAgent string) (map[string]any, error) {
	var payload map[string]any
	if err := doOpenAIJSON(ctx, client, http.MethodGet, chatGPTSessionURL, nil, userAgent, "https://chatgpt.com/", &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func getOpenAISentinelToken(ctx context.Context, client *http.Client, state *openAILoginState, flow string, userAgent string) (string, error) {
	deviceID := ""
	if state != nil {
		deviceID = strings.TrimSpace(state.deviceID)
		if deviceID == "" {
			deviceID = extractOpenAIDeviceID(state.authURL)
		}
	}
	if deviceID == "" {
		deviceID = randomOpenAIDeviceID()
	}
	if state != nil {
		state.deviceID = deviceID
	}

	sdkSource, err := fetchOpenAISentinelSDK(ctx, client, userAgent)
	if err != nil {
		return "", err
	}
	requirements, err := runOpenAISentinelHelper(ctx, map[string]any{
		"action":     "requirements",
		"sdkSource":  sdkSource,
		"device_id":  deviceID,
		"user_agent": recoveryBrowserUserAgent(userAgent),
	})
	if err != nil {
		return "", err
	}
	requestP := strings.TrimSpace(stringValue(requirements["request_p"]))
	if requestP == "" {
		return "", errors.New("OpenAI sentinel requirements token is empty")
	}

	challenge, err := fetchOpenAISentinelChallenge(ctx, client, deviceID, flow, requestP, userAgent)
	if err != nil {
		return "", err
	}
	challengeToken := strings.TrimSpace(stringValue(challenge["token"]))
	if challengeToken == "" {
		return "", errors.New("OpenAI sentinel challenge token is empty")
	}
	solved, err := runOpenAISentinelHelper(ctx, map[string]any{
		"action":     "solve",
		"sdkSource":  sdkSource,
		"device_id":  deviceID,
		"user_agent": recoveryBrowserUserAgent(userAgent),
		"request_p":  requestP,
		"challenge":  challenge,
	})
	if err != nil {
		return "", err
	}
	finalP := strings.TrimSpace(stringValue(solved["final_p"]))
	tValue := strings.TrimSpace(stringValue(solved["t"]))
	if finalP == "" || tValue == "" {
		return "", errors.New("OpenAI sentinel helper returned an incomplete token")
	}
	tokenJSON, err := json.Marshal(map[string]any{
		"p":    finalP,
		"t":    tValue,
		"c":    challengeToken,
		"id":   deviceID,
		"flow": flow,
	})
	if err != nil {
		return "", err
	}
	return string(tokenJSON), nil
}

func fetchOpenAISentinelSDK(ctx context.Context, client *http.Client, userAgent string) (string, error) {
	req, err := newOpenAIRequest(ctx, http.MethodGet, openAISentinelSDKURL, nil, userAgent, authOpenAIOrigin+"/")
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		if isCloudflareChallenge(resp, data) {
			return "", cloudflareChallengeError(openAISentinelSDKURL, resp.StatusCode)
		}
		return "", fmt.Errorf("%s HTTP %d: %s", openAISentinelSDKURL, resp.StatusCode, normalizeText(string(data), 220))
	}
	return string(data), nil
}

func fetchOpenAISentinelChallenge(ctx context.Context, client *http.Client, deviceID string, flow string, requestP string, userAgent string) (map[string]any, error) {
	payload := map[string]any{
		"p":    requestP,
		"id":   deviceID,
		"flow": flow,
	}
	var parsed map[string]any
	if err := doOpenAIJSONWithHeaders(ctx, client, http.MethodPost, openAISentinelReqURL, mustJSONReader(payload), userAgent, openAISentinelReferer, &parsed, map[string]string{
		"Accept":         "*/*",
		"Content-Type":   "text/plain;charset=UTF-8",
		"Origin":         "https://sentinel.openai.com",
		"Sec-Fetch-Dest": "empty",
		"Sec-Fetch-Mode": "cors",
		"Sec-Fetch-Site": "same-origin",
	}, "text/plain;charset=UTF-8"); err != nil {
		return nil, err
	}
	return parsed, nil
}

func runOpenAISentinelHelper(ctx context.Context, input map[string]any) (map[string]any, error) {
	data, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	helperPath := strings.TrimSpace(os.Getenv("CPA_CONTROL_CENTER_SENTINEL_HELPER_PATH"))
	if helperPath == "" {
		helperPath = "/app/openai_sentinel_token.js"
	}
	cmd := exec.CommandContext(ctx, "node", helperPath)
	cmd.Stdin = bytes.NewReader(data)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("OpenAI sentinel helper failed: %v: %s", err, normalizeText(string(output), 260))
	}
	var parsed map[string]any
	if err := json.Unmarshal(output, &parsed); err != nil {
		return nil, fmt.Errorf("OpenAI sentinel helper returned invalid JSON: %w", err)
	}
	return parsed, nil
}

func openAISentinelHeaders(state *openAILoginState) map[string]string {
	if state == nil || strings.TrimSpace(state.sentinelToken) == "" {
		return nil
	}
	return map[string]string{"openai-sentinel-token": state.sentinelToken}
}

func extractOpenAIDeviceID(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(parsed.Query().Get("device_id"))
}

func randomOpenAIDeviceID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf[:])
}

func doOpenAIJSON(ctx context.Context, client *http.Client, method string, endpoint string, body io.Reader, userAgent string, referer string, target *map[string]any, contentTypes ...string) error {
	return doOpenAIJSONWithHeaders(ctx, client, method, endpoint, body, userAgent, referer, target, nil, contentTypes...)
}

func doOpenAIJSONWithHeaders(ctx context.Context, client *http.Client, method string, endpoint string, body io.Reader, userAgent string, referer string, target *map[string]any, extraHeaders map[string]string, contentTypes ...string) error {
	req, err := newOpenAIRequest(ctx, method, endpoint, body, userAgent, referer)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if len(contentTypes) > 0 && strings.TrimSpace(contentTypes[0]) != "" {
		req.Header.Set("Content-Type", contentTypes[0])
	}
	if strings.Contains(endpoint, "auth.openai.com") {
		req.Header.Set("Origin", authOpenAIOrigin)
	}
	for key, value := range extraHeaders {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			req.Header.Set(key, value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		if isCloudflareChallenge(resp, data) {
			return cloudflareChallengeError(endpoint, resp.StatusCode)
		}
		return fmt.Errorf("%s HTTP %d: %s", endpoint, resp.StatusCode, normalizeText(string(data), 260))
	}
	if len(data) == 0 {
		*target = map[string]any{}
		return nil
	}
	if err := json.Unmarshal(data, target); err != nil {
		return err
	}
	return nil
}

func newOpenAIRequest(ctx context.Context, method string, endpoint string, body io.Reader, userAgent string, referer string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", recoveryBrowserUserAgent(userAgent))
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	if referer != "" {
		req.Header.Set("Referer", referer)
	}
	return req, nil
}

func mustJSONReader(payload any) io.Reader {
	data, _ := json.Marshal(payload)
	return bytes.NewReader(data)
}

func normalizeURL(raw string, base string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err == nil && parsed.IsAbs() {
		return parsed.String()
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return trimmed
	}
	return baseURL.ResolveReference(parsed).String()
}

func extractContinueURL(data map[string]any) string {
	return extractContinueURLFromAny(data)
}

func extractContinueURLFromAny(value any) string {
	switch typed := value.(type) {
	case map[string]any:
		for _, key := range []string{
			"continue_url",
			"continueUrl",
			"continue",
			"continue_to",
			"continueTo",
			"redirect_url",
			"redirectUrl",
			"redirect_uri",
			"redirectUri",
			"return_to",
			"returnTo",
			"next_url",
			"nextUrl",
			"authorization_url",
			"authorizationUrl",
			"authorize_url",
			"authorizeUrl",
			"callback_url",
			"callbackUrl",
			"location",
			"href",
			"url",
		} {
			if value := strings.TrimSpace(stringValue(typed[key])); looksLikeOpenAIContinueURL(value) {
				return value
			}
		}
		for _, key := range []string{"page", "payload", "data", "result", "next", "authorization", "auth"} {
			if found := extractContinueURLFromAny(typed[key]); found != "" {
				return found
			}
		}
		for _, nested := range typed {
			if found := extractContinueURLFromAny(nested); found != "" {
				return found
			}
		}
	case []any:
		for _, item := range typed {
			if found := extractContinueURLFromAny(item); found != "" {
				return found
			}
		}
	}
	return ""
}

func looksLikeOpenAIContinueURL(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	lower := strings.ToLower(trimmed)
	return strings.HasPrefix(trimmed, "/") ||
		strings.HasPrefix(lower, "https://auth.openai.com/") ||
		strings.HasPrefix(lower, "https://chatgpt.com/") ||
		strings.HasPrefix(lower, "https://chat.openai.com/")
}

func openAIPageType(data map[string]any) string {
	for _, path := range []string{"page.type", "type", "screen", "name"} {
		if value := strings.ToLower(strings.TrimSpace(stringValue(mapValue(data, path)))); value != "" {
			return value
		}
	}
	return ""
}

func openAIPageRequiresPhone(data map[string]any) bool {
	pageType := openAIPageType(data)
	if strings.Contains(pageType, "phone") {
		return true
	}
	collected := make([]string, 0)
	collectStrings(data, &collected)
	for _, text := range collected {
		lower := strings.ToLower(text)
		if strings.Contains(lower, "phone") && (strings.Contains(lower, "verification") ||
			strings.Contains(lower, "verify") ||
			strings.Contains(lower, "challenge") ||
			strings.Contains(lower, "number")) {
			return true
		}
	}
	return false
}

func openAIResponseIndicatesAccessDeactivated(data map[string]any) bool {
	if openAITextIndicatesAccessDeactivated(openAIPageType(data)) {
		return true
	}
	collected := make([]string, 0)
	collectStrings(data, &collected)
	for _, text := range collected {
		if openAITextIndicatesAccessDeactivated(text) {
			return true
		}
	}
	return false
}

func openAIURLIndicatesAccessDeactivated(rawURL string) bool {
	if strings.TrimSpace(rawURL) == "" {
		return false
	}
	return openAITextIndicatesAccessDeactivated(rawURL)
}

func openAITextIndicatesAccessDeactivated(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return false
	}
	for _, marker := range []string{
		"access_deactivated",
		"access deactivated",
		"account_deactivated",
		"account deactivated",
		"deactivated account",
		"account_disabled",
		"account disabled",
		"account_suspended",
		"account suspended",
		"账户已被删除或停用",
		"账户已被删除",
		"账户已被停用",
		"账号已被删除或停用",
		"账号已被删除",
		"账号已被停用",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func openAIResponseLooksComplete(data map[string]any) bool {
	pageType := openAIPageType(data)
	if pageType == "" && len(data) == 0 {
		return true
	}
	for _, marker := range []string{"complete", "completed", "success", "done"} {
		if strings.Contains(pageType, marker) {
			return true
		}
	}
	for _, path := range []string{"ok", "success", "complete", "completed"} {
		if boolValueFromAny(mapValue(data, path)) {
			return true
		}
	}
	if status := strings.ToLower(strings.TrimSpace(stringValue(mapValue(data, "status")))); status != "" {
		for _, marker := range []string{"complete", "completed", "success", "done"} {
			if strings.Contains(status, marker) {
				return true
			}
		}
	}
	return false
}

func openAIPageSummary(data map[string]any) string {
	parts := make([]string, 0, 2)
	if pageType := openAIPageType(data); pageType != "" {
		parts = append(parts, "page="+pageType)
	}
	keys := make([]string, 0, len(data))
	for key := range data {
		if strings.TrimSpace(key) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) > 8 {
		keys = keys[:8]
	}
	if len(keys) > 0 {
		parts = append(parts, "keys="+strings.Join(keys, ","))
	}
	if len(parts) == 0 {
		return "empty response"
	}
	return strings.Join(parts, "; ")
}

func needsModernOTP(pageType string, continueURL string) bool {
	lowerURL := strings.ToLower(continueURL)
	return pageType == "email_otp_verification" || strings.Contains(lowerURL, "/email-verification") || continueURL == ""
}

func mapValue(data map[string]any, dotted string) any {
	current := any(data)
	for _, part := range strings.Split(dotted, ".") {
		asMap, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = asMap[part]
	}
	return current
}
