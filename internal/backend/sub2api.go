package backend

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const sub2APIKind = "sub2api"

var sub2APITargetNameUnsafe = regexp.MustCompile(`[^A-Za-z0-9@._+\-]+`)

type sub2APIConvertCandidateInternal struct {
	SourceName   string
	TargetName   string
	AccountIndex int
	Account       sub2APIAccountInfo
	CPA          map[string]any
	Message      string
}

func (b *Backend) ScanSub2APIConversion() (Sub2APIConvertScanResult, error) {
	settings, err := b.store.LoadSettings()
	if err != nil {
		return Sub2APIConvertScanResult{}, err
	}
	if err := ensureConfigured(settings); err != nil {
		return Sub2APIConvertScanResult{}, err
	}

	ctx, err := b.beginTask(sub2APIKind, settings.Locale)
	if err != nil {
		return Sub2APIConvertScanResult{}, err
	}
	defer b.endTask()

	status := "success"
	finishMessage := "Sub2API conversion scan completed"
	defer func() {
		b.emitTaskFinished(sub2APIKind, status, finishMessage)
	}()

	result, _, err := b.scanSub2APIConversion(ctx, settings)
	if err != nil {
		status = taskStatus(err)
		finishMessage = err.Error()
		b.emitLog(sub2APIKind, "warning", finishMessage)
		return Sub2APIConvertScanResult{}, err
	}
	finishMessage = fmt.Sprintf("Sub2API conversion scan completed: %d convertible accounts from %d files", result.ConvertibleAccounts, result.ScannedFiles)
	b.emitLog(sub2APIKind, "info", finishMessage)
	return result, nil
}

func (b *Backend) RunSub2APIConversion(options Sub2APIConvertOptions) (Sub2APIConvertResult, error) {
	settings, err := b.store.LoadSettings()
	if err != nil {
		return Sub2APIConvertResult{}, err
	}
	if err := ensureConfigured(settings); err != nil {
		return Sub2APIConvertResult{}, err
	}

	ctx, err := b.beginTask(sub2APIKind, settings.Locale)
	if err != nil {
		return Sub2APIConvertResult{}, err
	}
	defer b.endTask()

	status := "success"
	finishMessage := "Sub2API conversion completed"
	defer func() {
		b.emitTaskFinished(sub2APIKind, status, finishMessage)
	}()

	scan, candidates, err := b.scanSub2APIConversion(ctx, settings)
	if err != nil {
		status = taskStatus(err)
		finishMessage = err.Error()
		return Sub2APIConvertResult{}, err
	}

	limit := options.MaxAccounts
	if limit <= 0 || limit > len(candidates) {
		limit = len(candidates)
	}
	selected := candidates[:limit]
	result := Sub2APIConvertResult{
		Summary: Sub2APIConvertSummary{
			TotalFiles: scan.TotalFiles,
			Candidates: len(candidates),
		},
		Results: make([]Sub2APIConvertItemResult, 0, len(selected)),
	}
	if len(selected) == 0 {
		finishMessage = "No convertible Sub2API OpenAI accounts found"
		b.emitProgress(sub2APIKind, "complete", 0, 0, finishMessage, true)
		return result, nil
	}

	uploadedAny := false
	existingNames := make(map[string]struct{})
	files, fetchErr := b.client.FetchAuthFiles(ctx, settings)
	if fetchErr == nil {
		for _, file := range files {
			if name := strings.TrimSpace(stringValue(file["name"])); name != "" {
				existingNames[name] = struct{}{}
			}
		}
	} else {
		b.emitLog(sub2APIKind, "warning", "Unable to refresh existing target names before conversion: "+fetchErr.Error())
	}

	for index, candidate := range selected {
		if err := ctx.Err(); err != nil {
			status = taskStatus(err)
			finishMessage = err.Error()
			return result, err
		}
		result.Summary.Processed++
		b.emitProgress(sub2APIKind, "convert", index, len(selected), fmt.Sprintf("Converting %s", candidate.SourceName), false)

		item := b.convertOneSub2APIAccount(ctx, settings, candidate, existingNames, options)
		result.Results = append(result.Results, item)
		if item.Action == "uploaded" || item.Action == "verify_failed" {
			uploadedAny = true
		}
		switch {
		case item.OK && item.Action == "uploaded":
			result.Summary.Uploaded++
			if strings.Contains(strings.ToLower(item.Message), "verified") {
				result.Summary.Verified++
			}
			if strings.Contains(strings.ToLower(item.Message), "quota-limited") {
				result.Summary.QuotaLimited++
			}
			existingNames[item.TargetName] = struct{}{}
		case item.Action == "skipped":
			result.Summary.Skipped++
		default:
			result.Summary.Failed++
		}
		level := "info"
		if !item.OK {
			level = "warning"
		}
		b.emitLog(sub2APIKind, level, fmt.Sprintf("%s -> %s: %s", item.SourceName, item.TargetName, item.Message))
		b.emitProgress(sub2APIKind, "convert", index+1, len(selected), item.Message, index+1 == len(selected))
	}

	if result.Summary.Failed > 0 {
		finishMessage = fmt.Sprintf("Sub2API conversion completed with %d failures", result.Summary.Failed)
	} else {
		finishMessage = "Sub2API conversion completed"
	}
	b.emitProgress(sub2APIKind, "complete", result.Summary.Processed, len(selected), finishMessage, true)

	if uploadedAny {
		if refreshedFiles, syncErr := b.client.FetchAuthFiles(ctx, settings); syncErr == nil {
			syncResult, syncErr := b.syncInventoryFromFiles(settings, refreshedFiles)
			if syncErr == nil {
				b.emitLog(sub2APIKind, "info", fmt.Sprintf("Inventory refreshed after Sub2API conversion: %d/%d", syncResult.FilteredAccounts, syncResult.TotalAccounts))
			} else {
				b.emitLog(sub2APIKind, "warning", fmt.Sprintf("Inventory refresh after Sub2API conversion failed: %s", syncErr.Error()))
			}
		} else {
			b.emitLog(sub2APIKind, "warning", fmt.Sprintf("Inventory refresh after Sub2API conversion failed: %s", syncErr.Error()))
		}
	}
	return result, nil
}

func (b *Backend) scanSub2APIConversion(ctx context.Context, settings AppSettings) (Sub2APIConvertScanResult, []sub2APIConvertCandidateInternal, error) {
	b.emitLog(sub2APIKind, "info", "Starting Sub2API conversion scan")
	b.emitProgress(sub2APIKind, "fetch", 0, 1, "Loading CPA auth inventory", false)
	files, err := b.client.FetchAuthFiles(ctx, settings)
	if err != nil {
		b.emitProgress(sub2APIKind, "fetch", 0, 1, err.Error(), true)
		return Sub2APIConvertScanResult{}, nil, err
	}
	b.emitProgress(sub2APIKind, "fetch", 1, 1, fmt.Sprintf("Loaded %d auth records", len(files)), true)

	result := Sub2APIConvertScanResult{
		TotalFiles: len(files),
		Candidates: make([]Sub2APIConvertCandidate, 0),
	}
	candidates := make([]sub2APIConvertCandidateInternal, 0)
	seenFiles := make(map[string]struct{})
	for index, file := range files {
		if err := ctx.Err(); err != nil {
			return result, candidates, err
		}
		name := strings.TrimSpace(stringValue(file["name"]))
		if name == "" {
			continue
		}
		if _, ok := seenFiles[name]; ok {
			continue
		}
		seenFiles[name] = struct{}{}
		result.ScannedFiles++
		if result.ScannedFiles%100 == 0 {
			b.emitProgress(sub2APIKind, "scan", result.ScannedFiles, len(files), fmt.Sprintf("Scanned %d auth files", result.ScannedFiles), false)
		}

		fullAuth, downloadErr := b.client.DownloadAuthFile(ctx, settings, name)
		if downloadErr != nil {
			continue
		}
		fileCandidates, skipped := sub2APIConvertCandidatesFromAuth(name, fullAuth)
		result.SkippedAccounts += skipped
		if len(fileCandidates) == 0 {
			continue
		}
		result.ConvertibleFiles++
		for _, candidate := range fileCandidates {
			result.Candidates = append(result.Candidates, sub2APIConvertCandidateSummary(candidate))
			candidates = append(candidates, candidate)
		}
		if index == len(files)-1 {
			b.emitProgress(sub2APIKind, "scan", result.ScannedFiles, len(files), fmt.Sprintf("Scanned %d auth files", result.ScannedFiles), false)
		}
	}
	sort.SliceStable(result.Candidates, func(i int, j int) bool {
		if result.Candidates[i].SourceName == result.Candidates[j].SourceName {
			return result.Candidates[i].AccountIndex < result.Candidates[j].AccountIndex
		}
		return result.Candidates[i].SourceName < result.Candidates[j].SourceName
	})
	sort.SliceStable(candidates, func(i int, j int) bool {
		if candidates[i].SourceName == candidates[j].SourceName {
			return candidates[i].AccountIndex < candidates[j].AccountIndex
		}
		return candidates[i].SourceName < candidates[j].SourceName
	})
	result.ConvertibleAccounts = len(candidates)
	b.emitProgress(sub2APIKind, "complete", result.ScannedFiles, len(files), fmt.Sprintf("Found %d convertible Sub2API accounts", result.ConvertibleAccounts), true)
	return result, candidates, nil
}

func sub2APIConvertCandidatesFromAuth(sourceName string, authJSON map[string]any) ([]sub2APIConvertCandidateInternal, int) {
	accounts := sub2APIOpenAIAccounts(authJSON)
	candidates := make([]sub2APIConvertCandidateInternal, 0, len(accounts))
	skipped := 0
	for index, account := range accounts {
		cpa, message := buildCPAAuthJSONFromSub2APIAccount(account)
		if message != "" {
			skipped++
			continue
		}
		candidate := sub2APIConvertCandidateInternal{
			SourceName:   sourceName,
			TargetName:   sub2APITargetName(sourceName, account, cpa),
			AccountIndex: index,
			Account:       account,
			CPA:           cpa,
			Message:       "convertible",
		}
		candidates = append(candidates, candidate)
	}
	return candidates, skipped
}

func buildCPAAuthJSONFromSub2APIAccount(account sub2APIAccountInfo) (map[string]any, string) {
	credentials := account.Credentials
	accessToken := strings.TrimSpace(stringOr(stringValue(credentials["access_token"]), stringValue(credentials["accessToken"])))
	if accessToken == "" {
		return nil, "missing access_token"
	}
	accountID := strings.TrimSpace(stringOr(
		stringValue(credentials["chatgpt_account_id"]),
		stringValue(credentials["chatgptAccountId"]),
		stringValue(credentials["account_id"]),
		stringValue(credentials["accountId"]),
	))
	if accountID == "" {
		if claims := decodeJWTPayload(accessToken); claims != nil {
			accountID = chatGPTAccountIDFromClaims(claims)
		}
	}
	if accountID == "" {
		return nil, "missing chatgpt_account_id"
	}

	email := strings.TrimSpace(stringOr(
		account.Name,
		stringValue(credentials["email"]),
		stringValue(credentials["account"]),
	))
	organizationID := strings.TrimSpace(stringValue(credentials["organization_id"]))
	planType := strings.TrimSpace(stringOr(
		chatGPTPlanTypeFromClaims(credentials),
		stringValue(credentials["plan_type"]),
		stringValue(credentials["planType"]),
	))
	refreshToken := strings.TrimSpace(stringOr(stringValue(credentials["refresh_token"]), stringValue(credentials["refreshToken"])))
	idToken := strings.TrimSpace(stringOr(stringValue(credentials["id_token"]), stringValue(credentials["idToken"])))
	expiresAt := ""
	if rawExpiresAt, ok := credentials["expires_at"].(string); ok {
		expiresAt = strings.TrimSpace(rawExpiresAt)
	}

	info := chatGPTSessionInfo{
		Email:          email,
		AccessToken:    accessToken,
		IDToken:        idToken,
		AccountID:      accountID,
		OrganizationID: organizationID,
		PlanType:       planType,
		ExpiresAt:      expiresAt,
	}
	if expiresAtUnix, ok := intValueFromAny(credentials["expires_at"]); ok {
		info.ExpiresAtUnix = int64(expiresAtUnix)
		info.ExpiresAt = time.Unix(int64(expiresAtUnix), 0).UTC().Format(time.RFC3339)
	} else if parsedExpiresAt, err := strconv.ParseInt(expiresAt, 10, 64); err == nil && parsedExpiresAt > 0 {
		info.ExpiresAtUnix = parsedExpiresAt
		info.ExpiresAt = time.Unix(parsedExpiresAt, 0).UTC().Format(time.RFC3339)
	}
	if claims := decodeJWTPayload(accessToken); claims != nil {
		authClaims, _ := claims["https://api.openai.com/auth"].(map[string]any)
		profileClaims, _ := claims["https://api.openai.com/profile"].(map[string]any)
		if info.Email == "" {
			info.Email = strings.TrimSpace(stringOr(stringValue(claims["email"]), stringValue(profileClaims["email"]), stringValue(authClaims["email"])))
		}
		if info.OrganizationID == "" {
			info.OrganizationID = strings.TrimSpace(stringValue(authClaims["organization_id"]))
		}
		if info.PlanType == "" {
			info.PlanType = strings.TrimSpace(stringOr(stringValue(authClaims["chatgpt_plan_type"]), stringValue(authClaims["plan_type"])))
		}
		if exp, ok := intValueFromAny(claims["exp"]); ok && exp > 0 {
			info.ExpiresAtUnix = int64(exp)
			if info.ExpiresAt == "" {
				info.ExpiresAt = time.Unix(int64(exp), 0).UTC().Format(time.RFC3339)
			}
		}
	}
	resolvedIDToken, synthetic := resolveCodexIDToken(info)

	output := map[string]any{
		"type":                "codex",
		"email":               info.Email,
		"account_id":          info.AccountID,
		"chatgpt_account_id":  info.AccountID,
		"organization_id":     info.OrganizationID,
		"plan_type":           info.PlanType,
		"chatgpt_plan_type":   info.PlanType,
		"id_token":            resolvedIDToken,
		"access_token":        info.AccessToken,
		"refresh_token":       refreshToken,
		"last_refresh":        nowISO(),
		"expired":             info.ExpiresAt,
		"disabled":            false,
		"id_token_synthetic":  synthetic,
		"sub2api_converted":   true,
		"sub2api_account_type": account.Type,
	}
	if modelMapping, ok := credentials["model_mapping"]; ok {
		output["model_mapping"] = modelMapping
	}
	return output, ""
}

func sub2APITargetName(sourceName string, account sub2APIAccountInfo, cpa map[string]any) string {
	email := strings.TrimSpace(stringValue(cpa["email"]))
	planType := strings.ToLower(strings.TrimSpace(stringValue(cpa["plan_type"])))
	accountID := strings.TrimSpace(stringValue(cpa["chatgpt_account_id"]))
	base := email
	if base == "" {
		base = strings.TrimSpace(account.Name)
	}
	if base == "" {
		base = accountID
	}
	if base == "" {
		base = strings.TrimSuffix(path.Base(sourceName), path.Ext(sourceName))
	}
	safeBase := strings.Trim(sub2APITargetNameUnsafe.ReplaceAllString(base, "-"), "-")
	if safeBase == "" {
		safeBase = "sub2api"
	}
	suffix := ""
	if planType != "" {
		suffix = "-" + sub2APITargetNameUnsafe.ReplaceAllString(planType, "-")
	}
	return "codex-" + safeBase + suffix + ".json"
}

func sub2APIConvertCandidateSummary(candidate sub2APIConvertCandidateInternal) Sub2APIConvertCandidate {
	return Sub2APIConvertCandidate{
		SourceName:   candidate.SourceName,
		TargetName:   candidate.TargetName,
		AccountIndex: candidate.AccountIndex,
		Email:        strings.TrimSpace(stringValue(candidate.CPA["email"])),
		Provider:     "codex",
		PlanType:     strings.TrimSpace(stringValue(candidate.CPA["plan_type"])),
		AccountID:    strings.TrimSpace(stringValue(candidate.CPA["chatgpt_account_id"])),
		Message:      candidate.Message,
	}
}

func (b *Backend) convertOneSub2APIAccount(ctx context.Context, settings AppSettings, candidate sub2APIConvertCandidateInternal, existingNames map[string]struct{}, options Sub2APIConvertOptions) Sub2APIConvertItemResult {
	email := strings.TrimSpace(stringValue(candidate.CPA["email"]))
	result := Sub2APIConvertItemResult{
		SourceName: candidate.SourceName,
		TargetName: candidate.TargetName,
		Email:      email,
		Action:     "uploaded",
	}
	if _, ok := existingNames[candidate.TargetName]; ok && !options.Overwrite {
		result.Action = "skipped"
		result.Message = "target auth file already exists"
		return result
	}
	if err := validateCPAAuthJSON(candidate.CPA); err != nil {
		result.Action = "convert_failed"
		result.Message = err.Error()
		return result
	}
	if err := b.client.UploadAuthFile(ctx, settings, candidate.TargetName, candidate.CPA); err != nil {
		result.Action = "upload_failed"
		result.Message = "upload failed: " + err.Error()
		return result
	}
	if options.SkipVerify {
		result.OK = true
		result.Message = "converted and uploaded"
		return result
	}
	probe, err := b.verifyRecoveredAuthFile(ctx, settings, candidate.TargetName, candidate.CPA)
	if err != nil {
		result.Action = "verify_failed"
		result.Message = "uploaded but verification failed: " + err.Error()
		return result
	}
	result.OK = true
	if probe.Record.QuotaLimited {
		result.Message = "converted, uploaded, verified; account is authenticated but quota-limited"
	} else {
		result.Message = "converted, uploaded, and verified"
	}
	return result
}
