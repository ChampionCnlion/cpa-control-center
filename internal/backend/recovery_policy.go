package backend

import (
	"net/http"
	"sort"
	"strings"
	"time"
)

func isQuotaRecoveryManaged(record AccountRecord) bool {
	return record.Disabled && strings.TrimSpace(record.ManagedReason) == "quota_disabled"
}

func quotaRecoveryMinRemainingPercent(settings AppSettings) float64 {
	if settings.QuotaRecoveryMinRemainingPercent >= 1 {
		return float64(settings.QuotaRecoveryMinRemainingPercent)
	}
	return float64(defaultQuotaRecoveryMinRemainingPercent)
}

func quotaRecoveryConfirmationPasses(settings AppSettings) int {
	if settings.QuotaRecoveryConfirmationPasses >= 1 {
		return settings.QuotaRecoveryConfirmationPasses
	}
	return defaultQuotaRecoveryConfirmationPasses
}

func quotaRecoveryLookaheadMinutes(settings AppSettings) int {
	if settings.QuotaRecoveryLookaheadMinutes >= 0 {
		return settings.QuotaRecoveryLookaheadMinutes
	}
	return defaultQuotaRecoveryLookaheadMinutes
}

func quotaRecoveryFallbackProbeHours(settings AppSettings) int {
	if settings.QuotaRecoveryFallbackProbeHours >= 1 {
		return settings.QuotaRecoveryFallbackProbeHours
	}
	return defaultQuotaRecoveryFallbackProbeHours
}

func quotaRecoveryProbeLimit(settings AppSettings) int {
	if settings.QuotaRecoveryProbeLimit >= 1 {
		return settings.QuotaRecoveryProbeLimit
	}
	return defaultQuotaRecoveryProbeLimit
}

func quotaPrimaryLimitReached(planType string, result quotaBucketResult) bool {
	if result.weekly != nil && result.weekly.remainingPercent <= 0 {
		return true
	}
	if normalizeQuotaPlanType(planType) == "free" {
		return false
	}
	return result.fiveHour != nil && result.fiveHour.remainingPercent <= 0
}

func quotaRecoveryPrimaryReady(settings AppSettings, planType string, result quotaBucketResult) bool {
	threshold := quotaRecoveryMinRemainingPercent(settings)
	if result.weekly == nil || result.weekly.remainingPercent < threshold {
		return false
	}
	if normalizeQuotaPlanType(planType) == "free" {
		return true
	}
	return result.fiveHour != nil && result.fiveHour.remainingPercent >= threshold
}

func applyProbeRecoveryPolicy(settings AppSettings, record AccountRecord, quotaResult *quotaBucketResult, now time.Time) AccountRecord {
	managed := isQuotaRecoveryManaged(record)
	if managed && intValue(record.APIStatusCode) == http.StatusOK && !record.Invalid401 && !record.Error {
		if quotaResult == nil || !quotaRecoveryPrimaryReady(settings, record.PlanType, *quotaResult) {
			record.QuotaLimited = true
			record.Recovered = false
			record.StateKey = stateQuotaLimited
			record.State = stateQuotaLimited
		}
	}

	switch {
	case record.QuotaLimited:
		blockUntil := computeQuotaRecoveryBlockedUntil(settings, record, quotaResult, now)
		if blockUntil == "" {
			blockUntil = record.QuotaBlockedUntil
		}
		record.QuotaBlockedUntil = blockUntil
		record.RecoveryNextProbeAt = computeQuotaRecoveryNextProbeAt(settings, now, blockUntil)
		record.RecoveryPassCount = 0
		record.RecoveryLastPassedAt = ""
	case managed && record.Recovered:
		record.QuotaBlockedUntil = ""
		record.RecoveryNextProbeAt = ""
		record.RecoveryPassCount++
		record.RecoveryLastPassedAt = now.Format(time.RFC3339)
		if record.RecoveryPassCount < quotaRecoveryConfirmationPasses(settings) {
			record.QuotaLimited = true
			record.Recovered = false
			record.StateKey = stateQuotaLimited
			record.State = stateQuotaLimited
		}
	case managed:
		record.RecoveryPassCount = 0
		record.RecoveryLastPassedAt = ""
		if record.RecoveryNextProbeAt == "" || !parseAndCompareAfter(record.RecoveryNextProbeAt, now) {
			record.RecoveryNextProbeAt = now.Add(time.Duration(quotaRecoveryFallbackProbeHours(settings)) * time.Hour).Format(time.RFC3339)
		}
	default:
		record.QuotaBlockedUntil = ""
		record.RecoveryNextProbeAt = ""
		record.RecoveryPassCount = 0
		record.RecoveryLastPassedAt = ""
	}

	return sanitizeRecord(record)
}

func computeQuotaRecoveryBlockedUntil(settings AppSettings, record AccountRecord, quotaResult *quotaBucketResult, now time.Time) string {
	blockUntil := ""
	if inventoryUsageLimitResetAt, ok := inventoryUsageLimitResetAt(record.StatusMessage, now); ok {
		blockUntil = inventoryUsageLimitResetAt.Format(time.RFC3339)
	}
	if quotaResult == nil {
		return blockUntil
	}

	threshold := quotaRecoveryMinRemainingPercent(settings)
	if quotaResult.weekly != nil && quotaResult.weekly.remainingPercent < threshold {
		blockUntil = laterResetValue(blockUntil, quotaResult.weekly.resetAt)
	}
	if normalizeQuotaPlanType(record.PlanType) != "free" && quotaResult.fiveHour != nil && quotaResult.fiveHour.remainingPercent < threshold {
		blockUntil = laterResetValue(blockUntil, quotaResult.fiveHour.resetAt)
	}
	return blockUntil
}

func computeQuotaRecoveryNextProbeAt(settings AppSettings, now time.Time, blockUntil string) string {
	if resetAt, ok := parseRFC3339(blockUntil); ok {
		nextProbeAt := resetAt.Add(-time.Duration(quotaRecoveryLookaheadMinutes(settings)) * time.Minute)
		if nextProbeAt.After(now) {
			return nextProbeAt.Format(time.RFC3339)
		}
		return now.Format(time.RFC3339)
	}
	return now.Add(time.Duration(quotaRecoveryFallbackProbeHours(settings)) * time.Hour).Format(time.RFC3339)
}

func inventoryUsageLimitResetAt(statusMessage string, now time.Time) (time.Time, bool) {
	errorPayload := findUsageLimitErrorPayload(statusMessage)
	if len(errorPayload) == 0 {
		return time.Time{}, false
	}
	return usageLimitResetAt(errorPayload, now)
}

func laterResetValue(current string, candidate string) string {
	if candidate == "" {
		return current
	}
	if current == "" {
		return candidate
	}
	if earlierReset(current, candidate) {
		return candidate
	}
	return current
}

func parseRFC3339(value string) (time.Time, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, trimmed)
	if err != nil {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

func parseAndCompareAfter(value string, now time.Time) bool {
	parsed, ok := parseRFC3339(value)
	return ok && parsed.After(now)
}

func limitQuotaRecoveryProbeCandidates(settings AppSettings, candidates []AccountRecord, indexes []int) ([]AccountRecord, []int) {
	if len(candidates) == 0 {
		return candidates, indexes
	}

	regularCandidates := make([]AccountRecord, 0, len(candidates))
	regularIndexes := make([]int, 0, len(indexes))
	recoveryCandidates := make([]AccountRecord, 0, len(candidates))
	recoveryIndexes := make([]int, 0, len(indexes))
	for i, candidate := range candidates {
		if isQuotaRecoveryManaged(candidate) {
			recoveryCandidates = append(recoveryCandidates, candidate)
			recoveryIndexes = append(recoveryIndexes, indexes[i])
			continue
		}
		regularCandidates = append(regularCandidates, candidate)
		regularIndexes = append(regularIndexes, indexes[i])
	}
	if len(recoveryCandidates) == 0 {
		return candidates, indexes
	}

	order := make([]int, len(recoveryCandidates))
	for i := range recoveryCandidates {
		order[i] = i
	}
	sort.Slice(order, func(i int, j int) bool {
		left := recoveryCandidates[order[i]]
		right := recoveryCandidates[order[j]]
		if left.RecoveryNextProbeAt != right.RecoveryNextProbeAt {
			return left.RecoveryNextProbeAt < right.RecoveryNextProbeAt
		}
		if left.QuotaBlockedUntil != right.QuotaBlockedUntil {
			return left.QuotaBlockedUntil < right.QuotaBlockedUntil
		}
		if left.LastProbedAt != right.LastProbedAt {
			return left.LastProbedAt < right.LastProbedAt
		}
		return strings.ToLower(left.Name) < strings.ToLower(right.Name)
	})

	limit := quotaRecoveryProbeLimit(settings)
	if len(order) > limit {
		order = order[:limit]
	}

	selectedRecoveryCandidates := make([]AccountRecord, 0, len(order))
	selectedRecoveryIndexes := make([]int, 0, len(order))
	for _, idx := range order {
		selectedRecoveryCandidates = append(selectedRecoveryCandidates, recoveryCandidates[idx])
		selectedRecoveryIndexes = append(selectedRecoveryIndexes, recoveryIndexes[idx])
	}

	return append(regularCandidates, selectedRecoveryCandidates...), append(regularIndexes, selectedRecoveryIndexes...)
}
