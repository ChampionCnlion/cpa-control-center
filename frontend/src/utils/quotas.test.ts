import { describe, expect, it } from 'vitest'
import type { CodexQuotaAccountDetail } from '@/types'
import { compareQuotaAccounts, quotaTotalRemaining } from '@/utils/quotas'

function buildAccount(overrides: Partial<CodexQuotaAccountDetail> = {}): CodexQuotaAccountDetail {
  return {
    name: 'account-a',
    email: '',
    planType: 'team',
    provider: 'codex',
    success: true,
    error: '',
    fetchedAt: '2026-03-16T00:00:00Z',
    earliestResetAt: '',
    fiveHour: {
      supported: true,
      remainingPercent: 80,
      resetAt: '2026-03-16T05:00:00Z',
    },
    weekly: {
      supported: true,
      remainingPercent: 60,
      resetAt: '2026-03-18T00:00:00Z',
    },
    codeReviewWeekly: {
      supported: true,
      remainingPercent: 100,
      resetAt: '2026-03-17T00:00:00Z',
    },
    ...overrides,
  }
}

describe('quotaTotalRemaining', () => {
  it('uses the limiting primary quota bucket and ignores code review quota', () => {
    expect(quotaTotalRemaining(buildAccount())).toBe(60)
    expect(quotaTotalRemaining(buildAccount({
      weekly: {
        supported: true,
        remainingPercent: 0,
        resetAt: '2026-03-18T00:00:00Z',
      },
    }))).toBe(0)
  })

  it('falls back to the weekly bucket for free plans', () => {
    expect(quotaTotalRemaining(buildAccount({
      planType: 'free',
      fiveHour: {
        supported: false,
        remainingPercent: null,
        resetAt: '',
      },
      weekly: {
        supported: true,
        remainingPercent: 45,
        resetAt: '2026-03-18T00:00:00Z',
      },
    }))).toBe(45)
  })
})

describe('compareQuotaAccounts', () => {
  it('sorts by effective remaining instead of summed buckets', () => {
    const quotaBlocked = buildAccount({
      name: 'quota-blocked',
      fiveHour: {
        supported: true,
        remainingPercent: 90,
        resetAt: '2026-03-16T05:00:00Z',
      },
      weekly: {
        supported: true,
        remainingPercent: 10,
        resetAt: '2026-03-18T00:00:00Z',
      },
      codeReviewWeekly: {
        supported: true,
        remainingPercent: 100,
        resetAt: '2026-03-17T00:00:00Z',
      },
    })
    const healthier = buildAccount({
      name: 'healthier',
      fiveHour: {
        supported: true,
        remainingPercent: 55,
        resetAt: '2026-03-16T06:00:00Z',
      },
      weekly: {
        supported: true,
        remainingPercent: 50,
        resetAt: '2026-03-18T00:00:00Z',
      },
      codeReviewWeekly: {
        supported: true,
        remainingPercent: 0,
        resetAt: '2026-03-20T00:00:00Z',
      },
    })

    expect(compareQuotaAccounts('total')(quotaBlocked, healthier)).toBeGreaterThan(0)
  })
})
