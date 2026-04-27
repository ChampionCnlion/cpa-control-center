import { describe, expect, it } from 'vitest'
import { createDefaultSettings, validateSettings } from '@/utils/settings'

describe('validateSettings', () => {
  it('accepts a valid CPA profile', () => {
    const settings = createDefaultSettings()
    expect(settings.detailedLogs).toBe(false)
    expect(settings.scanStrategy).toBe('full')
    expect(settings.scanBatchSize).toBe(1000)
    expect(settings.skipKnown401).toBe(true)
    expect(settings.quotaWorkers).toBe(10)
    expect(settings.quotaCheckFree).toBe(false)
    expect(settings.quotaCheckTeam).toBe(true)
    expect(settings.quotaFreeMaxAccounts).toBe(100)
    expect(settings.quotaAutoRefreshEnabled).toBe(false)
    expect(settings.quotaAutoRefreshCron).toBe('')
    expect(settings.quotaRecoveryMinRemainingPercent).toBe(2)
    expect(settings.quotaRecoveryConfirmationPasses).toBe(2)
    expect(settings.quotaRecoveryLookaheadMinutes).toBe(30)
    expect(settings.quotaRecoveryFallbackProbeHours).toBe(6)
    expect(settings.quotaRecoveryProbeLimit).toBe(50)
    settings.baseUrl = 'https://example.com'
    settings.managementToken = 'token'

    expect(validateSettings(settings)).toEqual({})
  })

  it('rejects missing or malformed core fields', () => {
    const settings = createDefaultSettings()
    settings.baseUrl = 'example.com'
    settings.managementToken = ''
    settings.probeWorkers = 0
    settings.quotaWorkers = 0
    settings.quotaFreeMaxAccounts = -2
    settings.quotaRecoveryMinRemainingPercent = 0
    settings.quotaRecoveryConfirmationPasses = 0
    settings.quotaRecoveryLookaheadMinutes = -1
    settings.quotaRecoveryFallbackProbeHours = 0
    settings.quotaRecoveryProbeLimit = 0

    expect(validateSettings(settings)).toMatchObject({
      baseUrl: expect.any(String),
      managementToken: expect.any(String),
      probeWorkers: expect.any(String),
      quotaWorkers: expect.any(String),
      quotaFreeMaxAccounts: expect.any(String),
      quotaRecoveryMinRemainingPercent: expect.any(String),
      quotaRecoveryConfirmationPasses: expect.any(String),
      quotaRecoveryLookaheadMinutes: expect.any(String),
      quotaRecoveryFallbackProbeHours: expect.any(String),
      quotaRecoveryProbeLimit: expect.any(String),
    })
  })

  it('rejects invalid scheduler settings when enabled', () => {
    const settings = createDefaultSettings()
    settings.baseUrl = 'https://example.com'
    settings.managementToken = 'token'
    settings.schedule.enabled = true
    settings.schedule.mode = 'scan'
    settings.schedule.cron = 'not-a-cron'

    expect(validateSettings(settings)).toMatchObject({
      scheduleCron: expect.any(String),
    })
  })

  it('rejects invalid quota auto refresh cron when enabled', () => {
    const settings = createDefaultSettings()
    settings.baseUrl = 'https://example.com'
    settings.managementToken = 'token'
    settings.quotaAutoRefreshEnabled = true
    settings.quotaAutoRefreshCron = 'bad cron'

    expect(validateSettings(settings)).toMatchObject({
      quotaAutoRefreshCron: expect.any(String),
    })
  })

  it('accepts a valid 5-field cron expression', () => {
    const settings = createDefaultSettings()
    settings.baseUrl = 'https://example.com'
    settings.managementToken = 'token'
    settings.schedule.enabled = true
    settings.schedule.mode = 'maintain'
    settings.schedule.cron = '0 */6 * * *'

    expect(validateSettings(settings)).toEqual({})
  })

  it('rejects invalid incremental scan settings', () => {
    const settings = createDefaultSettings()
    settings.baseUrl = 'https://example.com'
    settings.managementToken = 'token'
    settings.scanStrategy = 'incremental'
    settings.scanBatchSize = 0

    expect(validateSettings(settings)).toMatchObject({
      scanBatchSize: expect.any(String),
    })
  })
})
