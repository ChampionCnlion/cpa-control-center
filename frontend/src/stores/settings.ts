import { defineStore } from 'pinia'
import { i18n, setI18nLocale } from '@/i18n'
import { getSchedulerStatus, getSettings, onEvent, saveSettings, testAndSaveSettings, testConnection } from '@/lib/bridge'
import type { AppSettings, ConnectionResult, SchedulerStatus } from '@/types'
import { createDefaultScheduleSettings, createDefaultSettings, validateSettings } from '@/utils/settings'
import { toErrorMessage } from '@/utils/errors'
import { detectPreferredLocale, normalizeLocaleCode } from '@/utils/locale'

let disposeSchedulerBridge: (() => void) | null = null

interface SettingsState {
  settings: AppSettings
  connection: ConnectionResult | null
  schedulerStatus: SchedulerStatus
  loading: boolean
  saving: boolean
  errors: Record<string, string>
  schedulerBridgeReady: boolean
}

function createDefaultSchedulerStatus(): SchedulerStatus {
  return {
    enabled: false,
    mode: 'scan',
    cron: '',
    valid: true,
    validationMessage: '',
    running: false,
    nextRunAt: '',
    lastStartedAt: '',
    lastFinishedAt: '',
    lastStatus: '',
    lastMessage: '',
  }
}

export const useSettingsStore = defineStore('settingsStore', {
  state: (): SettingsState => ({
    settings: createDefaultSettings(),
    connection: null,
    schedulerStatus: createDefaultSchedulerStatus(),
    loading: false,
    saving: false,
    errors: {},
    schedulerBridgeReady: false,
  }),
  getters: {
    connectionTone: (state) => {
      if (!state.connection) {
        return 'idle'
      }
      return state.connection.ok ? 'ok' : 'error'
    },
    currentLocale: (state) => normalizeLocaleCode(state.settings.locale || i18n.global.locale.value),
  },
  actions: {
    mergeSettings(result: Partial<AppSettings>) {
      this.settings = {
        ...createDefaultSettings(),
        ...result,
        schedule: {
          ...createDefaultScheduleSettings(),
          ...(result.schedule ?? {}),
        },
      }
      this.applyLocale(this.settings.locale)
    },
    applySchedulerStatus(status?: Partial<SchedulerStatus> | null) {
      this.schedulerStatus = {
        ...createDefaultSchedulerStatus(),
        ...(status ?? {}),
      }
    },
    initSchedulerBridge() {
      if (this.schedulerBridgeReady) {
        return
      }
      disposeSchedulerBridge = onEvent('scheduler:status', (status: SchedulerStatus) => this.applySchedulerStatus(status))
      this.schedulerBridgeReady = true
    },
    destroySchedulerBridge() {
      if (!this.schedulerBridgeReady) {
        return
      }
      disposeSchedulerBridge?.()
      disposeSchedulerBridge = null
      this.schedulerBridgeReady = false
    },
    applyLocale(locale?: string) {
      const next = setI18nLocale(locale || detectPreferredLocale())
      this.settings.locale = next
    },
    async loadSchedulerStatus() {
      const status = await getSchedulerStatus()
      this.applySchedulerStatus(status as Partial<SchedulerStatus>)
      return this.schedulerStatus
    },
    async persistSettings() {
      const saved = await saveSettings(this.settings)
      this.mergeSettings(saved as Partial<AppSettings>)
      await this.loadSchedulerStatus()
      return this.settings
    },
    async loadSettings() {
      this.loading = true
      try {
        const result = await getSettings()
        this.mergeSettings(result as Partial<AppSettings>)
        await this.loadSchedulerStatus()
      } finally {
        this.loading = false
      }
    },
    async saveLocalePreference(locale: string) {
      const previous = this.currentLocale
      this.applyLocale(locale)
      try {
        await this.persistSettings()
      } catch (error) {
        this.applyLocale(previous)
        throw new Error(toErrorMessage(error))
      }
    },
    async testConnection() {
      this.errors = validateSettings(this.settings, i18n.global.t)
      if (Object.keys(this.errors).length > 0) {
        throw new Error(i18n.global.t('validation.fixBeforeTesting'))
      }
      this.connection = await testConnection(this.settings)
      return this.connection
    },
    async saveSettings() {
      this.errors = validateSettings(this.settings, i18n.global.t)
      if (Object.keys(this.errors).length > 0) {
        throw new Error(i18n.global.t('validation.fixBeforeSaving'))
      }
      this.saving = true
      try {
        return await this.persistSettings()
      } finally {
        this.saving = false
      }
    },
    async testAndSave() {
      try {
        this.errors = validateSettings(this.settings, i18n.global.t)
        if (Object.keys(this.errors).length > 0) {
          throw new Error(i18n.global.t('validation.fixBeforeSaving'))
        }
        this.saving = true
        const connection = await testAndSaveSettings(this.settings)
        await this.loadSettings()
        this.connection = connection
        return connection
      } catch (error) {
        throw new Error(toErrorMessage(error))
      } finally {
        this.saving = false
      }
    },
  },
})
