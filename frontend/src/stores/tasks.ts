import { defineStore } from 'pinia'
import { i18n } from '@/i18n'
import { cancelCurrentTask, getRecentLogs, onEvent, run401Recovery, runMaintain, runScan, runSub2APIConversion } from '@/lib/bridge'
import type { CodexQuotaSnapshot, LogEntry, MaintainOptions, Recovery401Options, Sub2APIConvertOptions, TaskFinished, TaskProgress } from '@/types'
import { toErrorMessage } from '@/utils/errors'
import { useAccountsStore } from '@/stores/accounts'
import { useQuotasStore } from '@/stores/quotas'
import { taskPhaseLabel } from '@/utils/status'

let eventDisposers: Array<() => void> = []

interface TaskTracker {
  active: boolean
  phase: string
  current: number
  total: number
  message: string
}

interface TasksState {
  scan: TaskTracker
  maintain: TaskTracker
  inventory: TaskTracker
  quota: TaskTracker
  recovery: TaskTracker
  sub2api: TaskTracker
  inventoryQueued: boolean
  logs: LogEntry[]
  initialised: boolean
}

function emptyTracker(): TaskTracker {
  return {
    active: false,
    phase: 'idle',
    current: 0,
    total: 0,
    message: '',
  }
}

type TaskKind = 'scan' | 'maintain' | 'inventory' | 'quota' | 'recovery' | 'sub2api'

function progressEntryId(kind: TaskKind): string {
  return `${kind}:progress`
}

function progressMessage(payload: TaskProgress): string {
  const phase = taskPhaseLabel(payload.phase)
  if (payload.total > 0) {
    return payload.message ? `${phase} ${payload.current}/${payload.total} · ${payload.message}` : `${phase} ${payload.current}/${payload.total}`
  }
  return payload.message || phase
}

export const useTasksStore = defineStore('tasksStore', {
  state: (): TasksState => ({
    scan: emptyTracker(),
    maintain: emptyTracker(),
    inventory: emptyTracker(),
    quota: emptyTracker(),
    recovery: emptyTracker(),
    sub2api: emptyTracker(),
    inventoryQueued: false,
    logs: [],
    initialised: false,
  }),
  getters: {
    hasActiveTask: (state) => state.scan.active || state.maintain.active || state.inventory.active || state.quota.active || state.recovery.active || state.sub2api.active,
  },
  actions: {
    initEventBridge() {
      if (this.initialised) {
        return
      }

      eventDisposers = [
        onEvent('scan:log', (entry: LogEntry) => this.pushLog(entry)),
        onEvent('maintain:log', (entry: LogEntry) => this.pushLog(entry)),
        onEvent('inventory:log', (entry: LogEntry) => this.pushLog(entry)),
        onEvent('quota:log', (entry: LogEntry) => this.pushLog(entry)),
        onEvent('recovery:log', (entry: LogEntry) => this.pushLog(entry)),
        onEvent('sub2api:log', (entry: LogEntry) => this.pushLog(entry)),
        onEvent('scan:progress', (payload: TaskProgress) => {
          const message = progressMessage(payload)
          this.scan = {
            active: !payload.done,
            phase: payload.phase,
            current: payload.current,
            total: payload.total,
            message,
          }
          this.upsertProgressLog('scan', payload, message)
        }),
        onEvent('maintain:progress', (payload: TaskProgress) => {
          const message = progressMessage(payload)
          this.maintain = {
            active: !payload.done,
            phase: payload.phase,
            current: payload.current,
            total: payload.total,
            message,
          }
          this.upsertProgressLog('maintain', payload, message)
        }),
        onEvent('inventory:progress', (payload: TaskProgress) => {
          const message = progressMessage(payload)
          this.inventory = {
            active: !payload.done,
            phase: payload.phase,
            current: payload.current,
            total: payload.total,
            message,
          }
          this.upsertProgressLog('inventory', payload, message)
        }),
        onEvent('quota:progress', (payload: TaskProgress) => {
          const message = progressMessage(payload)
          this.quota = {
            active: !payload.done,
            phase: payload.phase,
            current: payload.current,
            total: payload.total,
            message,
          }
          this.upsertProgressLog('quota', payload, message)
        }),
        onEvent('recovery:progress', (payload: TaskProgress) => {
          const message = progressMessage(payload)
          this.recovery = {
            active: !payload.done,
            phase: payload.phase,
            current: payload.current,
            total: payload.total,
            message,
          }
          this.upsertProgressLog('recovery', payload, message)
        }),
        onEvent('sub2api:progress', (payload: TaskProgress) => {
          const message = progressMessage(payload)
          this.sub2api = {
            active: !payload.done,
            phase: payload.phase,
            current: payload.current,
            total: payload.total,
            message,
          }
          this.upsertProgressLog('sub2api', payload, message)
        }),
        onEvent('quota:snapshot', (snapshot: CodexQuotaSnapshot) => {
          useQuotasStore().applySnapshot(snapshot)
        }),
        onEvent('task:finished', (payload: TaskFinished) => {
          if (payload.kind === 'scan') {
            this.scan.active = false
          } else if (payload.kind === 'maintain') {
            this.maintain.active = false
          } else if (payload.kind === 'inventory') {
            this.inventory.active = false
          } else if (payload.kind === 'quota') {
            this.quota.active = false
          } else if (payload.kind === 'recovery') {
            this.recovery.active = false
          } else if (payload.kind === 'sub2api') {
            this.sub2api.active = false
          }
          if (payload.kind !== 'quota') {
            void useAccountsStore().refreshAll()
          }
          if (this.inventoryQueued && !this.scan.active && !this.maintain.active && !this.inventory.active && !this.quota.active && !this.recovery.active && !this.sub2api.active) {
            this.inventoryQueued = false
            void this.runInventory().catch(() => {})
          }
        }),
      ]

      void getRecentLogs(200)
        .then((items) => {
          if (this.logs.length === 0 && Array.isArray(items)) {
            this.logs = items.slice(0, 500)
          }
        })
        .catch(() => {})

      this.initialised = true
    },
    destroyEventBridge() {
      if (!this.initialised) {
        return
      }
      eventDisposers.forEach((dispose) => dispose())
      eventDisposers = []
      this.initialised = false
    },
    pushLog(entry: LogEntry) {
      if (entry.id) {
        const existing = this.logs.findIndex((item) => item.id === entry.id)
        if (existing >= 0) {
          this.logs.splice(existing, 1)
        }
      }
      this.logs.unshift(entry)
      this.logs = this.logs.slice(0, 500)
    },
    upsertProgressLog(kind: TaskKind, payload: TaskProgress, message: string) {
      this.pushLog({
        id: progressEntryId(kind),
        kind,
        level: 'info',
        message,
        timestamp: new Date().toISOString(),
        progress: true,
      })
    },
    async runScan() {
      const message = i18n.global.t('tasks.queuedScan')
      this.scan = { ...emptyTracker(), active: true, phase: 'queued', message }
      this.upsertProgressLog('scan', { kind: 'scan', phase: 'queued', current: 0, total: 0, message, done: false }, message)
      try {
        return await runScan()
      } catch (error) {
        this.pushLog({
          kind: 'scan',
          level: 'error',
          message: toErrorMessage(error),
          timestamp: new Date().toISOString(),
        })
        throw error
      } finally {
        this.scan.active = false
      }
    },
    async runMaintain(options: MaintainOptions) {
      const message = i18n.global.t('tasks.queuedMaintain')
      this.maintain = { ...emptyTracker(), active: true, phase: 'queued', message }
      this.upsertProgressLog('maintain', { kind: 'maintain', phase: 'queued', current: 0, total: 0, message, done: false }, message)
      try {
        return await runMaintain(options)
      } catch (error) {
        this.pushLog({
          kind: 'maintain',
          level: 'error',
          message: toErrorMessage(error),
          timestamp: new Date().toISOString(),
        })
        throw error
      } finally {
        this.maintain.active = false
      }
    },
    async run401Recovery(options: Recovery401Options) {
      const message = i18n.global.t('tasks.queuedRecovery')
      this.recovery = { ...emptyTracker(), active: true, phase: 'queued', message }
      this.upsertProgressLog('recovery', { kind: 'recovery', phase: 'queued', current: 0, total: 0, message, done: false }, message)
      try {
        return await run401Recovery(options)
      } catch (error) {
        this.pushLog({
          kind: 'recovery',
          level: 'error',
          message: toErrorMessage(error),
          timestamp: new Date().toISOString(),
        })
        throw error
      } finally {
        this.recovery.active = false
      }
    },
    async runSub2APIConversion(options: Sub2APIConvertOptions) {
      const message = i18n.global.t('tasks.queuedSub2API')
      this.sub2api = { ...emptyTracker(), active: true, phase: 'queued', message }
      this.upsertProgressLog('sub2api', { kind: 'sub2api', phase: 'queued', current: 0, total: 0, message, done: false }, message)
      try {
        return await runSub2APIConversion(options)
      } catch (error) {
        this.pushLog({
          kind: 'sub2api',
          level: 'error',
          message: toErrorMessage(error),
          timestamp: new Date().toISOString(),
        })
        throw error
      } finally {
        this.sub2api.active = false
      }
    },
    scheduleInventorySync() {
      if (this.scan.active || this.maintain.active || this.inventory.active || this.quota.active || this.recovery.active || this.sub2api.active) {
        this.inventoryQueued = true
        return 'queued' as const
      }
      this.inventoryQueued = false
      void this.runInventory().catch(() => {})
      return 'started' as const
    },
    async runInventory() {
      const accountsStore = useAccountsStore()
      const message = i18n.global.t('tasks.queuedInventory')
      this.inventory = { ...emptyTracker(), active: true, phase: 'queued', message }
      this.upsertProgressLog('inventory', { kind: 'inventory', phase: 'queued', current: 0, total: 0, message, done: false }, message)
      try {
        return await accountsStore.syncInventory()
      } catch (error) {
        this.pushLog({
          kind: 'inventory',
          level: 'error',
          message: toErrorMessage(error),
          timestamp: new Date().toISOString(),
        })
        throw error
      } finally {
        this.inventory.active = false
      }
    },
    async cancelCurrentTask() {
      return await cancelCurrentTask()
    },
  },
})
