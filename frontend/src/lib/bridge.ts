import type {
  AccountFilter,
  AccountPage,
  AccountRecord,
  ActionResult,
  AppSettings,
  BulkAccountActionResult,
  CodexQuotaSnapshot,
  ConnectionResult,
  DashboardSnapshot,
  ExportResult,
  InventorySyncResult,
  LogEntry,
  MaintainResult,
  MaintainOptions,
  ScanDetailPage,
  ScanSummary,
  SchedulerStatus,
  TaskFinished,
  TaskProgress,
} from '@/types'

type EventPayloadMap = {
  'scheduler:status': SchedulerStatus
  'scan:log': LogEntry
  'maintain:log': LogEntry
  'inventory:log': LogEntry
  'quota:log': LogEntry
  'scan:progress': TaskProgress
  'maintain:progress': TaskProgress
  'inventory:progress': TaskProgress
  'quota:progress': TaskProgress
  'quota:snapshot': CodexQuotaSnapshot
  'task:finished': TaskFinished
}

type EventName = keyof EventPayloadMap
type EventHandler<T> = (payload: T) => void

type BrowserScreenInfo = {
  width: number
  height: number
  isPrimary: boolean
  isCurrent: boolean
}

type RequestBody = BodyInit | Record<string, unknown> | null | undefined

type WailsRuntime = {
  EventsOn?: (event: string, callback: (payload: unknown) => void) => void
  EventsOff?: (event: string) => void
  LogDebug?: (message: string) => void
  LogError?: (message: string) => void
  ClipboardSetText?: (text: string) => Promise<void> | void
  ScreenGetAll?: () => Promise<BrowserScreenInfo[]>
  WindowSetLightTheme?: () => Promise<void> | void
  WindowSetMinSize?: (width: number, height: number) => Promise<void> | void
}

type WailsApp = Record<string, (...args: unknown[]) => Promise<unknown>>

const browserEventListeners = new Map<string, Set<EventHandler<unknown>>>()
const browserEventRelays = new Map<string, (event: MessageEvent<string>) => void>()
let browserEventSource: EventSource | null = null

function wailsRuntime(): WailsRuntime | null {
  if (typeof window === 'undefined') {
    return null
  }
  return ((window as unknown as { runtime?: WailsRuntime }).runtime ?? null)
}

function wailsApp(): WailsApp | null {
  if (typeof window === 'undefined') {
    return null
  }
  const goObject = (window as unknown as { go?: { main?: { App?: WailsApp } } }).go
  return goObject?.main?.App ?? null
}

function hasWailsBridge() {
  return Boolean(wailsRuntime() && wailsApp())
}

async function callWails<T>(method: string, ...args: unknown[]): Promise<T> {
  const app = wailsApp()
  const target = app?.[method]
  if (typeof target !== 'function') {
    throw new Error(`Wails method unavailable: ${method}`)
  }
  return await target(...args) as T
}

async function httpRequest<T>(url: string, init?: Omit<RequestInit, 'body'> & { body?: RequestBody }): Promise<T> {
  const headers = new Headers(init?.headers)
  let body: BodyInit | undefined

  if (init?.body instanceof FormData || typeof init?.body === 'string' || init?.body instanceof Blob || init?.body instanceof URLSearchParams) {
    body = init.body
  } else if (init?.body != null) {
    headers.set('Content-Type', 'application/json')
    body = JSON.stringify(init.body)
  }

  if (!headers.has('Accept')) {
    headers.set('Accept', 'application/json')
  }

  const response = await fetch(url, {
    ...init,
    headers,
    body,
    credentials: 'same-origin',
  })

  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`.trim()
    const text = (await response.text()).trim()
    if (text) {
      try {
        const payload = JSON.parse(text) as { error?: string; message?: string }
        message = String(payload.error || payload.message || message)
      } catch {
        if (text) {
          message = text
        }
      }
    }
    throw new Error(message)
  }

  if (response.status === 204) {
    return undefined as T
  }

  return await response.json() as T
}

function ensureBrowserEventSource() {
  if (browserEventSource || typeof window === 'undefined') {
    return
  }
  browserEventSource = new EventSource('/api/events')
}

function cleanupBrowserEventSource() {
  if (!browserEventSource) {
    return
  }
  if (Array.from(browserEventListeners.values()).every((handlers) => handlers.size === 0)) {
    browserEventSource.close()
    browserEventSource = null
    browserEventRelays.clear()
  }
}

function browserOnEvent<T>(eventName: EventName, handler: EventHandler<T>) {
  ensureBrowserEventSource()

  let handlers = browserEventListeners.get(eventName)
  if (!handlers) {
    handlers = new Set()
    browserEventListeners.set(eventName, handlers)
  }
  handlers.add(handler as EventHandler<unknown>)

  if (!browserEventRelays.has(eventName) && browserEventSource) {
    const relay = (event: MessageEvent<string>) => {
      let payload: unknown = null
      try {
        payload = JSON.parse(event.data)
      } catch {
        payload = event.data
      }
      const activeHandlers = browserEventListeners.get(eventName)
      if (!activeHandlers) {
        return
      }
      activeHandlers.forEach((activeHandler) => {
        activeHandler(payload)
      })
    }
    browserEventRelays.set(eventName, relay)
    browserEventSource.addEventListener(eventName, relay as EventListener)
  }

  return () => {
    const currentHandlers = browserEventListeners.get(eventName)
    if (!currentHandlers) {
      return
    }
    currentHandlers.delete(handler as EventHandler<unknown>)
    if (currentHandlers.size > 0) {
      return
    }

    browserEventListeners.delete(eventName)
    const relay = browserEventRelays.get(eventName)
    if (relay && browserEventSource) {
      browserEventSource.removeEventListener(eventName, relay as EventListener)
    }
    browserEventRelays.delete(eventName)
    cleanupBrowserEventSource()
  }
}

export function onEvent<T>(eventName: EventName, handler: EventHandler<T>) {
  const runtime = wailsRuntime()
  if (hasWailsBridge() && runtime?.EventsOn && runtime?.EventsOff) {
    runtime.EventsOn(eventName, handler as EventHandler<unknown>)
    return () => runtime.EventsOff?.(eventName)
  }
  return browserOnEvent(eventName, handler)
}

export async function getSettings() {
  if (hasWailsBridge()) {
    return await callWails<AppSettings>('GetSettings')
  }
  return await httpRequest<AppSettings>('/api/settings')
}

export async function saveSettings(settings: AppSettings) {
  if (hasWailsBridge()) {
    return await callWails<AppSettings>('SaveSettings', settings)
  }
  return await httpRequest<AppSettings>('/api/settings', {
    method: 'POST',
    body: settings,
  })
}

export async function testConnection(settings: AppSettings) {
  if (hasWailsBridge()) {
    return await callWails<ConnectionResult>('TestConnection', settings)
  }
  return await httpRequest<ConnectionResult>('/api/settings/test', {
    method: 'POST',
    body: settings,
  })
}

export async function testAndSaveSettings(settings: AppSettings) {
  if (hasWailsBridge()) {
    return await callWails<ConnectionResult>('TestAndSaveSettings', settings)
  }
  return await httpRequest<ConnectionResult>('/api/settings/test-save', {
    method: 'POST',
    body: settings,
  })
}

export async function getSchedulerStatus() {
  if (hasWailsBridge()) {
    return await callWails<SchedulerStatus>('GetSchedulerStatus')
  }
  return await httpRequest<SchedulerStatus>('/api/scheduler/status')
}

export async function getDashboardSnapshot() {
  if (hasWailsBridge()) {
    return await callWails<DashboardSnapshot>('GetDashboardSnapshot')
  }
  return await httpRequest<DashboardSnapshot>('/api/dashboard')
}

export async function listAccountsPage(filter: AccountFilter, page: number, pageSize: number) {
  if (hasWailsBridge()) {
    return await callWails<AccountPage>('ListAccountsPage', filter, page, pageSize)
  }
  const params = new URLSearchParams({
    query: filter.query || '',
    state: filter.state || '',
    provider: filter.provider || '',
    type: filter.type || '',
    planType: filter.planType || '',
    page: String(page),
    pageSize: String(pageSize),
  })
  if (filter.disabled !== undefined) {
    params.set('disabled', String(filter.disabled))
  }
  return await httpRequest<AccountPage>(`/api/accounts?${params.toString()}`)
}

export async function syncInventory() {
  if (hasWailsBridge()) {
    return await callWails<InventorySyncResult>('SyncInventory')
  }
  return await httpRequest<InventorySyncResult>('/api/inventory/sync', { method: 'POST' })
}

export async function runScan() {
  if (hasWailsBridge()) {
    return await callWails<ScanSummary>('RunScan')
  }
  return await httpRequest<ScanSummary>('/api/tasks/scan', { method: 'POST' })
}

export async function cancelCurrentTask() {
  if (hasWailsBridge()) {
    return await callWails<boolean>('CancelScan')
  }
  const result = await httpRequest<{ cancelled: boolean }>('/api/tasks/cancel', { method: 'POST' })
  return Boolean(result.cancelled)
}

export async function runMaintain(options: MaintainOptions) {
  if (hasWailsBridge()) {
    return await callWails<MaintainResult>('RunMaintain', options)
  }
  return await httpRequest<MaintainResult>('/api/tasks/maintain', {
    method: 'POST',
    body: options,
  })
}

export async function getCodexQuotaSnapshot() {
  if (hasWailsBridge()) {
    return await callWails<CodexQuotaSnapshot>('GetCodexQuotaSnapshot')
  }
  return await httpRequest<CodexQuotaSnapshot>('/api/quotas')
}

export async function probeAccount(name: string) {
  if (hasWailsBridge()) {
    return await callWails<AccountRecord>('ProbeAccount', name)
  }
  return await httpRequest<AccountRecord>(`/api/accounts/${encodeURIComponent(name)}/probe`, { method: 'POST' })
}

export async function probeAccounts(names: string[]) {
  if (hasWailsBridge()) {
    return await callWails<BulkAccountActionResult>('ProbeAccounts', names)
  }
  return await httpRequest<BulkAccountActionResult>('/api/accounts/bulk/probe', {
    method: 'POST',
    body: { names },
  })
}

export async function setAccountDisabled(name: string, disabled: boolean) {
  if (hasWailsBridge()) {
    return await callWails<ActionResult>('SetAccountDisabled', name, disabled)
  }
  return await httpRequest<ActionResult>(`/api/accounts/${encodeURIComponent(name)}/disabled`, {
    method: 'POST',
    body: { disabled },
  })
}

export async function setAccountsDisabled(names: string[], disabled: boolean) {
  if (hasWailsBridge()) {
    return await callWails<BulkAccountActionResult>('SetAccountsDisabled', names, disabled)
  }
  return await httpRequest<BulkAccountActionResult>('/api/accounts/bulk/disabled', {
    method: 'POST',
    body: { names, disabled },
  })
}

export async function deleteAccount(name: string) {
  if (hasWailsBridge()) {
    return await callWails<ActionResult>('DeleteAccount', name)
  }
  return await httpRequest<ActionResult>(`/api/accounts/${encodeURIComponent(name)}`, { method: 'DELETE' })
}

export async function deleteAccounts(names: string[]) {
  if (hasWailsBridge()) {
    return await callWails<BulkAccountActionResult>('DeleteAccounts', names)
  }
  return await httpRequest<BulkAccountActionResult>('/api/accounts/bulk/delete', {
    method: 'POST',
    body: { names },
  })
}

export async function exportAccounts(kind: string, format: string, path = '') {
  if (hasWailsBridge()) {
    return await callWails<ExportResult>('ExportAccounts', kind, format, path)
  }
  return await httpRequest<ExportResult>('/api/exports', {
    method: 'POST',
    body: { kind, format, path },
  })
}

export async function getScanDetailsPage(runId: number, page: number, pageSize: number) {
  if (hasWailsBridge()) {
    return await callWails<ScanDetailPage>('GetScanDetailsPage', runId, page, pageSize)
  }
  const params = new URLSearchParams({
    page: String(page),
    pageSize: String(pageSize),
  })
  return await httpRequest<ScanDetailPage>(`/api/scan-runs/${runId}?${params.toString()}`)
}

export async function getRecentLogs(limit = 200) {
  if (hasWailsBridge()) {
    return [] as LogEntry[]
  }
  const result = await httpRequest<{ items: LogEntry[] }>(`/api/logs/recent?limit=${limit}`)
  return Array.isArray(result.items) ? result.items : []
}

export async function clipboardSetText(text: string) {
  const runtime = wailsRuntime()
  if (hasWailsBridge() && runtime?.ClipboardSetText) {
    await runtime.ClipboardSetText(text)
    return
  }
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text)
    return
  }
  throw new Error('Clipboard API unavailable')
}

export async function screenGetAll() {
  const runtime = wailsRuntime()
  if (hasWailsBridge() && runtime?.ScreenGetAll) {
    return await runtime.ScreenGetAll()
  }
  return [
    {
      width: window.screen.availWidth || window.screen.width,
      height: window.screen.availHeight || window.screen.height,
      isPrimary: true,
      isCurrent: true,
    },
  ] satisfies BrowserScreenInfo[]
}

export async function windowSetMinSize(width: number, height: number) {
  const runtime = wailsRuntime()
  if (hasWailsBridge() && runtime?.WindowSetMinSize) {
    await runtime.WindowSetMinSize(width, height)
    return
  }
  void width
  void height
}

export async function windowSetLightTheme() {
  const runtime = wailsRuntime()
  if (hasWailsBridge() && runtime?.WindowSetLightTheme) {
    await runtime.WindowSetLightTheme()
    return
  }
  document.documentElement.style.colorScheme = 'light'
}

export function logDebug(message: string) {
  const runtime = wailsRuntime()
  if (hasWailsBridge() && runtime?.LogDebug) {
    runtime.LogDebug(message)
    return
  }
  console.debug(message)
}

export function logError(message: string) {
  const runtime = wailsRuntime()
  if (hasWailsBridge() && runtime?.LogError) {
    runtime.LogError(message)
    return
  }
  console.error(message)
}
