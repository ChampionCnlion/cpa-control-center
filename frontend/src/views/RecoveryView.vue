<script setup lang="ts">
import { computed, ref } from 'vue'
import {
  ElButton,
  ElInput,
  ElInputNumber,
  ElMessage,
  ElMessageBox,
  ElTable,
  ElTableColumn,
  ElTag,
} from 'element-plus'
import { useI18n } from 'vue-i18n'
import { scan401Recovery } from '@/lib/bridge'
import { useAccountsStore } from '@/stores/accounts'
import { useTasksStore } from '@/stores/tasks'
import type { QuotaBucketSummary, Recovery401Candidate, Recovery401ItemResult, Recovery401Result, Recovery401ScanResult } from '@/types'
import { toErrorMessage } from '@/utils/errors'
import { formatDateTime } from '@/utils/format'
import { stateLabel, statusTagType } from '@/utils/status'

const { t } = useI18n()
const accountsStore = useAccountsStore()
const tasksStore = useTasksStore()

const loadingScan = ref(false)
const maxAccounts = ref(10)
const emailServiceUrl = ref('https://postinbox.org/mailbox')
const scanResult = ref<Recovery401ScanResult | null>(null)
const recoveryResult = ref<Recovery401Result | null>(null)

const candidates = computed<Recovery401Candidate[]>(() => scanResult.value?.candidates ?? [])
const results = computed<Recovery401ItemResult[]>(() => recoveryResult.value?.results ?? [])
const canRun = computed(() => !tasksStore.hasActiveTask && !loadingScan.value)
const fiveHourQuota = computed(() => aggregateQuotaBucket('fiveHour'))
const weeklyQuota = computed(() => aggregateQuotaBucket('weekly'))

type QuotaBucketKey = 'fiveHour' | 'weekly'

function statusType(ok: boolean) {
  return ok ? 'success' : 'warning'
}

function aggregateQuotaBucket(key: QuotaBucketKey): QuotaBucketSummary {
  let supported = false
  let successCount = 0
  let failedCount = 0
  let totalRemainingPercent = 0
  let hasTotal = false
  let resetAt = ''

  for (const plan of scanResult.value?.quota?.plans ?? []) {
    const bucket = plan[key]
    if (!bucket.supported) {
      continue
    }
    supported = true
    successCount += bucket.successCount
    failedCount += bucket.failedCount
    if (typeof bucket.totalRemainingPercent === 'number' && !Number.isNaN(bucket.totalRemainingPercent)) {
      totalRemainingPercent += bucket.totalRemainingPercent
      hasTotal = true
    }
    if (bucket.resetAt && (!resetAt || new Date(bucket.resetAt).getTime() < new Date(resetAt).getTime())) {
      resetAt = bucket.resetAt
    }
  }

  return {
    supported,
    totalRemainingPercent: hasTotal ? Number(totalRemainingPercent.toFixed(1)) : null,
    resetAt,
    successCount,
    failedCount,
  }
}

function formatQuotaNumber(value: number) {
  return Math.abs(value - Math.round(value)) < 0.05 ? String(Math.round(value)) : value.toFixed(1)
}

function formatQuotaTotal(bucket: QuotaBucketSummary) {
  if (!scanResult.value) {
    return '-'
  }
  if (!bucket.supported || typeof bucket.totalRemainingPercent !== 'number' || Number.isNaN(bucket.totalRemainingPercent)) {
    return t('quotas.unavailable')
  }
  return t('recovery.stats.remainingPercent', { value: formatQuotaNumber(bucket.totalRemainingPercent) })
}

function formatQuotaHint(bucket: QuotaBucketSummary) {
  if (!scanResult.value) {
    return t('recovery.stats.quotaHintEmpty')
  }
  if (!scanResult.value.quota) {
    return t('recovery.stats.quotaUnavailableHint')
  }
  const coverage = t('quotas.coverage', { success: bucket.successCount, total: bucket.successCount + bucket.failedCount })
  const reset = bucket.resetAt ? formatDateTime(bucket.resetAt) : t('common.notAvailable')
  return t('recovery.stats.quotaHint', { coverage, reset })
}

function detectionSourceLabel(source: string) {
  const key = `recovery.sources.${source || 'unknown'}`
  return t(key)
}

function apiStatusLabel(row: Recovery401Candidate) {
  return typeof row.apiStatusCode === 'number' ? String(row.apiStatusCode) : '-'
}

function candidateDetail(row: Recovery401Candidate) {
  return row.probeErrorText || row.statusMessage || row.probeErrorKind || '-'
}

async function scanCandidates() {
  loadingScan.value = true
  recoveryResult.value = null
  try {
    scanResult.value = await scan401Recovery()
    ElMessage.success(t('recovery.messages.scanCompleted', { count: candidates.value.length }))
  } catch (error) {
    ElMessage.error(toErrorMessage(error))
  } finally {
    loadingScan.value = false
  }
}

async function runRecovery() {
  if (!canRun.value) {
    return
  }
  try {
    await ElMessageBox.confirm(
      t('recovery.dialog.message', { count: maxAccounts.value }),
      t('recovery.dialog.title'),
      {
        confirmButtonText: t('recovery.dialog.confirm'),
        cancelButtonText: t('recovery.dialog.cancel'),
        customClass: 'cpa-message-box',
        type: 'warning',
      },
    )
    recoveryResult.value = await tasksStore.run401Recovery({
      maxAccounts: maxAccounts.value,
      emailServiceUrl: emailServiceUrl.value,
    })
    await accountsStore.refreshAll()
    ElMessage.success(t('recovery.messages.runCompleted', {
      uploaded: recoveryResult.value.summary.uploaded,
      failed: recoveryResult.value.summary.failed,
    }))
  } catch (error) {
    if (String(error) !== 'cancel') {
      ElMessage.error(toErrorMessage(error))
    }
  }
}
</script>

<template>
  <div class="view-shell view-shell--recovery">
    <section class="hero-panel">
      <div>
        <p class="eyebrow">{{ t('recovery.eyebrow') }}</p>
        <h2>{{ t('recovery.title') }}</h2>
        <p class="lead">
          {{ t('recovery.lead') }}
        </p>
      </div>
      <div class="hero-actions">
        <el-button size="large" :loading="loadingScan" :disabled="tasksStore.hasActiveTask" @click="scanCandidates">
          {{ t('recovery.actions.scan') }}
        </el-button>
        <el-button type="primary" size="large" :loading="tasksStore.recovery.active" :disabled="!canRun" @click="runRecovery">
          {{ t('recovery.actions.run') }}
        </el-button>
      </div>
    </section>

    <section class="stats-grid">
      <article class="stat-card stat-card--accent">
        <span class="stat-label">{{ t('recovery.stats.current401') }}</span>
        <strong>{{ accountsStore.summary.invalid401Count }}</strong>
        <small>{{ t('recovery.stats.current401Hint') }}</small>
      </article>
      <article class="stat-card">
        <span class="stat-label">{{ t('recovery.stats.scanned') }}</span>
        <strong>{{ scanResult?.total ?? '-' }}</strong>
        <small>{{ t('recovery.stats.scannedHint') }}</small>
      </article>
      <article class="stat-card">
        <span class="stat-label">{{ t('recovery.stats.probed') }}</span>
        <strong>{{ scanResult?.probed ?? '-' }}</strong>
        <small>{{ t('recovery.stats.probedHint') }}</small>
      </article>
      <article class="stat-card">
        <span class="stat-label">{{ t('recovery.stats.candidates') }}</span>
        <strong>{{ candidates.length }}</strong>
        <small>{{ t('recovery.stats.candidatesHint') }}</small>
      </article>
      <article class="stat-card">
        <span class="stat-label">{{ t('recovery.stats.fiveHour') }}</span>
        <strong>{{ formatQuotaTotal(fiveHourQuota) }}</strong>
        <small>{{ formatQuotaHint(fiveHourQuota) }}</small>
      </article>
      <article class="stat-card">
        <span class="stat-label">{{ t('recovery.stats.weekly') }}</span>
        <strong>{{ formatQuotaTotal(weeklyQuota) }}</strong>
        <small>{{ formatQuotaHint(weeklyQuota) }}</small>
      </article>
    </section>

    <section class="dashboard-grid dashboard-grid--recovery">
      <article class="panel panel--fill">
        <div class="panel-head">
          <div>
            <p class="panel-kicker">{{ t('recovery.options.kicker') }}</p>
            <h3>{{ t('recovery.options.title') }}</h3>
          </div>
        </div>
        <div class="panel__body recovery-options">
          <label class="form-row">
            <span>{{ t('recovery.options.maxAccounts') }}</span>
            <el-input-number v-model="maxAccounts" :min="1" :max="50" controls-position="right" />
          </label>
          <label class="form-row form-row--wide">
            <span>{{ t('recovery.options.emailServiceUrl') }}</span>
            <el-input v-model="emailServiceUrl" />
          </label>
          <p class="muted">{{ t('recovery.options.hint') }}</p>
        </div>
      </article>

      <article class="panel panel--fill">
        <div class="panel-head">
          <div>
            <p class="panel-kicker">{{ t('recovery.candidates.kicker') }}</p>
            <h3>{{ t('recovery.candidates.title') }}</h3>
          </div>
          <span class="muted">{{ t('recovery.candidates.count', { count: candidates.length }) }}</span>
        </div>
        <div class="panel__body panel__body--table">
          <div class="table-wrap">
            <el-table :data="candidates" height="100%">
              <el-table-column prop="name" :label="t('recovery.columns.name')" min-width="220" show-overflow-tooltip />
              <el-table-column prop="email" :label="t('recovery.columns.email')" min-width="180" show-overflow-tooltip />
              <el-table-column prop="provider" :label="t('recovery.columns.provider')" width="100" />
              <el-table-column prop="planType" :label="t('recovery.columns.plan')" width="95" />
              <el-table-column :label="t('recovery.columns.state')" width="130">
                <template #default="{ row }">
                  <el-tag :type="statusTagType(row.stateKey)" effect="plain">{{ stateLabel(row.stateKey) }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column :label="t('recovery.columns.source')" width="130">
                <template #default="{ row }">
                  {{ detectionSourceLabel(row.detectionSource) }}
                </template>
              </el-table-column>
              <el-table-column :label="t('recovery.columns.apiStatus')" width="95">
                <template #default="{ row }">
                  {{ apiStatusLabel(row) }}
                </template>
              </el-table-column>
              <el-table-column :label="t('recovery.columns.message')" min-width="260" show-overflow-tooltip>
                <template #default="{ row }">
                  {{ candidateDetail(row) }}
                </template>
              </el-table-column>
            </el-table>
          </div>
        </div>
      </article>
    </section>

    <section class="panel panel--fill recovery-results">
      <div class="panel-head">
        <div>
          <p class="panel-kicker">{{ t('recovery.results.kicker') }}</p>
          <h3>{{ t('recovery.results.title') }}</h3>
        </div>
        <span class="muted">{{ t('recovery.results.summary', {
          processed: recoveryResult?.summary.processed ?? 0,
          uploaded: recoveryResult?.summary.uploaded ?? 0,
          failed: recoveryResult?.summary.failed ?? 0,
        }) }}</span>
      </div>
      <div class="panel__body panel__body--table">
        <div class="table-wrap">
          <el-table :data="results" height="100%">
            <el-table-column prop="name" :label="t('recovery.columns.name')" min-width="220" show-overflow-tooltip />
            <el-table-column prop="email" :label="t('recovery.columns.email')" min-width="180" show-overflow-tooltip />
            <el-table-column prop="action" :label="t('recovery.columns.action')" width="150">
              <template #default="{ row }">
                <el-tag :type="statusType(row.ok)" effect="plain">{{ row.action }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="message" :label="t('recovery.columns.message')" min-width="320" show-overflow-tooltip />
          </el-table>
        </div>
      </div>
    </section>
  </div>
</template>
