<script setup lang="ts">
import { computed, ref } from 'vue'
import {
  ElButton,
  ElInputNumber,
  ElMessage,
  ElMessageBox,
  ElSwitch,
  ElTable,
  ElTableColumn,
  ElTag,
} from 'element-plus'
import { useI18n } from 'vue-i18n'
import { scanSub2APIConversion } from '@/lib/bridge'
import { useAccountsStore } from '@/stores/accounts'
import { useTasksStore } from '@/stores/tasks'
import type { Sub2APIConvertCandidate, Sub2APIConvertItemResult, Sub2APIConvertResult, Sub2APIConvertScanResult } from '@/types'
import { toErrorMessage } from '@/utils/errors'

const { t } = useI18n()
const accountsStore = useAccountsStore()
const tasksStore = useTasksStore()

const loadingScan = ref(false)
const maxAccounts = ref(0)
const overwrite = ref(false)
const skipVerify = ref(false)
const scanResult = ref<Sub2APIConvertScanResult | null>(null)
const convertResult = ref<Sub2APIConvertResult | null>(null)

const candidates = computed<Sub2APIConvertCandidate[]>(() => scanResult.value?.candidates ?? [])
const results = computed<Sub2APIConvertItemResult[]>(() => convertResult.value?.results ?? [])
const canRun = computed(() => !tasksStore.hasActiveTask && !loadingScan.value)
const runLimitLabel = computed(() => (
  maxAccounts.value > 0 ? String(maxAccounts.value) : t('sub2api.options.allAccounts')
))

function statusType(ok: boolean, action = '') {
  if (ok) {
    return 'success'
  }
  if (action === 'skipped') {
    return 'info'
  }
  return 'warning'
}

function displayValue(value: string) {
  return value?.trim() || '-'
}

async function scanCandidates() {
  loadingScan.value = true
  convertResult.value = null
  try {
    scanResult.value = await scanSub2APIConversion()
    ElMessage.success(t('sub2api.messages.scanCompleted', { count: candidates.value.length }))
  } catch (error) {
    ElMessage.error(toErrorMessage(error))
  } finally {
    loadingScan.value = false
  }
}

async function runConversion() {
  if (!canRun.value) {
    return
  }
  try {
    await ElMessageBox.confirm(
      t('sub2api.dialog.message', { count: runLimitLabel.value }),
      t('sub2api.dialog.title'),
      {
        confirmButtonText: t('sub2api.dialog.confirm'),
        cancelButtonText: t('sub2api.dialog.cancel'),
        customClass: 'cpa-message-box',
        type: 'warning',
      },
    )
    convertResult.value = await tasksStore.runSub2APIConversion({
      maxAccounts: maxAccounts.value,
      overwrite: overwrite.value,
      skipVerify: skipVerify.value,
    })
    await accountsStore.refreshAll()
    ElMessage.success(t('sub2api.messages.runCompleted', {
      uploaded: convertResult.value.summary.uploaded,
      failed: convertResult.value.summary.failed,
      skipped: convertResult.value.summary.skipped,
    }))
  } catch (error) {
    if (String(error) !== 'cancel') {
      ElMessage.error(toErrorMessage(error))
    }
  }
}
</script>

<template>
  <div class="view-shell view-shell--sub2api">
    <section class="hero-panel">
      <div>
        <p class="eyebrow">{{ t('sub2api.eyebrow') }}</p>
        <h2>{{ t('sub2api.title') }}</h2>
        <p class="lead">
          {{ t('sub2api.lead') }}
        </p>
      </div>
      <div class="hero-actions">
        <el-button size="large" :loading="loadingScan" :disabled="tasksStore.hasActiveTask" @click="scanCandidates">
          {{ t('sub2api.actions.scan') }}
        </el-button>
        <el-button type="primary" size="large" :loading="tasksStore.sub2api.active" :disabled="!canRun" @click="runConversion">
          {{ t('sub2api.actions.convert') }}
        </el-button>
      </div>
    </section>

    <section class="stats-grid">
      <article class="stat-card stat-card--accent">
        <span class="stat-label">{{ t('sub2api.stats.convertibleAccounts') }}</span>
        <strong>{{ scanResult?.convertibleAccounts ?? '-' }}</strong>
        <small>{{ t('sub2api.stats.convertibleAccountsHint') }}</small>
      </article>
      <article class="stat-card">
        <span class="stat-label">{{ t('sub2api.stats.totalFiles') }}</span>
        <strong>{{ scanResult?.totalFiles ?? '-' }}</strong>
        <small>{{ t('sub2api.stats.totalFilesHint') }}</small>
      </article>
      <article class="stat-card">
        <span class="stat-label">{{ t('sub2api.stats.scannedFiles') }}</span>
        <strong>{{ scanResult?.scannedFiles ?? '-' }}</strong>
        <small>{{ t('sub2api.stats.scannedFilesHint') }}</small>
      </article>
      <article class="stat-card">
        <span class="stat-label">{{ t('sub2api.stats.convertibleFiles') }}</span>
        <strong>{{ scanResult?.convertibleFiles ?? '-' }}</strong>
        <small>{{ t('sub2api.stats.convertibleFilesHint') }}</small>
      </article>
      <article class="stat-card">
        <span class="stat-label">{{ t('sub2api.stats.skippedAccounts') }}</span>
        <strong>{{ scanResult?.skippedAccounts ?? '-' }}</strong>
        <small>{{ t('sub2api.stats.skippedAccountsHint') }}</small>
      </article>
    </section>

    <section class="dashboard-grid dashboard-grid--sub2api">
      <article class="panel panel--fill">
        <div class="panel-head">
          <div>
            <p class="panel-kicker">{{ t('sub2api.options.kicker') }}</p>
            <h3>{{ t('sub2api.options.title') }}</h3>
          </div>
        </div>
        <div class="panel__body sub2api-options">
          <label class="form-row">
            <span>{{ t('sub2api.options.maxAccounts') }}</span>
            <el-input-number v-model="maxAccounts" :min="0" :max="5000" controls-position="right" />
          </label>
          <el-switch v-model="overwrite" :active-text="t('sub2api.options.overwrite')" />
          <el-switch v-model="skipVerify" :active-text="t('sub2api.options.skipVerify')" />
          <p class="muted">{{ t('sub2api.options.hint') }}</p>
        </div>
      </article>

      <article class="panel panel--fill">
        <div class="panel-head">
          <div>
            <p class="panel-kicker">{{ t('sub2api.candidates.kicker') }}</p>
            <h3>{{ t('sub2api.candidates.title') }}</h3>
          </div>
          <span class="muted">{{ t('sub2api.candidates.count', { count: candidates.length }) }}</span>
        </div>
        <div class="panel__body panel__body--table">
          <div class="table-wrap">
            <el-table :data="candidates" height="100%">
              <el-table-column prop="sourceName" :label="t('sub2api.columns.sourceName')" min-width="220" show-overflow-tooltip />
              <el-table-column prop="targetName" :label="t('sub2api.columns.targetName')" min-width="220" show-overflow-tooltip />
              <el-table-column prop="email" :label="t('sub2api.columns.email')" min-width="180" show-overflow-tooltip />
              <el-table-column prop="planType" :label="t('sub2api.columns.plan')" width="100">
                <template #default="{ row }">
                  {{ displayValue(row.planType) }}
                </template>
              </el-table-column>
              <el-table-column prop="accountId" :label="t('sub2api.columns.accountId')" min-width="180" show-overflow-tooltip>
                <template #default="{ row }">
                  {{ displayValue(row.accountId) }}
                </template>
              </el-table-column>
              <el-table-column prop="message" :label="t('sub2api.columns.message')" min-width="160" show-overflow-tooltip />
            </el-table>
          </div>
        </div>
      </article>
    </section>

    <section class="panel panel--fill sub2api-results">
      <div class="panel-head">
        <div>
          <p class="panel-kicker">{{ t('sub2api.results.kicker') }}</p>
          <h3>{{ t('sub2api.results.title') }}</h3>
        </div>
        <span class="muted">{{ t('sub2api.results.summary', {
          processed: convertResult?.summary.processed ?? 0,
          uploaded: convertResult?.summary.uploaded ?? 0,
          skipped: convertResult?.summary.skipped ?? 0,
          failed: convertResult?.summary.failed ?? 0,
          verified: convertResult?.summary.verified ?? 0,
        }) }}</span>
      </div>
      <div class="panel__body panel__body--table">
        <div class="table-wrap">
          <el-table :data="results" height="100%">
            <el-table-column prop="sourceName" :label="t('sub2api.columns.sourceName')" min-width="220" show-overflow-tooltip />
            <el-table-column prop="targetName" :label="t('sub2api.columns.targetName')" min-width="220" show-overflow-tooltip />
            <el-table-column prop="email" :label="t('sub2api.columns.email')" min-width="180" show-overflow-tooltip />
            <el-table-column prop="action" :label="t('sub2api.columns.action')" width="150">
              <template #default="{ row }">
                <el-tag :type="statusType(row.ok, row.action)" effect="plain">{{ row.action }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="message" :label="t('sub2api.columns.message')" min-width="320" show-overflow-tooltip />
          </el-table>
        </div>
      </div>
    </section>
  </div>
</template>
