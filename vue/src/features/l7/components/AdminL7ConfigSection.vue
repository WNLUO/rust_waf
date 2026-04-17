<script setup lang="ts">
import type { AutoTuningRuntimePayload } from '@/features/l7/types/l7'
import type { L7ConfigForm } from '@/features/l7/utils/adminL7'
import { listFieldClass, numberInputClass } from '@/features/l7/utils/adminL7'
import { useAdminL7ConfigSection } from '@/features/l7/composables/useAdminL7ConfigSection'
import L7SafelineInterceptPanel from '@/features/l7/components/L7SafelineInterceptPanel.vue'
import L7Http3Panel from '@/features/l7/components/L7Http3Panel.vue'
import L7SlowAttackPanel from '@/features/l7/components/L7SlowAttackPanel.vue'
import L7CcDefensePanel from '@/features/l7/components/L7CcDefensePanel.vue'
import L7AutoTuningPanel from '@/features/l7/components/L7AutoTuningPanel.vue'
import L7RuntimeLimitsPanel from '@/features/l7/components/L7RuntimeLimitsPanel.vue'
import L7HttpConfigPanel from '@/features/l7/components/L7HttpConfigPanel.vue'

const props = defineProps<{
  form: L7ConfigForm
  trustedProxyCidrsText: string
  autoTuningRuntime?: AutoTuningRuntimePayload | null
  dropUnmatchedRequests: boolean
  dropUnmatchedRequestsDisabled?: boolean
  compatibilityMode?: boolean
  hideAdaptiveManagedSections?: boolean
}>()

const emit = defineEmits<{
  'update:form': [value: L7ConfigForm]
  'update:trustedProxyCidrsText': [value: string]
  'update:dropUnmatchedRequests': [value: boolean]
}>()

const {
  http2Enabled,
  http10Enabled,
  http10Saving,
  bloomEnabled,
  bloomVerifyEnabled,
  healthcheckEnabled,
  http3Enabled,
  runtimeProfile,
  failureMode,
  upstreamProtocolPolicy,
  upstreamHttp1StrictMode,
  upstreamHttp1AllowConnectionReuse,
  rejectAmbiguousHttp1Requests,
  rejectHttp1TransferEncodingRequests,
  rejectBodyOnSafeHttpMethods,
  rejectExpect100Continue,
  maxRequestSize,
  firstByteTimeout,
  readIdleTimeout,
  tlsHandshakeTimeout,
  proxyConnectTimeout,
  proxyWriteTimeout,
  proxyReadTimeout,
  bloomFilterScale,
  healthcheckInterval,
  healthcheckTimeout,
  http2MaxStreams,
  http2MaxFrameSize,
  http2InitialWindowSize,
  http2EnablePriorities,
  http3MaxStreams,
  http3IdleTimeout,
  http3Mtu,
  http3MaxFrameSize,
  http3QpackTableSize,
  http3CertificatePath,
  http3PrivateKeyPath,
  http3ConnectionMigration,
  http3Tls13Enabled,
  autoTuningMode,
  autoTuningIntent,
  autoRuntimeAdjustEnabled,
  autoBootstrapSecs,
  autoControlIntervalSecs,
  autoCooldownSecs,
  autoMaxStepPercent,
  autoRollbackWindowMinutes,
  autoTlsHandshakeTimeoutRatePercent,
  autoBucketRejectRatePercent,
  autoP95ProxyLatencyMs,
  autoPinnedFieldsText,
  autoEffectEvaluation,
  hotspotView,
  autoRiskLeaderboard,
  autoRiskByHost,
  autoRiskByRoute,
  hotspotHeatmapCards,
  autoEffectStatusLabel,
  autoEffectStatusClass,
  formatSignedNumber,
  formatSignedInteger,
  segmentLabel,
  segmentStatusLabel,
  adjustReasonLabel,
  riskSeverityClass,
  hostRiskSeverityClass,
  hotspotViewButtonClass,
  ccDefenseEnabled,
  ccRequestWindow,
  ccIpChallengeThreshold,
  ccIpBlockThreshold,
  ccHostChallengeThreshold,
  ccHostBlockThreshold,
  ccRouteChallengeThreshold,
  ccRouteBlockThreshold,
  ccHotPathChallengeThreshold,
  ccHotPathBlockThreshold,
  ccDelayThresholdPercent,
  ccDelayMs,
  ccChallengeTtl,
  ccChallengeCookieName,
  ccHardRouteBlockMultiplier,
  ccHardHostBlockMultiplier,
  ccHardIpBlockMultiplier,
  ccHardHotPathBlockMultiplier,
  slowAttackDefenseEnabled,
  slowAttackHeaderMinRate,
  slowAttackBodyMinRate,
  slowAttackIdleKeepaliveTimeout,
  slowAttackEventWindow,
  slowAttackMaxEvents,
  slowAttackBlockDuration,
  safelineInterceptEnabled,
  safelineInterceptAction,
  safelineInterceptMatchMode,
  safelineInterceptMaxBodyBytes,
  safelineInterceptBlockDuration,
  safelineResponseStatusCode,
  safelineResponseContentType,
  contentTypeDialogOpen,
  contentTypeDraft,
  contentTypeOptions,
  handleHttp10Toggle,
  openContentTypeDialog,
  selectContentTypeOption,
  confirmContentTypeDialog,
  closeContentTypeDialog,
  safelineResponseBodySource,
} = useAdminL7ConfigSection(props, emit)

const safelineControls = {
  safelineInterceptEnabled,
  safelineInterceptAction,
  safelineInterceptMatchMode,
  safelineInterceptMaxBodyBytes,
  safelineInterceptBlockDuration,
  safelineResponseStatusCode,
  safelineResponseContentType,
  safelineResponseBodySource,
  contentTypeDialogOpen,
  contentTypeDraft,
  contentTypeOptions,
  openContentTypeDialog,
  selectContentTypeOption,
  confirmContentTypeDialog,
  closeContentTypeDialog,
}

const http3Controls = {
  http3ConnectionMigration,
  http3Tls13Enabled,
  http3MaxStreams,
  http3IdleTimeout,
  http3Mtu,
  http3MaxFrameSize,
  http3QpackTableSize,
  http3CertificatePath,
  http3PrivateKeyPath,
}

const slowAttackControls = {
  slowAttackDefenseEnabled,
  slowAttackHeaderMinRate,
  slowAttackBodyMinRate,
  slowAttackIdleKeepaliveTimeout,
  slowAttackEventWindow,
  slowAttackMaxEvents,
  slowAttackBlockDuration,
}

const ccDefenseControls = {
  ccDefenseEnabled,
  ccRequestWindow,
  ccIpChallengeThreshold,
  ccIpBlockThreshold,
  ccHostChallengeThreshold,
  ccHostBlockThreshold,
  ccRouteChallengeThreshold,
  ccRouteBlockThreshold,
  ccHotPathChallengeThreshold,
  ccHotPathBlockThreshold,
  ccDelayThresholdPercent,
  ccDelayMs,
  ccChallengeTtl,
  ccChallengeCookieName,
  ccHardRouteBlockMultiplier,
  ccHardHostBlockMultiplier,
  ccHardIpBlockMultiplier,
  ccHardHotPathBlockMultiplier,
}

const autoTuningControls = {
  autoTuningMode,
  autoTuningIntent,
  autoRuntimeAdjustEnabled,
  autoBootstrapSecs,
  autoControlIntervalSecs,
  autoCooldownSecs,
  autoMaxStepPercent,
  autoRollbackWindowMinutes,
  autoTlsHandshakeTimeoutRatePercent,
  autoBucketRejectRatePercent,
  autoP95ProxyLatencyMs,
  autoPinnedFieldsText,
  autoEffectEvaluation,
  hotspotView,
  autoRiskLeaderboard,
  autoRiskByHost,
  autoRiskByRoute,
  hotspotHeatmapCards,
  autoEffectStatusLabel,
  autoEffectStatusClass,
}

const autoTuningHelpers = {
  formatSignedNumber,
  formatSignedInteger,
  segmentLabel,
  segmentStatusLabel,
  adjustReasonLabel,
  riskSeverityClass,
  hostRiskSeverityClass,
  hotspotViewButtonClass,
}

const runtimeLimitControls = {
  maxRequestSize,
  firstByteTimeout,
  readIdleTimeout,
  tlsHandshakeTimeout,
  proxyConnectTimeout,
  proxyWriteTimeout,
  proxyReadTimeout,
  bloomFilterScale,
  healthcheckInterval,
  healthcheckTimeout,
  http2MaxStreams,
  http2MaxFrameSize,
  http2InitialWindowSize,
}

const httpConfigControls = {
  http10Enabled,
  http10Saving,
  http2Enabled,
  bloomEnabled,
  bloomVerifyEnabled,
  healthcheckEnabled,
  http3Enabled,
  http2EnablePriorities,
  runtimeProfile,
  failureMode,
  upstreamProtocolPolicy,
  upstreamHttp1StrictMode,
  upstreamHttp1AllowConnectionReuse,
  rejectAmbiguousHttp1Requests,
  rejectHttp1TransferEncodingRequests,
  rejectBodyOnSafeHttpMethods,
  rejectExpect100Continue,
  handleHttp10Toggle,
}

function updateDropUnmatchedRequests(value: boolean) {
  emit('update:dropUnmatchedRequests', value)
}
</script>

<template>
  <section
    class="rounded-xl border border-white/80 bg-white/78 p-4 shadow-[0_18px_48px_rgba(90,60,30,0.08)]"
  >
    <div
      v-if="compatibilityMode"
      class="mb-4 rounded-xl border border-amber-200 bg-amber-50/80 px-4 py-3 text-sm leading-6 text-amber-900"
    >
      当前处于 L7 兼容模式。这里编辑的是历史 CC /
      自动调优细粒度参数，仅用于旧策略回滚或专项排障，不作为自动控制器的常规入口。
    </div>
    <div
      v-else-if="hideAdaptiveManagedSections"
      class="mb-4 rounded-xl border border-blue-100 bg-blue-50/70 px-4 py-3 text-sm leading-6 text-blue-900"
    >
      当前展示的是 L7 独立运行项。CC
      防护阈值与自动调优细项已交由自动化接管，并收纳到兼容层入口。
    </div>
    <L7HttpConfigPanel
      :controls="httpConfigControls"
      :drop-unmatched-requests="dropUnmatchedRequests"
      :drop-unmatched-requests-disabled="dropUnmatchedRequestsDisabled"
      :hide-adaptive-managed-sections="hideAdaptiveManagedSections"
      :update-drop-unmatched-requests="updateDropUnmatchedRequests"
    />

    <L7SlowAttackPanel
      v-if="!hideAdaptiveManagedSections"
      :controls="slowAttackControls"
      :number-input-class="numberInputClass"
    />

    <L7AutoTuningPanel
      v-if="!hideAdaptiveManagedSections"
      :controls="autoTuningControls"
      :runtime="autoTuningRuntime ?? null"
      :helpers="autoTuningHelpers"
      :number-input-class="numberInputClass"
      :list-field-class="listFieldClass"
    />

    <L7RuntimeLimitsPanel
      :controls="runtimeLimitControls"
      :number-input-class="numberInputClass"
    />

    <L7CcDefensePanel
      v-if="!hideAdaptiveManagedSections"
      :controls="ccDefenseControls"
      :number-input-class="numberInputClass"
    />

    <L7SafelineInterceptPanel
      v-if="!hideAdaptiveManagedSections"
      :controls="safelineControls"
      :number-input-class="numberInputClass"
    />

    <L7Http3Panel
      :controls="http3Controls"
      :number-input-class="numberInputClass"
    />
  </section>
</template>

<style scoped>
.l7-inline-field {
  display: flex;
  align-items: center;
  justify-content: flex-start;
  gap: 0.5rem;
  color: rgb(100 116 139);
  font-size: 0.75rem;
  font-weight: 500;
  white-space: nowrap;
}

.l7-inline-field :deep(input),
.l7-inline-field :deep(select),
.l7-inline-field :deep(.numberInputClass) {
  width: 5rem;
  margin-top: 0 !important;
  border-radius: 0.375rem;
  border: 1px solid rgb(203 213 225);
  background: transparent;
  padding: 0.25rem 0.5rem;
  box-shadow: none;
  text-align: center;
  transition: border-color 0.2s ease;
}

.l7-inline-field :deep(input[type='text']) {
  width: 10rem;
  text-align: left;
}

.l7-inline-field :deep(input[type='number']::-webkit-outer-spin-button),
.l7-inline-field :deep(input[type='number']::-webkit-inner-spin-button) {
  -webkit-appearance: none;
  margin: 0;
}

.l7-inline-field :deep(input[type='number']) {
  -moz-appearance: textfield;
  appearance: textfield;
}

.l7-inline-select {
  width: auto;
  min-width: 8.5rem;
}

.l7-inline-button {
  width: auto;
  min-width: 12rem;
  text-align: center;
  cursor: pointer;
}

.l7-inline-field :deep(input:focus),
.l7-inline-field :deep(select:focus) {
  border-color: rgba(59, 130, 246, 0.65);
}

.l7-toggle-field {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
}

.ui-switch {
  appearance: none;
  width: 2.25rem;
  height: 1.25rem;
  border-radius: 9999px;
  background: rgb(203 213 225);
  position: relative;
  cursor: pointer;
  transition: background-color 0.2s ease;
}

.ui-switch::after {
  content: '';
  position: absolute;
  top: 0.125rem;
  left: 0.125rem;
  width: 1rem;
  height: 1rem;
  border-radius: 9999px;
  background: white;
  transition: transform 0.2s ease;
}

.ui-switch:checked {
  background: rgb(37 99 235);
}

.ui-switch:checked::after {
  transform: translateX(1rem);
}

.ui-switch:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}
</style>
