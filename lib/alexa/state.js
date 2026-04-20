// In-process singleton for Alexa event gateway coordination.
// Mirrors lib/google-home/state.js patterns: debounce timer maps keyed by userId,
// LWA access-token cache per user, and telemetry counters.

const state = {
    // Per-user ChangeReport debounce timers: Map<userId, { timer, queuedAt, force }>
    alexaChangeReportQueue: new Map(),
    // Per-user discovery (AddOrUpdateReport) debounce timers
    alexaDiscoveryQueue: new Map(),
    // Per-user Amazon LWA access-token cache: Map<userId, { token, expiresAt }>
    alexaLwaTokenCache: new Map(),
    alexaMetrics: {
        change_report: {
            sent: 0,
            failed: 0,
            skipped: 0,
            last_success_at: null,
            last_failure_at: null,
            last_failure_reason: null,
            last_status: null,
            last_user_id: null
        },
        discovery: {
            sent: 0,
            failed: 0,
            skipped: 0,
            last_success_at: null,
            last_failure_at: null,
            last_failure_reason: null,
            last_status: null,
            last_user_id: null
        }
    },
    alexaStateHashTableSupported: true,
    alexaRuntimeSchemaReadyPromise: null
};

module.exports = state;
