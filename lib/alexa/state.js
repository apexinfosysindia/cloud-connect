const state = {
    // LWA access-token cache, keyed by userId → { token, expiresAt }
    alexaLwaAccessTokenCache: new Map(),
    // In-flight LWA refresh promises, keyed by userId → Promise<token|null>. Single-
    // flight: when the cache is cold and many sends fire concurrently (e.g. a bulk
    // hide), the FIRST caller starts the refresh and stores its promise here; every
    // concurrent caller awaits the SAME promise instead of starting its own. Without
    // this, N concurrent sends each POST to Amazon's LWA token endpoint for the same
    // user → Amazon throttles them → "LWA token refresh failed". Cleared when the
    // refresh settles.
    alexaLwaRefreshInflight: new Map(),
    // Per-user debounce/coalesce queues for outbound Event Gateway reports
    alexaAddOrUpdateQueue: new Map(),
    alexaChangeReportQueue: new Map(),
    // Delete-report queue accumulates endpointIds across coalesced calls, since
    // the underlying rows may be gone by the time the report fires.
    alexaDeleteReportQueue: new Map(),
    // Per-user timestamp (ms) of the last dashboard liveness probe, to throttle
    // the AddOrUpdateReport we fire from /api/account/me (5s poll) down to once
    // per minute. Keyed by userId → epoch ms.
    alexaLivenessProbeAt: new Map(),
    // In-memory unlink-retry timers, keyed by userId → { timer, attempt }. When a
    // portal unlink's DeleteReport can't land (Amazon's enablement state is still
    // converging after a rapid link/unlink), we keep the link and retry the delete
    // with backoff. In-memory only — a process restart drops the pending retry and
    // the user falls back to clicking Unlink again (which #230 supports).
    alexaUnlinkRetryQueue: new Map(),
    alexaEventGatewayMetrics: {
        add_or_update_report: {
            sent: 0,
            failed: 0,
            skipped: 0,
            last_success_at: null,
            last_failure_at: null,
            last_failure_reason: null,
            last_status: null,
            last_user_id: null
        },
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
        delete_report: {
            sent: 0,
            failed: 0,
            skipped: 0,
            last_success_at: null,
            last_failure_at: null,
            last_failure_reason: null,
            last_status: null,
            last_user_id: null
        },
        doorbell_event: {
            sent: 0,
            failed: 0,
            skipped: 0,
            last_success_at: null,
            last_failure_at: null,
            last_failure_reason: null,
            last_status: null,
            last_user_id: null
        }
    }
};

module.exports = state;
