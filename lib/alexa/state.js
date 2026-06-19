const state = {
    // LWA access-token cache, keyed by userId → { token, expiresAt }
    alexaLwaAccessTokenCache: new Map(),
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
