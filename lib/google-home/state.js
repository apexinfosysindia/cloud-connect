const state = {
    googleHomegraphAccessTokenCache: {
        token: null,
        expiresAt: 0
    },
    googleHomegraphRequestSyncQueue: new Map(),
    googleHomegraphReportStateQueue: new Map(),
    homegraphMetrics: {
        request_sync: {
            sent: 0,
            failed: 0,
            skipped: 0,
            last_success_at: null,
            last_failure_at: null,
            last_failure_reason: null,
            last_status: null,
            last_user_id: null
        },
        report_state: {
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
    googleEntityLastSeenColumnSupported: true,
    googleSyncSnapshotsTableSupported: true,
    googleSyncSnapshotsUpsertSupported: true,
    googleStateHashColumnSupported: true,
    googleLastReportedColumnsSupported: true,
    googleRuntimeSchemaReadyPromise: null,
    // Ring buffer of the most recent HomeGraph events (newest last), for the admin
    // "recent events" log stream. In-memory only — bounded and volatile (clears on
    // restart, like homegraphMetrics above). Each entry:
    //   { at, type, outcome: 'sent'|'failed'|'skipped', user_id, status, detail }
    homegraphRecent: []
};

module.exports = state;
