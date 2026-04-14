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
    googleRuntimeSchemaReadyPromise: null
};

module.exports = state;
