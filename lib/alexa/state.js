const state = {
    // LWA access-token cache is PER-USER (unlike Google's service-wide JWT),
    // so we don't carry a single process-wide access-token cache here. The
    // authoritative store is alexa_tokens.lwa_access_token_encrypted; this
    // object only holds debounce queues + metrics.
    alexaChangeReportQueue: new Map(),
    alexaAddOrUpdateReportQueue: new Map(),
    eventGatewayMetrics: {
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
        add_or_update_report: {
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
    alexaEntityLastSeenColumnSupported: true,
    alexaSyncSnapshotsTableSupported: true,
    alexaSyncSnapshotsUpsertSupported: true,
    alexaStateHashColumnSupported: true,
    alexaLastReportedColumnsSupported: true,
    alexaRuntimeSchemaReadyPromise: null
};

module.exports = state;
