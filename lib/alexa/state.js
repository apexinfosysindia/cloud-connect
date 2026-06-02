const state = {
    // LWA access-token cache, keyed by userId → { token, expiresAt }
    alexaLwaAccessTokenCache: new Map(),
    // Per-user debounce/coalesce queues for outbound Event Gateway reports
    alexaAddOrUpdateQueue: new Map(),
    alexaChangeReportQueue: new Map(),
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
        }
    }
};

module.exports = state;
