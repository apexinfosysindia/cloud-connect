const express = require('express');

/**
 * Alexa/Smart Home admin diagnostics — the Alexa analog of routes/google-home-admin.js.
 *
 * Surfaces the proactive-report telemetry that both integrations already record but never
 * exposed: lib/alexa/event-gateway.js (markSuccess/markFailure/markSkipped →
 * state.alexaEventGatewayMetrics) and lib/google-home/homegraph.js (→ state.homegraphMetrics).
 * Each tracks per-report-type sent/failed/skipped + last_success_at/last_failure_at/
 * last_failure_reason/last_status/last_user_id.
 *
 * The metrics are GLOBAL/fleet-wide (not per-user), so this is an ADMIN ops view, secured
 * with requireAdmin and rendered on the Vista dashboard ("Smart Home Health"). It answers:
 * are proactive reports to Amazon/Google failing across the fleet, and why?
 */
module.exports = function ({ utils, auth, state, alexaState }) {
    const router = express.Router();
    const { asyncHandler } = utils;

    router.get(
        '/api/admin/smart-home-health',
        auth.requireAdmin,
        asyncHandler(async (req, res) => {
            res.status(200).json({
                // NOTE: deps.state is the GOOGLE state singleton (homegraphMetrics);
                // Alexa's metrics live on the separate deps.alexaState singleton.
                alexa: alexaState.alexaEventGatewayMetrics,
                google: state.homegraphMetrics
            });
        })
    );

    return router;
};
