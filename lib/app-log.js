/**
 * Thin logging shim for high-signal app events. Each call BOTH:
 *   1. writes to console (so PM2's file logs capture it as before), AND
 *   2. records a structured entry in the in-memory app-event buffer (lib/server-state),
 *      surfaced on the Vista "Server Health" card.
 *
 * Use at deliberately-chosen high-signal error sites only (gateway failures, route
 * catch blocks, the top-level handler) — NOT as a blanket replacement for every
 * console.* call. Keeps the buffer a meaningful "important events" stream, not noise.
 */
const { recordAppEvent } = require('./server-state');

// Render args into a single console-friendly string without throwing on circular refs.
function joinArgs(args) {
    return args
        .map((a) => {
            if (typeof a === 'string') return a;
            try {
                return JSON.stringify(a);
            } catch (_e) {
                return String(a);
            }
        })
        .join(' ');
}

function logWarn(source, msg, meta) {
    console.warn(`[${source}] ${msg}`, meta != null ? meta : '');
    recordAppEvent('warn', source, msg, meta);
}

function logError(source, msg, meta) {
    console.error(`[${source}] ${msg}`, meta != null ? meta : '');
    recordAppEvent('error', source, msg, meta);
}

module.exports = { logWarn, logError, joinArgs };
