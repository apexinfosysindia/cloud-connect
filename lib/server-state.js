/**
 * Generic, app-wide in-memory state that isn't tied to a specific integration.
 *
 * Currently holds the server app-event ring buffer — a bounded, volatile record of
 * recent warn/error-level app events for the Vista "Server Health" admin card. Same
 * contract as the Alexa/Google gateway `recent` buffers: in-memory only, capped, and
 * cleared on restart (the PM2 file logs are the durable record).
 */
const APP_EVENTS_CAP = 200;

const serverState = {
    // Newest last. Each entry: { at, level: 'warn'|'error', source, msg, meta }
    appEvents: []
};

/**
 * Append one app event to the ring buffer (best-effort, never throws). `meta` is an
 * optional small object; it is shallow-JSON-trimmed so a huge object can't bloat memory.
 */
function recordAppEvent(level, source, msg, meta) {
    try {
        const entry = {
            at: new Date().toISOString(),
            level: level === 'error' ? 'error' : 'warn',
            source: String(source || 'app').slice(0, 80),
            msg: String(msg == null ? '' : msg).slice(0, 500)
        };
        if (meta && typeof meta === 'object') {
            let metaStr = null;
            try {
                metaStr = JSON.stringify(meta).slice(0, 1000);
            } catch (_e) {
                metaStr = null;
            }
            if (metaStr) entry.meta = metaStr;
        }
        serverState.appEvents.push(entry);
        const overflow = serverState.appEvents.length - APP_EVENTS_CAP;
        if (overflow > 0) serverState.appEvents.splice(0, overflow);
    } catch (_e) {
        // never let logging break the caller
    }
}

module.exports = { serverState, recordAppEvent, APP_EVENTS_CAP };
