// Maps the normalized `{ action, payload }` produced by
// `lib/alexa/entity-mapping.translateAlexaDirective(...)` into the dialect the
// addon's `execute_google_command` case-switch understands. We do NOT introduce
// new addon actions for Alexa — instead, we translate Alexa-normalized actions
// into existing Google-flavored action strings so the addon's dispatcher (and
// its bash case arms) remain the single source of truth for HA service calls.
//
// Returns { addonAction, addonPayload } or null when the directive cannot be
// mapped (the caller should respond with an Alexa ErrorResponse).

'use strict';

function clampPercent(n) {
    const v = Number(n);
    if (!Number.isFinite(v)) return 0;
    if (v < 0) return 0;
    if (v > 100) return 100;
    return Math.round(v);
}

function kelvinFromMiredOrKelvin(n) {
    // entity-mapping.translateAlexaDirective already passes kelvin for
    // Alexa.ColorTemperatureController.SetColorTemperature, so we just coerce.
    const v = Number(n);
    if (!Number.isFinite(v) || v <= 0) return 3000;
    return Math.round(v);
}

function translateAlexaThermostatSetpoint(payload) {
    // entity-mapping normalizes into { target, lower, upper } each as
    // { value, scale }. Addon `set_thermostat_setpoint` expects
    // `{ setpoint }`, and `set_thermostat_setpoint_range` expects
    // `{ low, high }`. Scale is assumed to already be normalized to the
    // device's HA-native scale by the caller if needed; we pass through.
    const out = {};
    if (payload?.target && Number.isFinite(Number(payload.target.value))) {
        return { addonAction: 'set_thermostat_setpoint', addonPayload: { setpoint: Number(payload.target.value) } };
    }
    if (payload?.lower && payload?.upper) {
        return {
            addonAction: 'set_thermostat_setpoint_range',
            addonPayload: {
                low: Number(payload.lower.value),
                high: Number(payload.upper.value)
            }
        };
    }
    return null;
    /* eslint-disable-next-line no-unreachable */
    void out;
}

function translateAlexaActionToAddonAction(alexaAction, alexaPayload, entity) {
    if (!alexaAction) return null;
    const p = alexaPayload || {};
    const entityType = (entity && (entity.entity_type || entity.entityType)) || '';
    const instance = p.instance || '';

    switch (alexaAction) {
        case 'power.set':
            return {
                addonAction: 'set_on',
                addonPayload: { on: p.value === 'on' || p.value === true }
            };

        case 'brightness.set':
            return {
                addonAction: 'set_brightness',
                addonPayload: { brightness: clampPercent(p.value) }
            };

        case 'brightness.adjust':
            // TODO: ideally compute current brightness + delta on the server.
            // We currently forward the delta clamped into [0,100] as an
            // absolute value — Alexa's AdjustBrightness semantics expect a
            // relative delta, but we have no reliable cached state here.
            // Clients almost always use SetBrightness in practice.
            return {
                addonAction: 'set_brightness',
                addonPayload: { brightness: clampPercent(p.delta) }
            };

        case 'color.set': {
            const hue = Number(p.hue) || 0;
            const saturation = Math.round((Number(p.saturation) || 0) * 100);
            // entity-mapping sends brightness as 0..1; addon wants 0..255.
            const bri01 = Number(p.brightness);
            const brightness_255 = Math.max(
                0,
                Math.min(255, Math.round((Number.isFinite(bri01) ? bri01 : 1) * 255))
            );
            return {
                addonAction: 'set_color_hs',
                addonPayload: { hue, saturation, brightness_255 }
            };
        }

        case 'color_temperature.set':
            return {
                addonAction: 'set_color_temp',
                addonPayload: { color_temp_kelvin: kelvinFromMiredOrKelvin(p.kelvin) }
            };

        case 'color_temperature.adjust':
            // No corresponding addon action; unsupported for now.
            return null;

        case 'thermostat.mode':
            return {
                addonAction: 'set_thermostat_mode',
                addonPayload: { mode: String(p.value || '') }
            };

        case 'thermostat.setpoint':
            return translateAlexaThermostatSetpoint(p);

        case 'thermostat.adjust':
            // Would require reading current setpoint; not mapped.
            return null;

        case 'lock.set':
            return {
                addonAction: 'set_lock',
                addonPayload: { lock: p.value === 'lock' }
            };

        case 'scene.activate':
            return { addonAction: 'activate_scene', addonPayload: {} };

        case 'scene.deactivate':
            // Addon only has activate_scene — HA scene.turn_off is rarely
            // meaningful and not wired.
            return null;

        case 'range.set': {
            if (instance === 'Fan.Speed' || entityType === 'fan') {
                return {
                    addonAction: 'set_fan_speed_percent',
                    addonPayload: { percentage: clampPercent(p.value) }
                };
            }
            if (instance === 'Cover.Position' || entityType === 'cover') {
                return {
                    addonAction: 'set_open_percent',
                    addonPayload: { openPercent: clampPercent(p.value) }
                };
            }
            return null;
        }

        case 'range.adjust':
            // Would require reading current value; not mapped.
            return null;

        case 'mode.set': {
            if (instance === 'Cover.Position' || entityType === 'cover') {
                const open = String(p.value || '') === 'Position.Open';
                return {
                    addonAction: 'set_open_close',
                    addonPayload: { open }
                };
            }
            return null;
        }

        case 'toggle.set': {
            if (instance === 'Vacuum.Pause' || entityType === 'vacuum') {
                return {
                    addonAction: 'set_pause',
                    addonPayload: { pause: p.value === 'on' || p.value === true }
                };
            }
            return null;
        }

        case 'volume.set':
            return {
                addonAction: 'set_volume',
                addonPayload: { volume: Number(p.value) || 0 }
            };

        case 'volume.adjust':
            return null;

        case 'mute.set':
            return {
                addonAction: 'set_mute',
                addonPayload: { muted: Boolean(p.value) }
            };

        case 'playback.play':
            return { addonAction: 'media_resume', addonPayload: {} };
        case 'playback.pause':
            return { addonAction: 'media_pause', addonPayload: {} };
        case 'playback.stop':
            return { addonAction: 'media_stop', addonPayload: {} };
        case 'playback.next':
            return { addonAction: 'media_next', addonPayload: {} };
        case 'playback.previous':
            return { addonAction: 'media_previous', addonPayload: {} };

        default:
            return null;
    }
}

module.exports = { translateAlexaActionToAddonAction };
