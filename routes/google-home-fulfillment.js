const express = require('express');

module.exports = function ({ config, utils, auth, googleCore, homegraph, entityMapping }) {
    const router = express.Router();

    router.post('/api/google/home/fulfillment', auth.requireGoogleBearer, async (req, res) => {
        const requestId = utils.sanitizeGoogleRequestId(req.body?.requestId) || `req_${Date.now()}`;
        const inputs = Array.isArray(req.body?.inputs) ? req.body.inputs : [];
        const input = inputs[0] || {};
        const intent = utils.sanitizeString(input.intent, 120) || '';

        try {
            await homegraph.markGoogleEntitiesStaleByFreshness();

            if (intent === 'action.devices.SYNC') {
                const entities = await googleCore.getGoogleEntitiesForUser(req.googleUser.id, {
                    includeDisabled: false
                });
                const userPin = req.googleUser.google_home_security_pin || null;
                const devices = entities.map((entity) => entityMapping.buildGoogleDeviceObject(entity, userPin));

                return res.status(200).json({
                    requestId,
                    payload: {
                        agentUserId: String(req.googleUser.id),
                        devices
                    }
                });
            }

            if (intent === 'action.devices.QUERY') {
                const queryPayload = input.payload || {};
                const requestedDevices = Array.isArray(queryPayload.devices) ? queryPayload.devices : [];
                const requestedIds = requestedDevices.map((item) => utils.sanitizeEntityId(item?.id)).filter(Boolean);

                const entities = await googleCore.getGoogleEntitiesForUser(req.googleUser.id, {
                    includeDisabled: false
                });
                const entitiesMap = new Map(entities.map((entity) => [entity.entity_id, entity]));
                const devicesState = {};

                for (const entityId of requestedIds) {
                    const entity = entitiesMap.get(entityId);
                    if (!entity) {
                        devicesState[entityId] = {
                            online: false
                        };
                        continue;
                    }

                    const effectiveEntity = entity;
                    if (effectiveEntity.online !== 1) {
                        devicesState[entityId] = {
                            online: false
                        };
                        continue;
                    }

                    devicesState[entityId] = entityMapping.parseGoogleEntityState(effectiveEntity);
                }

                return res.status(200).json({
                    requestId,
                    payload: {
                        devices: devicesState
                    }
                });
            }

            if (intent === 'action.devices.EXECUTE') {
                const executePayload = input.payload || {};
                const commands = Array.isArray(executePayload.commands) ? executePayload.commands : [];
                const entities = await googleCore.getGoogleEntitiesForUser(req.googleUser.id, {
                    includeDisabled: false
                });
                const entitiesMap = new Map(entities.map((entity) => [entity.entity_id, entity]));
                const commandResults = [];

                for (const commandEntry of commands) {
                    const targetDevices = Array.isArray(commandEntry.devices) ? commandEntry.devices : [];
                    const executions = Array.isArray(commandEntry.execution) ? commandEntry.execution : [];

                    for (const target of targetDevices) {
                        const entityId = utils.sanitizeEntityId(target?.id);
                        if (!entityId) {
                            continue;
                        }

                        const entity = entitiesMap.get(entityId);
                        if (!entity) {
                            commandResults.push({
                                ids: [entityId],
                                status: 'ERROR',
                                errorCode: 'deviceOffline'
                            });
                            continue;
                        }

                        if (!utils.isEntityEffectivelyOnline(entity)) {
                            commandResults.push({
                                ids: [entityId],
                                status: 'ERROR',
                                errorCode: 'deviceOffline'
                            });
                            continue;
                        }

                        const entityStatePayload = utils.parseJsonSafe(entity.state_json, {}) || {};

                        for (const execution of executions) {
                            const commandName = utils.sanitizeActionName(execution?.command);
                            const params = execution?.params || {};

                            if (
                                !entityMapping.supportsGoogleCommandForEntityType(
                                    entity.entity_type,
                                    commandName,
                                    entityStatePayload
                                )
                            ) {
                                commandResults.push({
                                    ids: [entityId],
                                    status: 'ERROR',
                                    errorCode: 'notSupported'
                                });
                                continue;
                            }

                            const userSecurityPin = req.googleUser.google_home_security_pin || null;
                            const needsPin =
                                userSecurityPin &&
                                (commandName === 'action.devices.commands.ArmDisarm' ||
                                    commandName === 'action.devices.commands.LockUnlock');
                            if (needsPin) {
                                const challenge = execution?.challenge || params?.challenge;
                                if (!challenge || !challenge.pin) {
                                    commandResults.push({
                                        ids: [entityId],
                                        status: 'ERROR',
                                        errorCode: 'challengeNeeded',
                                        challengeNeeded: {
                                            type: 'pinNeeded'
                                        }
                                    });
                                    continue;
                                }
                                if (String(challenge.pin) !== String(userSecurityPin)) {
                                    commandResults.push({
                                        ids: [entityId],
                                        status: 'ERROR',
                                        errorCode: 'challengeNeeded',
                                        challengeNeeded: {
                                            type: 'challengeFailedPinNeeded'
                                        }
                                    });
                                    continue;
                                }
                            }

                            let action = null;
                            let payload = {};
                            let successStates = {};

                            if (commandName === 'action.devices.commands.OnOff') {
                                action = 'set_on';
                                payload = { on: Boolean(params?.on) };
                                successStates = { on: payload.on };
                                if (entity.entity_type === 'light' && payload.on) {
                                    const entityColorModes = Array.isArray(entityStatePayload.supported_color_modes)
                                        ? entityStatePayload.supported_color_modes
                                        : [];
                                    const hasBrightness =
                                        entityColorModes.length > 0 && !entityColorModes.every((m) => m === 'onoff');
                                    if (hasBrightness) {
                                        const storedBrightness = Number(entityStatePayload.brightness) || 0;
                                        successStates.brightness = storedBrightness > 0 ? storedBrightness : 100;
                                    }
                                }
                            } else if (commandName === 'action.devices.commands.BrightnessAbsolute') {
                                const brightnessVal = Math.max(0, Math.min(100, Number(params?.brightness ?? 0)));
                                const entityColorModes = Array.isArray(entityStatePayload.supported_color_modes)
                                    ? entityStatePayload.supported_color_modes
                                    : [];
                                const hasBrightness =
                                    entityColorModes.length > 0 && !entityColorModes.every((m) => m === 'onoff');
                                if (hasBrightness) {
                                    action = 'set_brightness';
                                    payload = { brightness: brightnessVal };
                                    successStates = { on: true, brightness: brightnessVal };
                                } else {
                                    action = 'set_on';
                                    payload = { on: brightnessVal > 0 };
                                    successStates = { on: brightnessVal > 0 };
                                }
                            } else if (commandName === 'action.devices.commands.ColorAbsolute') {
                                const color = params?.color || {};
                                if (color.spectrumHSV || color.spectrumHsv) {
                                    const hsv = color.spectrumHSV || color.spectrumHsv || {};
                                    action = 'set_color_hs';
                                    payload = {
                                        hue: Number(hsv.hue ?? 0),
                                        saturation: Math.round(Number(hsv.saturation ?? 0) * 100),
                                        brightness_255: Math.round(Number(hsv.value ?? 1) * 255)
                                    };
                                    successStates = { color: { spectrumHsv: hsv } };
                                } else if (color.temperature || color.temperatureK) {
                                    action = 'set_color_temp';
                                    payload = {
                                        color_temp_kelvin: Number(color.temperature || color.temperatureK || 3000)
                                    };
                                    successStates = { color: { temperatureK: payload.color_temp_kelvin } };
                                } else {
                                    commandResults.push({
                                        ids: [entityId],
                                        status: 'ERROR',
                                        errorCode: 'notSupported'
                                    });
                                    continue;
                                }
                            } else if (commandName === 'action.devices.commands.SetFanSpeed') {
                                const sfEntity = Number(entityStatePayload.supported_features) || 0;
                                const hasSetSpeed = (sfEntity & 1) !== 0;
                                const percentageStep = Number(entityStatePayload.percentage_step) || 0;

                                if (entity.entity_type === 'vacuum') {
                                    action = 'set_vacuum_fan_speed';
                                    payload = { fan_speed: String(params?.fanSpeed || '') };
                                    successStates = { currentFanSpeedSetting: payload.fan_speed };
                                } else if (hasSetSpeed && percentageStep > 0 && params?.fanSpeedPercent !== undefined) {
                                    action = 'set_fan_speed_percent';
                                    payload = {
                                        percentage: Math.max(
                                            0,
                                            Math.min(100, Math.round(Number(params.fanSpeedPercent)))
                                        )
                                    };
                                    successStates = {
                                        currentFanSpeedSetting: String(
                                            Math.max(1, Math.round(payload.percentage / percentageStep))
                                        ),
                                        currentFanSpeedPercent: payload.percentage
                                    };
                                } else if (hasSetSpeed && percentageStep > 0 && params?.fanSpeed) {
                                    const speedIndex = Number(params.fanSpeed) || 1;
                                    const pct = Math.round(speedIndex * percentageStep);
                                    action = 'set_fan_speed_percent';
                                    payload = { percentage: Math.max(0, Math.min(100, pct)) };
                                    successStates = {
                                        currentFanSpeedSetting: String(speedIndex),
                                        currentFanSpeedPercent: payload.percentage
                                    };
                                } else if (!hasSetSpeed && (sfEntity & 8) !== 0) {
                                    action = 'set_fan_preset';
                                    payload = { preset_mode: String(params?.fanSpeed || '') };
                                    successStates = { currentFanSpeedSetting: payload.preset_mode };
                                } else {
                                    action = 'set_fan_speed';
                                    payload = { speed: String(params?.fanSpeed || '1') };
                                    successStates = { currentFanSpeedSetting: payload.speed };
                                }
                            } else if (commandName === 'action.devices.commands.SetFanSpeedRelative') {
                                const sfEntity = Number(entityStatePayload.supported_features) || 0;
                                const hasSetSpeed = (sfEntity & 1) !== 0;
                                const percentageStep = Number(entityStatePayload.percentage_step) || 0;
                                if (hasSetSpeed && percentageStep > 0) {
                                    const currentPct = Number(entityStatePayload.percentage) || 0;
                                    const relWeight = Number(params?.fanSpeedRelativeWeight ?? 0);
                                    const relPercent = Number(params?.fanSpeedRelativePercent ?? 0);
                                    let newPct;
                                    if (relPercent !== 0) {
                                        newPct = currentPct + relPercent;
                                    } else {
                                        newPct = currentPct + relWeight * percentageStep;
                                    }
                                    newPct = Math.max(0, Math.min(100, Math.round(newPct)));
                                    action = 'set_fan_speed_percent';
                                    payload = { percentage: newPct };
                                    successStates = {
                                        currentFanSpeedSetting: String(
                                            Math.max(1, Math.round(newPct / percentageStep))
                                        ),
                                        currentFanSpeedPercent: newPct
                                    };
                                } else {
                                    commandResults.push({
                                        ids: [entityId],
                                        status: 'ERROR',
                                        errorCode: 'notSupported'
                                    });
                                    continue;
                                }
                            } else if (commandName === 'action.devices.commands.OpenClose') {
                                const openPercent = Math.max(0, Math.min(100, Number(params?.openPercent ?? 0)));
                                const sfEntity = Number(entityStatePayload.supported_features) || 0;
                                const hasSetPosition = (sfEntity & 4) !== 0;
                                if (entity.entity_type === 'valve') {
                                    if (hasSetPosition) {
                                        action = 'set_valve_position';
                                        payload = { openPercent };
                                    } else {
                                        action = 'set_valve_open_close';
                                        payload = { open: openPercent > 0 };
                                    }
                                } else if (hasSetPosition || sfEntity === 0) {
                                    action = 'set_open_percent';
                                    payload = { openPercent };
                                } else {
                                    action = 'set_open_close';
                                    payload = { open: openPercent > 0 };
                                }
                                successStates = { openPercent };
                            } else if (commandName === 'action.devices.commands.OpenCloseRelative') {
                                const relPercent = Number(params?.openRelativePercent ?? 0);
                                const currentOpen = Number(entityStatePayload.openPercent ?? 50);
                                const newOpen = Math.max(0, Math.min(100, Math.round(currentOpen + relPercent)));
                                if (entity.entity_type === 'valve') {
                                    action = 'set_valve_position';
                                    payload = { openPercent: newOpen };
                                } else {
                                    action = 'set_open_percent';
                                    payload = { openPercent: newOpen };
                                }
                                successStates = { openPercent: newOpen };
                            } else if (commandName === 'action.devices.commands.RotateAbsolute') {
                                action = 'set_tilt';
                                const tilt = Math.max(0, Math.min(100, Number(params?.rotationPercent ?? 0)));
                                payload = { tilt };
                                successStates = { rotationPercent: tilt };
                            } else if (commandName === 'action.devices.commands.LockUnlock') {
                                action = 'set_lock';
                                payload = { lock: Boolean(params?.lock) };
                                successStates = { isLocked: payload.lock };
                            } else if (commandName === 'action.devices.commands.ThermostatSetMode') {
                                const mode = entityMapping.normalizeGoogleThermostatMode(params?.thermostatMode);
                                action = 'set_thermostat_mode';
                                payload = { mode };
                                successStates = { thermostatMode: mode };
                            } else if (commandName === 'action.devices.commands.ThermostatTemperatureSetpoint') {
                                const setpoint = Number(params?.thermostatTemperatureSetpoint ?? 22);
                                action = 'set_thermostat_setpoint';
                                payload = { setpoint };
                                successStates = { thermostatTemperatureSetpoint: setpoint };
                            } else if (commandName === 'action.devices.commands.ThermostatTemperatureSetRange') {
                                action = 'set_thermostat_setpoint_range';
                                payload = {
                                    heat_setpoint: Number(params?.thermostatTemperatureSetpointLow ?? 20),
                                    cool_setpoint: Number(params?.thermostatTemperatureSetpointHigh ?? 24)
                                };
                                successStates = {
                                    thermostatTemperatureSetpointLow: payload.heat_setpoint,
                                    thermostatTemperatureSetpointHigh: payload.cool_setpoint
                                };
                            } else if (commandName === 'action.devices.commands.SetTemperature') {
                                const tempSetpoint = Number(params?.temperature ?? 50);
                                action = 'set_water_heater_temperature';
                                payload = { temperature: tempSetpoint };
                                successStates = { temperatureSetpointCelsius: tempSetpoint };
                            } else if (commandName === 'action.devices.commands.setVolume') {
                                action = 'set_volume';
                                payload = {
                                    volume: Math.max(0, Math.min(100, Number(params?.volumeLevel ?? 0)))
                                };
                                if (Object.prototype.hasOwnProperty.call(params || {}, 'mute')) {
                                    payload.muted = Boolean(params?.mute);
                                }
                                successStates = { currentVolume: payload.volume };
                                if (payload.muted !== undefined) successStates.isMuted = payload.muted;
                            } else if (commandName === 'action.devices.commands.volumeRelative') {
                                const relSteps = Number(params?.relativeSteps ?? 0);
                                const currentVol = Number(entityStatePayload.volume ?? 0);
                                const stepSize = Number(entityStatePayload.volume_step) || 5;
                                const newVol = Math.max(0, Math.min(100, Math.round(currentVol + relSteps * stepSize)));
                                action = 'set_volume';
                                payload = { volume: newVol };
                                successStates = { currentVolume: newVol };
                            } else if (commandName === 'action.devices.commands.mute') {
                                action = 'set_mute';
                                payload = { muted: Boolean(params?.mute) };
                                successStates = { isMuted: payload.muted };
                            } else if (commandName === 'action.devices.commands.mediaControl') {
                                const mediaCommand = params?.mediaCommand || '';
                                if (mediaCommand === 'PAUSE') {
                                    action = 'media_pause';
                                } else if (mediaCommand === 'RESUME') {
                                    action = 'media_resume';
                                } else if (mediaCommand === 'STOP') {
                                    action = 'media_stop';
                                } else if (mediaCommand === 'NEXT') {
                                    action = 'media_next';
                                } else if (mediaCommand === 'PREVIOUS') {
                                    action = 'media_previous';
                                } else {
                                    commandResults.push({
                                        ids: [entityId],
                                        status: 'ERROR',
                                        errorCode: 'notSupported'
                                    });
                                    continue;
                                }
                                payload = {};
                                successStates = {};
                            } else if (commandName === 'action.devices.commands.mediaSeekToPosition') {
                                action = 'media_seek';
                                const seekPosition = Number(params?.absPositionMs ?? 0);
                                payload = { seek_position: seekPosition / 1000 };
                                successStates = {};
                            } else if (commandName === 'action.devices.commands.mediaSeekRelative') {
                                action = 'media_seek_relative';
                                const relMs = Number(params?.relativePositionMs ?? 0);
                                const currentPos = Number(entityStatePayload.media_position ?? 0);
                                const newPos = Math.max(0, currentPos + relMs / 1000);
                                payload = { seek_position: newPos };
                                successStates = {};
                            } else if (commandName === 'action.devices.commands.Shuffle') {
                                action = 'media_shuffle';
                                payload = { shuffle: Boolean(params?.shuffle) };
                                successStates = {};
                            } else if (commandName === 'action.devices.commands.SetRepeat') {
                                action = 'media_repeat';
                                const repeatMode = Boolean(params?.isOn);
                                const isSingle = Boolean(params?.isSingle);
                                payload = { repeat: repeatMode ? (isSingle ? 'one' : 'all') : 'off' };
                                successStates = {};
                            } else if (commandName === 'action.devices.commands.SetInput') {
                                const inputKey = params?.newInput || '';
                                const sourceList = Array.isArray(entityStatePayload.source_list)
                                    ? entityStatePayload.source_list
                                    : [];
                                const matchedSource =
                                    sourceList.find(
                                        (src) => src.toLowerCase().replace(/[^a-z0-9_]/g, '_') === inputKey
                                    ) || inputKey;
                                action = 'set_input';
                                payload = { source: matchedSource };
                                successStates = { currentInput: inputKey };
                            } else if (commandName === 'action.devices.commands.ActivateScene') {
                                action = 'activate_scene';
                                payload = { deactivate: Boolean(params?.deactivate) };
                                successStates = {};
                            } else if (commandName === 'action.devices.commands.StartStop') {
                                if (entity.entity_type === 'lawn_mower') {
                                    if (params?.start) {
                                        action = 'lawn_mower_start';
                                        payload = {};
                                    } else {
                                        const sfEntity = Number(entityStatePayload.supported_features) || 0;
                                        const hasDock = (sfEntity & 4) !== 0;
                                        action = hasDock ? 'lawn_mower_dock' : 'lawn_mower_pause';
                                        payload = {};
                                    }
                                } else {
                                    action = 'set_start_stop';
                                    payload = { start: Boolean(params?.start) };
                                }
                                successStates = { isRunning: Boolean(params?.start) };
                            } else if (commandName === 'action.devices.commands.PauseUnpause') {
                                if (entity.entity_type === 'lawn_mower') {
                                    if (params?.pause) {
                                        action = 'lawn_mower_pause';
                                        payload = {};
                                    } else {
                                        action = 'lawn_mower_start';
                                        payload = {};
                                    }
                                    successStates = { isPaused: Boolean(params?.pause) };
                                } else {
                                    action = 'set_pause';
                                    payload = { pause: Boolean(params?.pause) };
                                    successStates = { isPaused: Boolean(params?.pause) };
                                }
                            } else if (commandName === 'action.devices.commands.Dock') {
                                action = 'dock';
                                payload = {};
                                successStates = { isDocked: true, isRunning: false };
                            } else if (commandName === 'action.devices.commands.Locate') {
                                action = 'locate';
                                payload = {};
                                successStates = {};
                            } else if (commandName === 'action.devices.commands.SetHumidity') {
                                action = 'set_humidity';
                                payload = {
                                    humidity: Math.max(0, Math.min(100, Number(params?.humiditySetpointPercent ?? 50)))
                                };
                                successStates = { humiditySetpointPercent: payload.humidity };
                            } else if (commandName === 'action.devices.commands.SetModes') {
                                const updateModeSettings = params?.updateModeSettings || {};
                                if (entity.entity_type === 'humidifier') {
                                    const modeName = Object.keys(updateModeSettings)[0] || '';
                                    const modeValue = updateModeSettings[modeName] || '';
                                    action = 'set_humidifier_mode';
                                    payload = { mode: modeValue };
                                    successStates = { currentModeSettings: { mode: modeValue } };
                                } else if (entity.entity_type === 'select' || entity.entity_type === 'input_select') {
                                    const selectedOption = updateModeSettings.option || '';
                                    action = 'set_select_option';
                                    payload = { option: selectedOption };
                                    successStates = { currentModeSettings: { option: selectedOption } };
                                } else if (entity.entity_type === 'climate') {
                                    const modeName = Object.keys(updateModeSettings)[0] || '';
                                    const modeValue = updateModeSettings[modeName] || '';
                                    if (modeName === 'fan_mode') {
                                        action = 'set_climate_fan_mode';
                                        payload = { fan_mode: modeValue };
                                    } else if (modeName === 'preset_mode') {
                                        action = 'set_climate_preset_mode';
                                        payload = { preset_mode: modeValue };
                                    } else if (modeName === 'swing_mode') {
                                        action = 'set_climate_swing_mode';
                                        payload = { swing_mode: modeValue };
                                    } else {
                                        commandResults.push({
                                            ids: [entityId],
                                            status: 'ERROR',
                                            errorCode: 'notSupported'
                                        });
                                        continue;
                                    }
                                    successStates = { currentModeSettings: { [modeName]: modeValue } };
                                } else if (entity.entity_type === 'media_player') {
                                    const modeValue = updateModeSettings.sound_mode || '';
                                    action = 'set_sound_mode';
                                    payload = { sound_mode: modeValue };
                                    successStates = { currentModeSettings: { sound_mode: modeValue } };
                                } else if (entity.entity_type === 'light') {
                                    const effectValue = updateModeSettings.effect || '';
                                    action = 'set_light_effect';
                                    payload = { effect: effectValue };
                                    successStates = { currentModeSettings: { effect: effectValue } };
                                } else if (entity.entity_type === 'fan') {
                                    const presetValue = updateModeSettings.preset_mode || '';
                                    action = 'set_fan_preset';
                                    payload = { preset_mode: presetValue };
                                    successStates = { currentModeSettings: { preset_mode: presetValue } };
                                } else {
                                    commandResults.push({
                                        ids: [entityId],
                                        status: 'ERROR',
                                        errorCode: 'notSupported'
                                    });
                                    continue;
                                }
                            } else if (commandName === 'action.devices.commands.ArmDisarm') {
                                action = 'arm_disarm';
                                payload = {
                                    arm: Boolean(params?.arm),
                                    arm_level: String(params?.armLevel || '')
                                };
                                successStates = {
                                    isArmed: payload.arm,
                                    ...(payload.arm && payload.arm_level ? { currentArmLevel: payload.arm_level } : {})
                                };
                            } else if (commandName === 'action.devices.commands.GetCameraStream') {
                                try {
                                    const queuedCmd = await googleCore.queueGoogleCommandForEntity(
                                        req.googleUser.id,
                                        entity.device_id,
                                        entity.entity_id,
                                        'get_camera_stream',
                                        {}
                                    );
                                    if (!queuedCmd?.id) {
                                        commandResults.push({
                                            ids: [entityId],
                                            status: 'ERROR',
                                            errorCode: 'transientError',
                                            debugString: 'Unable to queue camera stream request'
                                        });
                                        continue;
                                    }

                                    const result = await googleCore.waitForGoogleCommandResult(queuedCmd.id, 10000);
                                    const streamPath = result?.state?.stream_path;

                                    if (streamPath) {
                                        const subdomain = req.googleUser.subdomain;
                                        const streamUrl = `https://${subdomain}.${config.CLOUD_BASE_DOMAIN}${streamPath}`;
                                        commandResults.push({
                                            ids: [entityId],
                                            status: 'SUCCESS',
                                            states: {
                                                online: true,
                                                cameraStreamAccessUrl: streamUrl,
                                                cameraStreamProtocol: 'hls'
                                            }
                                        });
                                    } else {
                                        commandResults.push({
                                            ids: [entityId],
                                            status: 'ERROR',
                                            errorCode: 'transientError',
                                            debugString: 'Unable to start camera stream'
                                        });
                                    }
                                } catch (camErr) {
                                    console.error('CAMERA STREAM EXECUTE ERROR:', camErr);
                                    commandResults.push({
                                        ids: [entityId],
                                        status: 'ERROR',
                                        errorCode: 'transientError'
                                    });
                                }
                                continue;
                            } else {
                                commandResults.push({
                                    ids: [entityId],
                                    status: 'ERROR',
                                    errorCode: 'notSupported'
                                });
                                continue;
                            }

                            await googleCore.queueGoogleCommandForEntity(
                                req.googleUser.id,
                                entity.device_id,
                                entity.entity_id,
                                action,
                                payload
                            );
                            commandResults.push({
                                ids: [entityId],
                                status: 'SUCCESS',
                                states: {
                                    online: true,
                                    ...successStates
                                }
                            });
                        }
                    }
                }

                return res.status(200).json({
                    requestId,
                    payload: {
                        commands: commandResults
                    }
                });
            }

            if (intent === 'action.devices.DISCONNECT') {
                await googleCore.cleanupGoogleAuthDataForUser(req.googleUser.id);
                homegraph.scheduleGoogleRequestSyncForUser(req.googleUser.id, 'google_home_unlinked');
                return res.status(200).json({ requestId, payload: {} });
            }

            return res.status(400).json({ error: 'Unsupported intent' });
        } catch (error) {
            console.error('GOOGLE FULFILLMENT ERROR:', error);
            return res.status(500).json({ error: 'Unable to process Google fulfillment request' });
        }
    });

    return router;
};
