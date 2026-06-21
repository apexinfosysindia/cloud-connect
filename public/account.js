(function accountPortal() {
    const pageMode = document.body.dataset.authMode;
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');
    const forgotPasswordForm = document.getElementById('forgotPasswordForm');
    const forgotPasswordLink = document.getElementById('forgotPasswordLink');
    const backToLoginLink = document.getElementById('backToLoginLink');
    const dashboard = document.getElementById('dashboard');
    const headerSubtitle = document.getElementById('headerSubtitle');
    const accountTitle = document.getElementById('accountTitle');
    const alertBox = document.getElementById('alertBox');
    const logoutBtn = document.getElementById('logoutBtn');
    const headerLogoutBtn = document.getElementById('headerLogoutBtn');
    const guestNavActions = document.getElementById('guestNavActions');
    const signedInNavActions = document.getElementById('signedInNavActions');
    const subdomainCard = document.getElementById('subdomainCard');
    const dashSubdomain = document.getElementById('dashSubdomain');
    const saveSubdomainBtn = document.getElementById('saveSubdomainBtn');
    const dashUrlHelp = document.getElementById('dashUrlHelp');
    const googleHomeCard = document.getElementById('googleHomeCard');
    const googleHomeStatus = document.getElementById('googleHomeStatus');
    const googleHomeEntities = document.getElementById('googleHomeEntities');
    const googleUnlinkBtn = document.getElementById('googleUnlinkBtn');
    const googleConsentCard = document.getElementById('googleConsentCard');
    const googleConsentMeta = document.getElementById('googleConsentMeta');
    const googleConsentApproveBtn = document.getElementById('googleConsentApproveBtn');
    const googleConsentDenyBtn = document.getElementById('googleConsentDenyBtn');
    const emailVerificationCard = document.getElementById('emailVerificationCard');
    const resendVerificationBtn = document.getElementById('resendVerificationBtn');
    const portalBrandTitle = 'ApexOS Cloud Connect Oasis';
    const loginTitle = `Sign In | ${portalBrandTitle}`;
    const signupTitle = `Create Account | ${portalBrandTitle}`;
    const dashboardTitle = `Account | ${portalBrandTitle}`;
    const ACCOUNT_REFRESH_MS = 5000;
    const GOOGLE_ENTITIES_REFRESH_MS = 15000;
    let accountRefreshTimer = null;
    let accountRefreshInFlight = false;
    let accountRenderFingerprint = '';
    let manageViewActive = false;
    let googleOAuthRedirectInFlight = false;
    let alexaOAuthRedirectInFlight = false;
    let googleEntitiesRefreshTimer = null;
    let googleEntitiesRefreshInFlight = false;
    let googleEntitiesRefreshKey = '';
    let googleEntitiesLastFingerprint = null;
    // Alexa mirror of the Google fingerprint: the Alexa card reloads on every
    // 5s account-refresh tick, so guard structural re-renders behind a content
    // fingerprint to avoid wiping innerHTML (and the user's scroll) needlessly.
    let alexaEntitiesLastFingerprint = null;
    const oauthParams = new URLSearchParams(window.location.search);
    const googleOAuthMode = oauthParams.get('google_oauth') === '1';
    const googleOAuthClientId = oauthParams.get('client_id') || '';
    const googleOAuthRedirectUri = oauthParams.get('redirect_uri') || '';
    const googleOAuthState = oauthParams.get('state') || '';
    const googleOAuthError = oauthParams.get('error') || '';
    const googleOAuthConsentMode = oauthParams.get('google_oauth_consent') === '1';
    const googleOAuthChallengeParam = oauthParams.get('oauth_challenge') || '';
    // Alexa account-linking mirror of googleOAuthMode. Alexa intentionally has
    // no consent step (the Alexa app already showed its own consent screen
    // before bouncing here) and no cookie-probe step (login and OAuth both run
    // on the portal host — no cross-host cookie round-trip needed).
    const alexaOAuthMode = oauthParams.get('alexa_oauth') === '1';
    const alexaOAuthClientId = oauthParams.get('client_id') || '';
    const alexaOAuthRedirectUri = oauthParams.get('redirect_uri') || '';
    const alexaOAuthState = oauthParams.get('state') || '';
    const alexaOAuthError = oauthParams.get('error') || '';
    const googleOAuthCookieProbeKey = [
        'apx_google_oauth_cookie_probe',
        googleOAuthClientId,
        googleOAuthRedirectUri,
        googleOAuthState
    ].join('|');

    function hasTriedGoogleOAuthCookieProbe() {
        if (!googleOAuthMode) {
            return false;
        }

        try {
            return window.sessionStorage.getItem(googleOAuthCookieProbeKey) === '1';
        } catch (_error) {
            return false;
        }
    }

    function markGoogleOAuthCookieProbeTried() {
        if (!googleOAuthMode) {
            return;
        }

        try {
            window.sessionStorage.setItem(googleOAuthCookieProbeKey, '1');
        } catch (_error) {
            // ignore sessionStorage failures
        }
    }

    function showAlert(message, isError = true) {
        alertBox.textContent = message;
        window.clearTimeout(showAlert.dismissTimer);
        alertBox.className = `alert is-visible ${isError ? 'is-error' : 'is-success'}`;

        showAlert.dismissTimer = window.setTimeout(() => {
            hideAlert();
        }, 3500);
    }

    function hideAlert() {
        window.clearTimeout(showAlert.dismissTimer);
        alertBox.className = 'alert';
    }

    async function copyToClipboard(value) {
        if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
            await navigator.clipboard.writeText(value);
            return;
        }

        const temp = document.createElement('textarea');
        temp.value = value;
        temp.setAttribute('readonly', '');
        temp.style.position = 'absolute';
        temp.style.left = '-9999px';
        document.body.appendChild(temp);
        temp.select();
        document.execCommand('copy');
        document.body.removeChild(temp);
    }

    function restoreButton(button, fallbackText) {
        if (!button) return;
        button.textContent = fallbackText;
        button.disabled = false;
    }

    // ── Identifier-first login state machine ────────────────────────────────
    // The login form is one <form> holding four steps (email → passkey /
    // password → otp) that toggle via .hidden. `loginCurrentStep` drives the
    // single submit dispatcher (defined with the form handler lower down), and
    // `loginEmailValue` carries the validated address between steps so later
    // steps never re-read the (now-hidden) email input.
    const loginSteps = {
        email: document.getElementById('loginStepEmail'),
        passkey: document.getElementById('loginStepPasskey'),
        password: document.getElementById('loginStepPassword'),
        otp: document.getElementById('loginStepOtp')
    };
    let loginCurrentStep = 'email';
    let loginEmailValue = '';

    // Show one step, hide the rest, and focus its primary input. Resetting to
    // 'email' also clears the carried-over address + transient field values so a
    // returning view never shows a stale password/code.
    function goLoginStep(step) {
        loginCurrentStep = step;
        Object.keys(loginSteps).forEach((key) => {
            const el = loginSteps[key];
            if (el) el.classList.toggle('hidden', key !== step);
        });

        if (step === 'email') {
            loginEmailValue = '';
            const pw = document.getElementById('loginPassword');
            const otp = document.getElementById('loginOtp');
            if (pw) pw.value = '';
            if (otp) otp.value = '';
        }

        const focusId = {
            email: 'loginEmail',
            passkey: 'loginPasskeyBtn',
            password: 'loginPassword',
            otp: 'loginOtp'
        }[step];
        const focusEl = focusId ? document.getElementById(focusId) : null;
        if (focusEl) {
            try {
                focusEl.focus();
            } catch (_) {
                /* focusing a not-yet-painted element can throw; ignore */
            }
        }
    }

    // Reset the login form back to the first (email) step. Called whenever the
    // login view is (re)shown so it never reappears mid-flow.
    function resetLoginSteps() {
        const emailInput = document.getElementById('loginEmail');
        if (emailInput) emailInput.value = '';
        const hint = document.getElementById('loginPasswordHint');
        if (hint) {
            hint.textContent = '';
            hint.classList.add('hidden');
        }
        goLoginStep('email');
    }

    function setPageTitle(title) {
        document.title = title;
    }

    function normalizeSignedInUrl() {
        if (googleOAuthMode || alexaOAuthMode) {
            return;
        }

        if (window.location.pathname !== '/') {
            window.history.replaceState({}, '', '/');
        }
    }

    function isGoogleOauthLinkingIntent() {
        return googleOAuthMode || googleOAuthConsentMode;
    }

    function maybeContinueGoogleOAuthFromCookie() {
        if (!isGoogleOauthLinkingIntent() || googleOAuthConsentMode || googleOAuthRedirectInFlight) {
            return;
        }

        if (hasTriedGoogleOAuthCookieProbe()) {
            return;
        }

        if (!googleOAuthClientId || !googleOAuthRedirectUri) {
            return;
        }

        googleOAuthRedirectInFlight = true;
        markGoogleOAuthCookieProbeTried();
        const continueUrl = new URL('/api/google/home/oauth', window.location.origin);
        continueUrl.searchParams.set('client_id', googleOAuthClientId);
        continueUrl.searchParams.set('redirect_uri', googleOAuthRedirectUri);
        continueUrl.searchParams.set('response_type', 'code');
        continueUrl.searchParams.set('state', googleOAuthState);
        continueUrl.searchParams.set('from_cookie', '1');

        window.location.assign(continueUrl.toString());
    }

    function hasSubdomain(userData) {
        return Boolean(userData && typeof userData.subdomain === 'string' && userData.subdomain.trim());
    }

    function setHeaderState(userData) {
        const isSignedIn = Boolean(userData);

        if (guestNavActions) {
            guestNavActions.classList.toggle('hidden', isSignedIn);
        }

        if (signedInNavActions) {
            signedInNavActions.classList.toggle('hidden', !isSignedIn);
        }
    }

    async function clearSessionAndShowAuth() {
        stopAccountAutoRefresh();
        stopGoogleEntitiesAutoRefresh();
        googleOAuthRedirectInFlight = false;
        localStorage.removeItem('apex_user');
        // Re-arm the passkey nudges for the next login in this same tab. Clear
        // BOTH the persisted flags and the in-memory latches — login does not
        // reload the page, so without resetting the latches the banner +
        // interstitial would stay suppressed after a same-tab logout->login.
        try {
            sessionStorage.removeItem('apex_passkey_prompt_dismissed');
            sessionStorage.removeItem('apex_passkey_interstitial_seen');
        } catch (_e) {
            // ignore
        }
        passkeyPromptDismissed = false;
        passkeyInterstitialSeen = false;
        passkeyBannerShownThisSession = false;
        setHeaderState(null);

        try {
            await fetch('/api/account/logout', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
        } catch (_error) {
            // Ignore logout network errors, local state is already cleared.
        }

        if (pageMode === 'signup') {
            showSignupView();
        } else {
            showLoginView();
        }
    }

    function showLoginView() {
        stopAccountAutoRefresh();
        stopGoogleEntitiesAutoRefresh();
        googleOAuthRedirectInFlight = false;
        manageViewActive = false;
        if (manageAccountView) manageAccountView.classList.add('hidden');
        if (signupForm) signupForm.classList.add('hidden');
        if (loginForm) loginForm.classList.remove('hidden');
        if (forgotPasswordForm) forgotPasswordForm.classList.add('hidden');
        if (dashboard) dashboard.classList.add('hidden');
        resetLoginSteps();
        setHeaderState(null);
        setPageTitle(loginTitle);
        accountTitle.textContent = 'Sign in to your Cloud account';
        headerSubtitle.textContent = 'Manage access, billing and your cloud address from one place.';
        hideAlert();

        if (isGoogleOauthLinkingIntent() && !googleOAuthConsentMode) {
            window.setTimeout(() => {
                maybeContinueGoogleOAuthFromCookie();
            }, 80);
        }

        if (googleOAuthConsentMode) {
            showAlert('Sign in to review and approve Google Assistant access.', false);
        }
    }

    function showSignupView() {
        stopAccountAutoRefresh();
        stopGoogleEntitiesAutoRefresh();
        googleOAuthRedirectInFlight = false;
        manageViewActive = false;
        if (manageAccountView) manageAccountView.classList.add('hidden');
        if (loginForm) loginForm.classList.add('hidden');
        if (signupForm) signupForm.classList.remove('hidden');
        if (dashboard) dashboard.classList.add('hidden');
        setHeaderState(null);
        setPageTitle(signupTitle);
        accountTitle.textContent = 'Create your Cloud account';
        headerSubtitle.textContent = 'Create your account, reserve your cloud address and complete billing.';
        hideAlert();

        if (isGoogleOauthLinkingIntent() && !googleOAuthConsentMode) {
            window.setTimeout(() => {
                maybeContinueGoogleOAuthFromCookie();
            }, 80);
        }

        if (googleOAuthConsentMode) {
            showAlert('Sign in to review and approve Google Assistant access.', false);
        }
    }

    function getStatusMessage(userData) {
        if (userData.status === 'payment_pending') {
            if (lastTrialCheckForEmail === userData.email && lastTrialEligibility === false) {
                return 'Billing is pending. The free trial has already been used for this account — pick a plan to subscribe and restore access.';
            }
            return 'Billing is pending. Remote access remains unavailable until the account is enabled.';
        }
        if (userData.status === 'trial') {
            return userData.trial_ends_at
                ? `Access is active for this account until ${new Date(userData.trial_ends_at).toLocaleDateString()}.`
                : 'Access is active for this account.';
        }
        if (userData.status === 'active') {
            // Admin-granted active access — no Razorpay sub, no expiry. Render
            // a distinct line so this user understands their access is open-
            // ended and not tied to a billing cycle.
            if (userData.admin_granted_access) {
                return 'Remote access is active. This account was activated by an administrator and has no expiry.';
            }
            const periodEndIso = userData.current_period_end;
            const periodEndDate = periodEndIso
                ? new Date(periodEndIso).toLocaleDateString()
                : null;
            // If the Razorpay sub is already in a terminal state (user cancelled
            // at cycle end), local status is still 'active' until the period
            // closes. Surface that explicitly so the user understands what
            // "active" means here.
            const rzpStatus = String(userData.razorpay_subscription_status || '').toLowerCase();
            const cancelAtPeriodEnd = ['cancelled', 'completed'].includes(rzpStatus);
            if (cancelAtPeriodEnd && periodEndDate) {
                return `Subscription cancelled. Access continues until ${periodEndDate}, after which no further charges will be made.`;
            }
            if (periodEndDate) {
                return `Remote access is active. Subscription renews on ${periodEndDate}.`;
            }
            return 'Remote access is active and this account is ready to use.';
        }
        if (userData.status === 'expired') {
            return 'Service has expired. Renew billing to restore remote access.';
        }
        if (userData.status === 'suspended') {
            return 'Service is suspended. Contact support or update billing to restore access.';
        }
        return 'Unknown account state.';
    }

    function getStatusTone(status) {
        if (status === 'payment_pending') {
            return {
                card: 'status-card status-card--pending',
                badge: 'status-badge status-badge--pending',
                label: 'pending',
                title: 'Activation pending'
            };
        }

        if (status === 'trial' || status === 'active') {
            return {
                card: 'status-card status-card--active',
                badge: 'status-badge status-badge--active',
                label: 'active',
                title: 'Remote access is live'
            };
        }

        return {
            card: 'status-card status-card--attention',
            badge: 'status-badge status-badge--attention',
            label: status === 'expired' ? 'expired' : 'suspended',
            title: 'Attention required'
        };
    }

    function buildAccountRenderFingerprint(userData) {
        if (!userData || typeof userData !== 'object') {
            return '';
        }

        return [
            userData.status || '',
            userData.subdomain || '',
            userData.domain || '',
            userData.access_token || '',
            userData.email_verified ? '1' : '0',
            userData.google_home_enabled ? '1' : '0',
            userData.google_home_linked ? '1' : '0',
            userData.alexa_enabled ? '1' : '0',
            userData.alexa_linked ? '1' : '0',
            userData.trial_ends_at || '',
            userData.trial_approved_at || '',
            userData.activated_at || '',
            userData.payment_pending ? '1' : '0'
        ].join('|');
    }

    function escapeHtml(value) {
        return String(value || '')
            .replaceAll('&', '&amp;')
            .replaceAll('<', '&lt;')
            .replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;')
            .replaceAll("'", '&#39;');
    }

    function isWellFormedPortalToken(token) {
        if (typeof token !== 'string') {
            return false;
        }

        const normalized = token.trim();
        if (!normalized.includes('.')) {
            return false;
        }

        const parts = normalized.split('.');
        if (parts.length !== 2) {
            return false;
        }

        return parts[0].length > 10 && parts[1].length >= 32;
    }

    function parseGoogleOauthChallenge(encodedChallenge) {
        if (!encodedChallenge) {
            return null;
        }

        try {
            const decoded = JSON.parse(decodeURIComponent(encodedChallenge));
            const clientId = String(decoded?.client_id || '').trim();
            const redirectUri = String(decoded?.redirect_uri || '').trim();
            const state = String(decoded?.state || '').trim();
            const portalToken = String(decoded?.portal_session_token || '').trim();
            if (!clientId || !redirectUri || !isWellFormedPortalToken(portalToken)) {
                return null;
            }

            return {
                client_id: clientId,
                redirect_uri: redirectUri,
                state,
                portal_session_token: portalToken
            };
        } catch (_error) {
            return null;
        }
    }

    // ── Shared entity card: domain filter + HA-device grouping ──────────
    // Both the Google and Alexa integration cards render through this one
    // subsystem. Each entity carries `entity_type` (its HA domain) and a
    // `state` object; the add-on now also stuffs `_ha_device_id` /
    // `_ha_device_name` into state (see lib/{google-home,alexa}/core.js), which
    // lets us group entities by their Home Assistant device. State is held in
    // JS (not the DOM) so it survives the 15s silent re-render: `selectedDomain`
    // is the active domain filter and `expanded` is the set of open device
    // groups (empty = all collapsed, matching "show the device first, expand on
    // click").
    const ENTITY_DOMAIN_LABELS = {
        light: 'Light',
        switch: 'Switch',
        outlet: 'Outlet',
        fan: 'Fan',
        cover: 'Cover',
        lock: 'Lock',
        climate: 'Climate',
        media_player: 'Media player',
        sensor: 'Sensor',
        binary_sensor: 'Binary sensor',
        scene: 'Scene',
        script: 'Script',
        button: 'Button',
        vacuum: 'Vacuum',
        humidifier: 'Humidifier',
        alarm_control_panel: 'Alarm panel',
        water_heater: 'Water heater',
        automation: 'Automation',
        group: 'Group',
        input_boolean: 'Input boolean',
        input_button: 'Input button',
        input_select: 'Input select',
        select: 'Select',
        valve: 'Valve',
        lawn_mower: 'Lawn mower',
        event: 'Event',
        camera: 'Camera'
    };
    const ENTITY_OTHER_GROUP_KEY = '__ungrouped__';

    // Container/filter/bulk are referenced by id (resolved lazily) so this
    // config can be declared before the Alexa elements exist in source order.
    const entityCards = {
        google: {
            containerId: 'googleHomeEntities',
            filterId: 'googleDomainFilter',
            bulkId: 'googleEntitiesBulkToggle',
            toggleClass: 'google-entity-toggle',
            linkedKey: 'google_home_linked',
            linkMsg: 'Link Apex Connect+ in Google Home app first.',
            exposeBase: '/api/account/google-home/entities',
            bulkUrl: '/api/account/google-home/entities/expose-bulk',
            cache: [],
            selectedDomain: 'all',
            expanded: new Set(),
            wired: false
        },
        alexa: {
            containerId: 'alexaHomeEntities',
            filterId: 'alexaDomainFilter',
            bulkId: 'alexaEntitiesBulkToggle',
            toggleClass: 'alexa-entity-toggle',
            linkedKey: 'alexa_linked',
            linkMsg: 'Link the Apex Oasis skill in the Alexa app first.',
            exposeBase: '/api/account/alexa/entities',
            bulkUrl: '/api/account/alexa/entities/expose-bulk',
            cache: [],
            selectedDomain: 'all',
            expanded: new Set(),
            wired: false
        }
    };

    function getVendorCfg(vendor) {
        return entityCards[vendor];
    }

    // Pluralize a domain label using the common English rules so the filter
    // reads naturally: "Switch" → "Switches", "Cover" → "Covers". Operates on
    // the trailing characters, so multi-word labels pluralize their last word
    // ("Media player" → "Media players").
    function pluralizeLabel(word) {
        if (/(?:s|x|z|ch|sh)$/i.test(word)) return `${word}es`;
        if (/[^aeiou]y$/i.test(word)) return `${word.slice(0, -1)}ies`;
        return `${word}s`;
    }

    function friendlyDomainLabel(type) {
        const base =
            ENTITY_DOMAIN_LABELS[type] ||
            (type ? type.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()) : 'Other');
        return pluralizeLabel(base);
    }

    function entityDomainOf(entity) {
        return entity.entity_type || 'switch';
    }

    function entityGroupKey(entity) {
        const st = entity.state || {};
        if (st._ha_device_id) return `id:${st._ha_device_id}`;
        if (st._ha_device_name) return `name:${st._ha_device_name}`;
        return ENTITY_OTHER_GROUP_KEY;
    }

    function entityGroupName(entity) {
        const st = entity.state || {};
        if (st._ha_device_name) return st._ha_device_name;
        if (st._ha_device_id) return 'Unnamed device';
        return 'Internal (APEX Native)';
    }

    function getFilteredEntities(vendor) {
        const cfg = getVendorCfg(vendor);
        if (cfg.selectedDomain === 'all') return cfg.cache.slice();
        return cfg.cache.filter((e) => entityDomainOf(e) === cfg.selectedDomain);
    }

    function groupEntities(list) {
        const map = new Map();
        list.forEach((e) => {
            const key = entityGroupKey(e);
            if (!map.has(key)) {
                map.set(key, { key, name: entityGroupName(e), entities: [] });
            }
            map.get(key).entities.push(e);
        });
        const groups = Array.from(map.values());
        groups.sort((a, b) => {
            if (a.key === ENTITY_OTHER_GROUP_KEY) return 1;
            if (b.key === ENTITY_OTHER_GROUP_KEY) return -1;
            return a.name.localeCompare(b.name);
        });
        return groups;
    }

    function entityRowHtml(vendor, entity) {
        const cfg = getVendorCfg(vendor);
        return `
                <label class="google-entity-row">
                    <input type="checkbox" class="${cfg.toggleClass}" data-entity-id="${escapeHtml(entity.entity_id)}" ${entity.exposed ? 'checked' : ''}>
                    <span class="google-entity-name">${escapeHtml(entity.display_name || entity.entity_id)}</span>
                    <span class="google-entity-meta">${escapeHtml(entity.entity_type || 'switch')} | ${entity.online ? 'online' : 'offline'}</span>
                </label>`;
    }

    function deviceGroupHtml(vendor, group) {
        const cfg = getVendorCfg(vendor);
        const open = cfg.expanded.has(group.key);
        const total = group.entities.length;
        const exposed = group.entities.filter((e) => e.exposed).length;
        const allExposed = total > 0 && exposed === total;
        return `
                <div class="device-group ${open ? 'is-open' : ''}" data-group-key="${escapeHtml(group.key)}">
                    <div class="device-group__header" role="button" tabindex="0" aria-expanded="${open ? 'true' : 'false'}">
                        <input type="checkbox" class="device-group__checkbox" ${allExposed ? 'checked' : ''} aria-label="Expose all entities for ${escapeHtml(group.name)}">
                        <span class="device-group__name">${escapeHtml(group.name)}</span>
                        <span class="device-group__count">${exposed}/${total}</span>
                        <span class="device-group__chevron" aria-hidden="true">▾</span>
                    </div>
                    <div class="device-group__entities">
                        ${group.entities.map((e) => entityRowHtml(vendor, e)).join('')}
                    </div>
                </div>`;
    }

    function getVisibleToggles(vendor) {
        const cfg = getVendorCfg(vendor);
        const container = document.getElementById(cfg.containerId);
        if (!container) return [];
        return Array.from(container.querySelectorAll(`.${cfg.toggleClass}`));
    }

    function updateEntityBulkLabel(vendor) {
        const cfg = getVendorCfg(vendor);
        const bulk = document.getElementById(cfg.bulkId);
        if (!bulk) return;
        const toggles = getVisibleToggles(vendor);
        if (toggles.length === 0) {
            bulk.classList.add('hidden');
            return;
        }
        bulk.classList.remove('hidden');
        // "Hide all" only when every entity in the current (filtered) view is
        // already exposed; otherwise "Expose all" (covers mixed + all-hidden).
        const allExposed = toggles.every((t) => t.checked);
        bulk.dataset.nextExpose = allExposed ? '0' : '1';
        bulk.textContent = allExposed ? 'Hide all' : 'Expose all';
    }

    // Recompute each device group's checkbox (checked / indeterminate) and
    // count from the live DOM toggles, plus the bulk button label — without
    // rebuilding innerHTML (avoids the scroll jump a full re-render causes).
    function refreshEntityGroupChrome(vendor) {
        const cfg = getVendorCfg(vendor);
        const container = document.getElementById(cfg.containerId);
        if (container) {
            container.querySelectorAll('.device-group').forEach((groupEl) => {
                const rows = groupEl.querySelectorAll(`.${cfg.toggleClass}`);
                const total = rows.length;
                let exposed = 0;
                rows.forEach((r) => {
                    if (r.checked) exposed += 1;
                });
                const cb = groupEl.querySelector('.device-group__checkbox');
                if (cb) {
                    cb.checked = total > 0 && exposed === total;
                    cb.indeterminate = exposed > 0 && exposed < total;
                }
                const count = groupEl.querySelector('.device-group__count');
                if (count) count.textContent = `${exposed}/${total}`;
            });
        }
        updateEntityBulkLabel(vendor);
    }

    // Keep the silent-poll baseline in lockstep with our optimistic in-memory
    // cache after a local expose/hide. Without this, the next 15s poll sees the
    // server state differ from a stale fingerprint and does a full rebuild —
    // undoing the in-place update and jumping scroll to the top.
    function resyncEntitiesFingerprint(vendor) {
        if (vendor === 'google') {
            googleEntitiesLastFingerprint = buildGoogleEntitiesFingerprint(entityCards.google.cache);
        } else if (vendor === 'alexa') {
            alexaEntitiesLastFingerprint = buildGoogleEntitiesFingerprint(entityCards.alexa.cache);
        }
    }

    // Reconcile every visible toggle to cfg.cache, refresh group chrome, and
    // resync the fingerprint — all without rebuilding innerHTML, so a device-
    // group or global bulk action keeps the user's scroll position and the set
    // of expanded groups intact (the DOM structure is unchanged by exposure-
    // only edits; only checkbox states move).
    function syncEntityCardInPlace(vendor) {
        const cfg = getVendorCfg(vendor);
        const container = document.getElementById(cfg.containerId);
        if (container) {
            const exposedById = new Map(cfg.cache.map((e) => [e.entity_id, Boolean(e.exposed)]));
            container.querySelectorAll(`.${cfg.toggleClass}`).forEach((box) => {
                if (exposedById.has(box.dataset.entityId)) {
                    box.checked = exposedById.get(box.dataset.entityId);
                }
            });
        }
        refreshEntityGroupChrome(vendor);
        resyncEntitiesFingerprint(vendor);
    }

    function populateDomainFilter(vendor) {
        const cfg = getVendorCfg(vendor);
        const sel = document.getElementById(cfg.filterId);
        if (!sel) return;
        const domains = Array.from(new Set(cfg.cache.map(entityDomainOf))).sort();
        // A single domain (or none) isn't worth filtering — hide the control.
        if (domains.length <= 1) {
            sel.classList.add('hidden');
            cfg.selectedDomain = 'all';
        } else {
            sel.classList.remove('hidden');
        }
        if (cfg.selectedDomain !== 'all' && !domains.includes(cfg.selectedDomain)) {
            cfg.selectedDomain = 'all';
        }
        const opts = ['<option value="all">All domains</option>'].concat(
            domains.map((d) => `<option value="${escapeHtml(d)}">${escapeHtml(friendlyDomainLabel(d))}</option>`)
        );
        sel.innerHTML = opts.join('');
        sel.value = cfg.selectedDomain;
    }

    function renderEntityCard(vendor) {
        const cfg = getVendorCfg(vendor);
        const container = document.getElementById(cfg.containerId);
        if (!container) return;

        populateDomainFilter(vendor);

        if (cfg.cache.length === 0) {
            container.innerHTML =
                '<p class="detail-copy">No entities synced yet. Keep the addon online and wait for the next sync.</p>';
            const bulk = document.getElementById(cfg.bulkId);
            if (bulk) bulk.classList.add('hidden');
            return;
        }

        const filtered = getFilteredEntities(vendor);
        if (filtered.length === 0) {
            container.innerHTML = '<p class="detail-copy">No entities match this filter.</p>';
            updateEntityBulkLabel(vendor);
            return;
        }

        const groups = groupEntities(filtered);
        const hasRealDevices = groups.some((g) => g.key !== ENTITY_OTHER_GROUP_KEY);
        if (!hasRealDevices) {
            // No HA device metadata yet (e.g. add-on not redeployed) — fall back
            // to a flat list so nothing hides behind a single "Other" group.
            container.innerHTML = filtered.map((e) => entityRowHtml(vendor, e)).join('');
        } else {
            container.innerHTML = groups.map((g) => deviceGroupHtml(vendor, g)).join('');
        }
        refreshEntityGroupChrome(vendor);
    }

    function hideEntityCardControls(vendor) {
        const cfg = getVendorCfg(vendor);
        const bulk = document.getElementById(cfg.bulkId);
        if (bulk) bulk.classList.add('hidden');
        const filt = document.getElementById(cfg.filterId);
        if (filt) filt.classList.add('hidden');
    }

    async function onEntityToggle(vendor, input) {
        const cfg = getVendorCfg(vendor);
        const userData = JSON.parse(localStorage.getItem('apex_user') || 'null');
        if (!userData?.portal_session_token) {
            showAlert('Please log in again to continue.');
            input.checked = !input.checked;
            return;
        }
        if (!userData[cfg.linkedKey]) {
            showAlert(cfg.linkMsg);
            input.checked = false;
            return;
        }
        const entityId = input.dataset.entityId;
        const exposed = input.checked;
        input.disabled = true;
        try {
            const res = await fetch(`${cfg.exposeBase}/${encodeURIComponent(entityId)}/expose`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ portal_session_token: userData.portal_session_token, exposed })
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error || 'Unable to update entity exposure');
            const item = cfg.cache.find((e) => e.entity_id === entityId);
            if (item) item.exposed = exposed;
            if (data.message) showAlert(data.message, false);
        } catch (error) {
            input.checked = !exposed;
            showAlert(error.message);
        } finally {
            input.disabled = false;
            // In-place chrome update + fingerprint resync keeps scroll position
            // (the list isn't rebuilt) and stops the 15s poll from undoing this.
            refreshEntityGroupChrome(vendor);
            resyncEntitiesFingerprint(vendor);
        }
    }

    // Shared expose/hide for a set of entities via the batched server endpoint.
    // The server rejects any single request carrying more than BULK_EXPOSE_MAX_ITEMS
    // (200) entities, so when a select-all exceeds that we split into sequential
    // sub-requests of <=200 here and aggregate the results. (The server still batches
    // each accepted request internally in groups of 10 — this only keeps us under the
    // per-request cap.)
    const BULK_EXPOSE_CLIENT_CHUNK = 200;

    async function applyEntityBulk(vendor, targets, expose, triggerBtn) {
        const cfg = getVendorCfg(vendor);
        const userData = JSON.parse(localStorage.getItem('apex_user') || 'null');
        if (!userData?.portal_session_token) {
            showAlert('Please log in again to continue.');
            syncEntityCardInPlace(vendor);
            return;
        }
        const updates = targets.map((e) => ({ entity_id: e.entity_id, exposed: expose }));
        const originalLabel = triggerBtn ? triggerBtn.textContent : '';
        if (triggerBtn) {
            triggerBtn.disabled = true;
            triggerBtn.textContent = expose ? 'Exposing...' : 'Hiding...';
        }
        try {
            // Split into <=200-item chunks so each request stays under the server cap.
            const chunks = [];
            for (let i = 0; i < updates.length; i += BULK_EXPOSE_CLIENT_CHUNK) {
                chunks.push(updates.slice(i, i + BULK_EXPOSE_CLIENT_CHUNK));
            }
            let failedCount = 0;
            for (const chunk of chunks) {
                const res = await fetch(cfg.bulkUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ portal_session_token: userData.portal_session_token, updates: chunk })
                });
                const data = await res.json().catch(() => ({}));
                if (!res.ok) throw new Error(data.error || 'Unable to update entities');
                failedCount += Array.isArray(data.results) ? data.results.filter((r) => !r.ok).length : 0;
            }
            const ids = new Set(targets.map((t) => t.entity_id));
            cfg.cache.forEach((e) => {
                if (ids.has(e.entity_id)) e.exposed = expose;
            });
            // Exposure-only change: the rendered groups/rows are unchanged, so
            // update checkboxes + chrome in place (no rebuild → no scroll jump,
            // expanded groups stay open).
            syncEntityCardInPlace(vendor);
            if (!failedCount) {
                showAlert(expose ? 'Entities exposed.' : 'Entities hidden.', false);
            } else {
                showAlert(`${updates.length - failedCount} updated, ${failedCount} failed. Please retry the failures.`);
            }
        } catch (error) {
            showAlert(error.message);
            syncEntityCardInPlace(vendor);
        } finally {
            if (triggerBtn) {
                triggerBtn.disabled = false;
                triggerBtn.textContent = originalLabel;
            }
        }
    }

    async function onEntityBulkToggle(vendor) {
        const cfg = getVendorCfg(vendor);
        const userData = JSON.parse(localStorage.getItem('apex_user') || 'null');
        if (!userData?.portal_session_token) {
            showAlert('Please log in again to continue.');
            return;
        }
        if (!userData[cfg.linkedKey]) {
            showAlert(cfg.linkMsg);
            return;
        }
        const bulk = document.getElementById(cfg.bulkId);
        const expose = bulk?.dataset.nextExpose === '1';
        // Act only on the currently-filtered set, and only on entities whose
        // state actually differs from the target (avoids pointless writes).
        const targets = getFilteredEntities(vendor).filter((e) => Boolean(e.exposed) !== expose);
        if (targets.length === 0) {
            updateEntityBulkLabel(vendor);
            return;
        }
        await applyEntityBulk(vendor, targets, expose, bulk);
    }

    async function onDeviceGroupToggle(vendor, groupCheckbox, groupKey) {
        const cfg = getVendorCfg(vendor);
        const userData = JSON.parse(localStorage.getItem('apex_user') || 'null');
        if (!userData?.portal_session_token) {
            showAlert('Please log in again to continue.');
            groupCheckbox.checked = !groupCheckbox.checked;
            return;
        }
        if (!userData[cfg.linkedKey]) {
            showAlert(cfg.linkMsg);
            groupCheckbox.checked = !groupCheckbox.checked;
            return;
        }
        const expose = groupCheckbox.checked;
        groupCheckbox.indeterminate = false;
        // Respect the active domain filter: a device's checkbox acts on the
        // entities currently shown for it (the filtered subset).
        const targets = getFilteredEntities(vendor).filter(
            (e) => entityGroupKey(e) === groupKey && Boolean(e.exposed) !== expose
        );
        if (targets.length === 0) return;
        await applyEntityBulk(vendor, targets, expose, null);
    }

    // Delegated listeners, attached once per card, survive innerHTML swaps.
    function wireEntityCard(vendor) {
        const cfg = getVendorCfg(vendor);
        const container = document.getElementById(cfg.containerId);
        if (container && !cfg.wired) {
            cfg.wired = true;
            container.addEventListener('change', (event) => {
                const entityToggle = event.target.closest(`.${cfg.toggleClass}`);
                if (entityToggle) {
                    void onEntityToggle(vendor, entityToggle);
                    return;
                }
                const groupCb = event.target.closest('.device-group__checkbox');
                if (groupCb) {
                    const wrap = groupCb.closest('.device-group');
                    void onDeviceGroupToggle(vendor, groupCb, wrap?.getAttribute('data-group-key'));
                }
            });
            const toggleHeader = (header) => {
                const wrap = header.closest('.device-group');
                const key = wrap?.getAttribute('data-group-key');
                if (!wrap || !key) return;
                if (cfg.expanded.has(key)) cfg.expanded.delete(key);
                else cfg.expanded.add(key);
                wrap.classList.toggle('is-open');
                header.setAttribute('aria-expanded', cfg.expanded.has(key) ? 'true' : 'false');
            };
            container.addEventListener('click', (event) => {
                if (event.target.closest('.device-group__checkbox')) return;
                const header = event.target.closest('.device-group__header');
                if (header) toggleHeader(header);
            });
            container.addEventListener('keydown', (event) => {
                if (event.key !== 'Enter' && event.key !== ' ') return;
                if (event.target.closest('.device-group__checkbox')) return;
                const header = event.target.closest('.device-group__header');
                if (header) {
                    event.preventDefault();
                    toggleHeader(header);
                }
            });
        }

        const filterEl = document.getElementById(cfg.filterId);
        if (filterEl && !filterEl.dataset.wired) {
            filterEl.dataset.wired = '1';
            filterEl.addEventListener('change', () => {
                cfg.selectedDomain = filterEl.value || 'all';
                renderEntityCard(vendor);
            });
        }

        const bulkBtn = document.getElementById(cfg.bulkId);
        if (bulkBtn && !bulkBtn.dataset.wired) {
            bulkBtn.dataset.wired = '1';
            bulkBtn.addEventListener('click', () => {
                void onEntityBulkToggle(vendor);
            });
        }
    }

    async function loadGoogleHomeEntities(userData) {
        if (!googleHomeEntities || !userData?.portal_session_token) {
            return;
        }

        if (!userData.google_home_enabled) {
            googleHomeEntities.innerHTML = '<p class="detail-copy">Enable Google Home to manage exposed entities.</p>';
            hideEntityCardControls('google');
            return;
        }

        wireEntityCard('google');

        // Only show the "Loading entities..." placeholder on the very first
        // load (or after a reset). On subsequent reloads triggered by the
        // silent 15s poll, wipe-and-replace causes a visible flash; instead
        // we fetch quietly and only swap the markup once the new list is
        // ready (or fall back to the placeholder if there's no prior state).
        const hasExistingList = googleEntitiesLastFingerprint !== null;
        if (!hasExistingList) {
            googleHomeEntities.innerHTML = '<p class="detail-copy">Loading entities...</p>';
        }

        try {
            const res = await fetch('/api/account/google-home/entities', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ portal_session_token: userData.portal_session_token })
            });
            const data = await res.json();
            if (!res.ok) {
                const message = data.error || 'Unable to load Google entities';
                throw new Error(message);
            }

            const entities = Array.isArray(data.entities) ? data.entities : [];
            googleEntitiesLastFingerprint = buildGoogleEntitiesFingerprint(entities);
            entityCards.google.cache = entities;
            // Filter + device-group render. selectedDomain and the set of
            // expanded device groups live in entityCards.google, so they
            // persist across the 15s silent re-render.
            renderEntityCard('google');
        } catch (error) {
            googleHomeEntities.innerHTML = `<p class="detail-copy">${escapeHtml(error.message || 'Unable to load Google Home entities right now.')}</p>`;
        }
    }

    // ── Amazon Alexa integration (mirror of the Google Home card) ───────
    const alexaHomeCard = document.getElementById('alexaHomeCard');
    const alexaHomeStatus = document.getElementById('alexaHomeStatus');
    const alexaHomeEntities = document.getElementById('alexaHomeEntities');
    const alexaUnlinkBtn = document.getElementById('alexaUnlinkBtn');

    function renderAlexaCard(userData, accessEnabled) {
        if (!alexaHomeCard) {
            return;
        }
        const linked = Boolean(userData.alexa_linked);
        const show = accessEnabled && linked;
        alexaHomeCard.classList.toggle('hidden', !show);
        if (show) {
            if (alexaHomeStatus) alexaHomeStatus.textContent = 'Linked to Alexa';
            if (alexaUnlinkBtn) {
                alexaUnlinkBtn.classList.remove('hidden');
                wireAlexaUnlink(userData);
            }
            void loadAlexaEntities(userData);
        } else {
            if (alexaHomeStatus) {
                alexaHomeStatus.textContent = accessEnabled
                    ? 'Enable the Apex Oasis skill in the Alexa app to manage exposed devices.'
                    : 'Available after account activation.';
            }
            if (alexaHomeEntities) {
                alexaHomeEntities.innerHTML =
                    '<p class="detail-copy">Link the Apex Oasis skill in the Alexa app to manage exposed devices.</p>';
            }
            alexaEntitiesLastFingerprint = null;
            entityCards.alexa.cache = [];
            hideEntityCardControls('alexa');
            if (alexaUnlinkBtn) alexaUnlinkBtn.classList.add('hidden');
        }
    }

    // Vendor-specific copy for the shared unlink confirmation modal.
    const UNLINK_CONFIG = {
        google: {
            endpoint: '/api/account/google-home/enable',
            title: 'Unlink Google',
            body: 'This unlinks Google Home from this account. Your exposed devices are removed from the Google Home app automatically. The "Apex Connect+" link entry stays in the Google Home app until you remove it there yourself.',
            confirmLabel: 'Unlink Google',
            error: 'Unable to unlink Google',
            success: 'Google unlinked. Your exposed devices are removed from the Google Home app automatically; you can remove the Apex Connect+ link entry there whenever you like.'
        },
        alexa: {
            endpoint: '/api/account/alexa/enable',
            title: 'Unlink Alexa',
            body: 'Unlink here while still linked and we remove your devices from the Alexa app and disable the Apex Oasis skill for your account. If Alexa still shows the skill or prompts you to relink, open the Alexa app and disable the "Apex Oasis" skill there to finish. Note: if you disable the skill in the Alexa app first instead, Alexa keeps the (now unresponsive) device tiles and you will need to remove them manually.',
            confirmLabel: 'Unlink Alexa',
            error: 'Unable to unlink Alexa',
            success: 'Alexa unlinked. Your devices stop responding right away and we ask Alexa to remove them and disable the skill. If you still see a relink prompt, disable the "Apex Oasis" skill in the Alexa app to finish.'
        }
    };

    function wireGoogleUnlink(userData) {
        if (!googleUnlinkBtn) return;
        googleUnlinkBtn.onclick = () => openUnlinkConfirm('google', userData, googleUnlinkBtn);
    }

    function wireAlexaUnlink(userData) {
        if (!alexaUnlinkBtn) return;
        alexaUnlinkBtn.onclick = () => openUnlinkConfirm('alexa', userData, alexaUnlinkBtn);
    }

    async function performUnlink(vendor, userData, triggerBtn) {
        const cfg = UNLINK_CONFIG[vendor];
        if (!cfg || !userData?.portal_session_token) return;
        try {
            const res = await fetch(cfg.endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ portal_session_token: userData.portal_session_token, enabled: false })
            });
            const data = await res.json();
            if (!res.ok) {
                throw new Error(data.error || cfg.error);
            }
            // Server returns a fresh portal session + cleared link flags.
            const merged = {
                ...(data.data || {}),
                portal_session_token: data.data?.portal_session_token || userData.portal_session_token
            };
            localStorage.setItem('apex_user', JSON.stringify(merged));
            renderDashboard(merged, { scroll: false });
            // The Alexa unlink is GATED: if the DeleteReport to Amazon didn't land in
            // one go (Amazon's gateway intermittently 500s on large device sets), the
            // server keeps the link and reports tiles_cleared:false — but it ALSO retries
            // the removal in the background until it lands. So we tell the user it's
            // finishing in the background (calm, non-error) rather than showing a failure
            // that makes them click Unlink over and over.
            if (vendor === 'alexa' && data.tiles_cleared === false) {
                showAlert('Unlinking Alexa — this is finishing in the background and your devices will be removed shortly. No need to click again.', false);
            } else {
                showAlert(cfg.success, false);
            }
        } catch (error) {
            showAlert(error.message || `${cfg.error} right now.`);
        } finally {
            if (triggerBtn) triggerBtn.disabled = false;
        }
    }

    // ── Shared unlink confirmation modal ────────────────────────────────
    const unlinkConfirmModal = document.getElementById('unlinkConfirmModal');
    const unlinkModalTitle = document.getElementById('unlinkModalTitle');
    const unlinkModalBody = document.getElementById('unlinkModalBody');
    const unlinkModalConfirmBtn = document.getElementById('unlinkModalConfirmBtn');
    const unlinkModalClose = document.getElementById('unlinkModalClose');
    let pendingUnlink = null; // { vendor, userData, triggerBtn }

    function openUnlinkConfirm(vendor, userData, triggerBtn) {
        const cfg = UNLINK_CONFIG[vendor];
        if (!cfg || !unlinkConfirmModal || !userData?.portal_session_token) return;
        pendingUnlink = { vendor, userData, triggerBtn };
        if (unlinkModalTitle) unlinkModalTitle.textContent = cfg.title;
        if (unlinkModalBody) unlinkModalBody.textContent = cfg.body;
        if (unlinkModalConfirmBtn) {
            unlinkModalConfirmBtn.textContent = cfg.confirmLabel;
            unlinkModalConfirmBtn.disabled = false;
        }
        unlinkConfirmModal.classList.remove('hidden');
    }

    function closeUnlinkConfirm() {
        if (!unlinkConfirmModal) return;
        unlinkConfirmModal.classList.add('hidden');
        pendingUnlink = null;
    }

    if (unlinkConfirmModal) {
        unlinkConfirmModal.addEventListener('click', (event) => {
            if (event.target.closest('[data-close-unlink-modal]')) {
                closeUnlinkConfirm();
            }
        });
    }
    if (unlinkModalClose) {
        unlinkModalClose.addEventListener('click', closeUnlinkConfirm);
    }
    if (unlinkModalConfirmBtn) {
        unlinkModalConfirmBtn.addEventListener('click', async () => {
            if (!pendingUnlink) return;
            const { vendor, userData, triggerBtn } = pendingUnlink;
            if (triggerBtn) triggerBtn.disabled = true;
            unlinkModalConfirmBtn.disabled = true;
            unlinkModalConfirmBtn.textContent = 'Unlinking...';
            closeUnlinkConfirm();
            await performUnlink(vendor, userData, triggerBtn);
        });
    }

    async function loadAlexaEntities(userData) {
        if (!alexaHomeEntities || !userData?.portal_session_token) {
            return;
        }
        wireEntityCard('alexa');
        try {
            const res = await fetch('/api/account/alexa/entities', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ portal_session_token: userData.portal_session_token })
            });
            const data = await res.json();
            if (!res.ok) {
                throw new Error(data.error || 'Unable to load Alexa devices');
            }
            const entities = Array.isArray(data.entities) ? data.entities : [];
            const fingerprint = buildGoogleEntitiesFingerprint(entities);
            // Skip the structural rebuild when nothing changed (the Alexa card
            // reloads on every 5s account tick). This keeps scroll position and
            // expanded device groups intact mid-interaction.
            if (fingerprint === alexaEntitiesLastFingerprint && alexaHomeEntities.querySelector('.google-entity-row')) {
                entityCards.alexa.cache = entities;
                return;
            }
            alexaEntitiesLastFingerprint = fingerprint;
            entityCards.alexa.cache = entities;
            // Filter + device-group render (mirror of the Google card). The
            // active domain filter and expanded device groups persist in
            // entityCards.alexa across reloads.
            renderEntityCard('alexa');
        } catch (error) {
            alexaHomeEntities.innerHTML = `<p class="detail-copy">${escapeHtml(error.message || 'Unable to load Alexa devices right now.')}</p>`;
        }
    }

    // Tracks the last fetched trial eligibility so we don't re-query on every
    // poll tick if nothing changed. null = unknown, true/false = known.
    let lastTrialEligibility = null;
    let lastTrialCheckForEmail = null;

    async function refreshTrialEligibility(userData) {
        const billingCard = document.getElementById('billingCard');
        if (!billingCard || !userData || !userData.portal_session_token) return;

        // Only re-query when the user identity changes or we have no cached
        // result yet. Eligibility doesn't flip mid-session in practice.
        if (lastTrialCheckForEmail === userData.email && lastTrialEligibility !== null) {
            applyTrialEligibility(billingCard, lastTrialEligibility);
            return;
        }

        try {
            const res = await fetch('/api/billing/trial-eligibility', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ portal_session_token: userData.portal_session_token })
            });
            if (!res.ok) return;
            const data = await res.json();
            lastTrialEligibility = Boolean(data.trial_available);
            lastTrialCheckForEmail = userData.email;
            applyTrialEligibility(billingCard, lastTrialEligibility);
            // Refresh the status detail copy so trial-consumed users see the
            // updated "pick a plan" message without waiting for the next poll.
            const statusDetail = document.getElementById('dashStatusDetail');
            if (statusDetail) {
                statusDetail.textContent = getStatusMessage(userData);
            }
        } catch (_ignored) {
            // Network glitches shouldn't break the dashboard — leave UI as-is.
        }
    }

    function applyTrialEligibility(billingCard, trialAvailable) {
        const annualBtn = billingCard.querySelector('[data-plan="annual"]');
        if (!annualBtn) return;
        const trialOnly = annualBtn.querySelectorAll('[data-trial-only]');
        const noTrialOnly = annualBtn.querySelectorAll('[data-no-trial-only]');
        trialOnly.forEach((el) => el.classList.toggle('hidden', !trialAvailable));
        noTrialOnly.forEach((el) => el.classList.toggle('hidden', trialAvailable));
    }

    function renderDashboard(userData, options = {}) {
        if (manageViewActive && !options.fromManageBack) {
            // Don't fight the manage account view: just refresh the cached
            // user data fingerprint so when the user clicks Back we re-render
            // with the latest state, but leave the DOM alone.
            accountRenderFingerprint = buildAccountRenderFingerprint(userData);
            return;
        }
        accountRenderFingerprint = buildAccountRenderFingerprint(userData);
        if (loginForm) loginForm.classList.add('hidden');
        if (signupForm) signupForm.classList.add('hidden');
        if (forgotPasswordForm) forgotPasswordForm.classList.add('hidden');
        dashboard.classList.remove('hidden');
        setHeaderState(userData);
        setPageTitle(dashboardTitle);
        normalizeSignedInUrl();
        accountTitle.textContent = `Cloud account for ${userData.email}`;
        headerSubtitle.textContent = 'Manage access status, billing and cloud address from one place.';

        const emailVerified = Boolean(userData.email_verified);
        const accessEnabled = ['active', 'trial'].includes(userData.status);
        const subdomainConfigured = hasSubdomain(userData);
        const tone = getStatusTone(userData.status);

        // Show/hide email verification card
        if (emailVerificationCard) {
            emailVerificationCard.classList.toggle('hidden', emailVerified);
        }

        updatePasskeyPromptBanner(userData);

        const statusCard = document.getElementById('statusCard');
        const statusBadge = document.getElementById('dashStatus');
        statusCard.className = tone.card;
        statusBadge.className = tone.badge;
        statusBadge.textContent = tone.label;
        document.getElementById('dashStatusTitle').textContent = tone.title;
        document.getElementById('dashStatusDetail').textContent = getStatusMessage(userData);

        if (googleConsentCard) {
            googleConsentCard.classList.add('hidden');
        }

        const billingCard = document.getElementById('billingCard');
        const tokenCard = document.getElementById('tokenCard');
        // Gate subdomain and billing behind email verification
        subdomainCard.classList.toggle('hidden', subdomainConfigured || !emailVerified);
        // Show billing card for any non-active billing state so expired users
        // can re-subscribe and suspended users can restore access. Without this
        // an 'expired' user has no UI path back to the plan picker.
        const needsBilling = ['payment_pending', 'expired', 'suspended'].includes(userData.status);
        const showBillingCard = needsBilling && subdomainConfigured && emailVerified;
        billingCard.classList.toggle('hidden', !showBillingCard);
        tokenCard.classList.toggle('hidden', !accessEnabled);

        // Show/hide "Cancel Subscription" row based on server-reported flag
        const cancelSubSection = document.getElementById('cancelSubscriptionSection');
        if (cancelSubSection) {
            cancelSubSection.classList.toggle('hidden', !userData.has_active_subscription);
        }

        // Reset plan picker to default (annual selected) on every render so
        // a dismissed or failed checkout doesn't leave stale selection state.
        const planOptions = billingCard.querySelectorAll('.plan-option');
        planOptions.forEach((btn) => {
            btn.classList.remove('plan-option--selected');
            btn.setAttribute('aria-pressed', 'false');
        });
        const defaultPlan = billingCard.querySelector('[data-plan="annual"]');
        if (defaultPlan) {
            defaultPlan.classList.add('plan-option--selected');
            defaultPlan.setAttribute('aria-pressed', 'true');
        }

        // When the billing card is visible, check whether this user is still
        // eligible for the 1-year free trial. Users who already consumed a
        // trial (e.g. prior annual subscription whose auto-renewal failed,
        // or deleted-and-resignup with the same email) see the annual plan
        // without the trial badge and will be charged immediately.
        if (showBillingCard) {
            refreshTrialEligibility(userData).catch(() => {});
        }

        if (dashSubdomain) {
            dashSubdomain.value = subdomainConfigured ? userData.subdomain : '';
        }

        const dashTokenEl = document.getElementById('dashToken');
        const dashTokenCopyEl = document.getElementById('dashTokenCopy');
        const issuedToken = userData.access_token || '';
        if (dashTokenEl) {
            // Stash the real token; the box stays masked with a placeholder
            // until the user clicks to copy (which also reveals it). Preserve an
            // already-revealed state across the silent 5s refresh.
            dashTokenEl.dataset.token = issuedToken;
            const alreadyRevealed = dashTokenCopyEl && dashTokenCopyEl.classList.contains('is-revealed');
            if (!issuedToken) {
                dashTokenEl.textContent = 'Issued when service is enabled';
                if (dashTokenCopyEl) {
                    dashTokenCopyEl.classList.remove('is-revealed');
                    dashTokenCopyEl.classList.add('is-empty');
                }
            } else {
                if (dashTokenCopyEl) dashTokenCopyEl.classList.remove('is-empty');
                dashTokenEl.textContent = alreadyRevealed ? issuedToken : 'Click to copy access token';
            }
        }

        if (googleHomeCard) {
            const linked = Boolean(userData.google_home_linked);
            const showGoogleCard = accessEnabled && linked;
            googleHomeCard.classList.toggle('hidden', !showGoogleCard);
            if (showGoogleCard) {
                if (googleHomeStatus) {
                    googleHomeStatus.textContent = 'Linked to Google';
                }
                if (googleUnlinkBtn) {
                    googleUnlinkBtn.classList.remove('hidden');
                    wireGoogleUnlink(userData);
                }

                const nextRefreshKey = getGoogleEntitiesRefreshKey(userData);
                if (googleEntitiesRefreshKey !== nextRefreshKey || googleEntitiesLastFingerprint === null) {
                    void loadGoogleHomeEntities(userData);
                }
                startGoogleEntitiesAutoRefresh(userData);
                void loadSecurityPinStatus(userData);
            } else {
                if (googleHomeStatus) {
                    googleHomeStatus.textContent = accessEnabled
                        ? 'Link Apex Connect+ in Google Home app to manage exposed entities.'
                        : 'Available after account activation.';
                }
                if (googleHomeEntities) {
                    googleHomeEntities.innerHTML = '<p class="detail-copy">Link Apex Connect+ in Google Home app to manage exposed entities.</p>';
                }
                googleEntitiesLastFingerprint = null;
                stopGoogleEntitiesAutoRefresh();
                hideEntityCardControls('google');
                if (googleUnlinkBtn) googleUnlinkBtn.classList.add('hidden');
            }
        } else {
            stopGoogleEntitiesAutoRefresh();
        }

        renderAlexaCard(userData, accessEnabled);

        const dashUrl = document.getElementById('dashUrl');
        const dashUrlLabel = document.getElementById('dashUrlLabel');
        // The address text lives in a child span so it can ellipsis-truncate
        // independently of the trailing open/add icon (the anchor is a flex row).
        const setDashUrlText = (text) => {
            dashUrl.textContent = '';
            const span = document.createElement('span');
            span.className = 'domain-link__text';
            span.textContent = text;
            dashUrl.appendChild(span);
        };
        if (!subdomainConfigured) {
            dashUrlLabel.textContent = 'Cloud Address';
            setDashUrlText('Set your cloud address');
            dashUrl.href = '#';
            dashUrl.removeAttribute('target');
            dashUrl.className = 'domain-link domain-link--setup';
            if (dashUrlHelp) {
                dashUrlHelp.textContent = 'Set your desired cloud address to continue account activation.';
            }
        } else {
            setDashUrlText(`https://${userData.domain}`);
            if (accessEnabled) {
                dashUrlLabel.textContent = 'Live Cloud Address';
                dashUrl.href = `https://${userData.domain}`;
                dashUrl.target = '_blank';
                dashUrl.className = 'domain-link domain-link--live';
                if (dashUrlHelp) {
                    dashUrlHelp.textContent = 'Your cloud address is active and ready to use. Click to open it.';
                }
            } else {
                dashUrlLabel.textContent = 'Reserved Cloud Address';
                dashUrl.href = '#';
                dashUrl.removeAttribute('target');
                dashUrl.className = 'domain-link domain-link--disabled';
                if (dashUrlHelp) {
                    dashUrlHelp.textContent = 'This address becomes available as soon as the account is enabled.';
                }
            }
        }

        const consentHandled = handleGoogleConsentFlow(userData);
        if (consentHandled) {
            return;
        }

        startAccountAutoRefresh();
        void appendGoogleOAuthPortalToken(userData);
        void appendAlexaOAuthPortalToken(userData);
    }

    async function appendAlexaOAuthPortalToken(userData) {
        if (alexaOAuthRedirectInFlight) {
            return;
        }

        if (!alexaOAuthMode) {
            return;
        }

        if (!userData?.portal_session_token) {
            return;
        }

        const portalToken = String(userData.portal_session_token || '');
        if (!isWellFormedPortalToken(portalToken)) {
            showAlert('Session token is invalid. Please log out and sign in again.');
            return;
        }

        if (alexaOAuthError) {
            showAlert(`Alexa link failed: ${alexaOAuthError}`);
            return;
        }

        if (!alexaOAuthClientId || !alexaOAuthRedirectUri) {
            return;
        }

        alexaOAuthRedirectInFlight = true;
        // Alexa's /api/alexa/oauth route reads portal_session_token from the
        // cookie OR query param. Pass it explicitly to avoid cookie-timing
        // races right after login. Alexa has no separate consent screen, so we
        // pass approved=1 to satisfy the route's consent gate; it then mints the
        // auth code and 302s straight back to Amazon (no consent bounce, which
        // would otherwise drop client_id/redirect_uri and dead-end on the dashboard).
        const continueUrl = new URL('/api/alexa/oauth', window.location.origin);
        continueUrl.searchParams.set('client_id', alexaOAuthClientId);
        continueUrl.searchParams.set('redirect_uri', alexaOAuthRedirectUri);
        continueUrl.searchParams.set('state', alexaOAuthState);
        continueUrl.searchParams.set('portal_session_token', portalToken);
        continueUrl.searchParams.set('approved', '1');
        window.location.assign(continueUrl.toString());
    }

    async function appendGoogleOAuthPortalToken(userData) {
        if (googleOAuthRedirectInFlight) {
            return;
        }

        if (!userData?.portal_session_token) {
            return;
        }

        const portalToken = String(userData.portal_session_token || '');
        if (!portalToken.includes('.') || portalToken.split('.').length !== 2) {
            googleOAuthRedirectInFlight = false;
            showAlert('Session token is invalid. Please log out and sign in again.');
            return;
        }

        if (!isGoogleOauthLinkingIntent() || googleOAuthConsentMode) {
            googleOAuthRedirectInFlight = false;
            return;
        }

        const oauthError = googleOAuthError;
        if (oauthError) {
            googleOAuthRedirectInFlight = false;
            showAlert(`Google link failed: ${oauthError}`);
            return;
        }

        const challenge = parseGoogleOauthChallenge(googleOAuthChallengeParam);
        if (googleOAuthConsentMode && challenge) {
            googleOAuthRedirectInFlight = false;
            return;
        }

        // NOTE: do NOT early-return when userData.google_home_linked === true.
        // Google Home triggers OAuth again for re-linking / "Sync devices"
        // flows, and we must still forward the user through /oauth/continue
        // → consent → auth code. Blocking this dropped the user on the
        // dashboard with no path forward.

        const redirectUri = googleOAuthRedirectUri;
        const state = googleOAuthState;
        if (!redirectUri) {
            googleOAuthRedirectInFlight = false;
            return;
        }

        const clientId = googleOAuthClientId;
        if (!clientId) {
            googleOAuthRedirectInFlight = false;
            return;
        }

        googleOAuthRedirectInFlight = true;
        try {
            const response = await fetch('/api/google/home/oauth/continue', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client_id: clientId,
                    redirect_uri: redirectUri,
                    state,
                    portal_session_token: portalToken
                })
            });

            const data = await response.json();
            if (!response.ok || !data?.redirect_url) {
                throw new Error(data?.error || 'Unable to continue Google linking');
            }

            window.location.assign(data.redirect_url);
        } catch (error) {
            googleOAuthRedirectInFlight = false;
            showAlert(error.message || 'Unable to continue Google linking');
        }
    }

    function renderGoogleConsentCard(userData, challenge) {
        if (!googleConsentCard) {
            showAlert('Consent screen unavailable. Please try again.');
            return;
        }

        if (loginForm) loginForm.classList.add('hidden');
        if (signupForm) signupForm.classList.add('hidden');
        if (dashboard) dashboard.classList.remove('hidden');

        setHeaderState(userData || null);
        setPageTitle(dashboardTitle);
        accountTitle.textContent = 'Confirm Google Assistant Access';
        headerSubtitle.textContent = 'Authorize Apex Connect+ for Google Assistant account linking.';
        hideAlert();

        const statusCard = document.getElementById('statusCard');
        const detailGrid = dashboard ? dashboard.querySelector('.detail-grid') : null;
        const logoutButton = document.getElementById('logoutBtn');

        if (statusCard) {
            statusCard.classList.add('hidden');
        }

        if (detailGrid) {
            for (const card of detailGrid.children) {
                if (card.id !== 'googleConsentCard') {
                    card.classList.add('hidden');
                }
            }
        }

        if (logoutButton) {
            logoutButton.classList.remove('hidden');
        }

        if (googleConsentMeta) {
            const safeEmail = escapeHtml(userData?.email || 'your account');
            let redirectHost = challenge.redirect_uri;
            try {
                redirectHost = new URL(challenge.redirect_uri).host;
            } catch (_error) {
                redirectHost = challenge.redirect_uri;
            }

            googleConsentMeta.innerHTML = `
                <div><strong>Google Client:</strong> ${escapeHtml(challenge.client_id)}</div>
                <div><strong>Redirect Host:</strong> ${escapeHtml(redirectHost)}</div>
                <div><strong>Account:</strong> ${safeEmail}</div>
            `;
        }

        googleConsentCard.classList.remove('hidden');
        stopGoogleEntitiesAutoRefresh();
        stopAccountAutoRefresh();
    }

    function handleGoogleConsentFlow(userData) {
        if (!isGoogleOauthLinkingIntent() || !googleOAuthConsentMode) {
            return false;
        }

        const challenge = parseGoogleOauthChallenge(googleOAuthChallengeParam);
        if (!challenge) {
            showAlert('Invalid Google consent request. Please start linking again.');
            return true;
        }

        const activePortalToken = isWellFormedPortalToken(userData?.portal_session_token)
            ? String(userData.portal_session_token).trim()
            : '';

        if (!activePortalToken) {
            showAlert('Please sign in again to continue Google linking.', false);
            return true;
        }

        renderGoogleConsentCard(userData, challenge);

        if (googleConsentApproveBtn) {
            googleConsentApproveBtn.onclick = () => {
                googleConsentApproveBtn.disabled = true;
                googleConsentApproveBtn.textContent = 'Authorizing...';

                try {
                    const authorizeUrl = new URL('/api/google/home/oauth', window.location.origin);
                    authorizeUrl.searchParams.set('client_id', challenge.client_id);
                    authorizeUrl.searchParams.set('redirect_uri', challenge.redirect_uri);
                    authorizeUrl.searchParams.set('response_type', 'code');
                    authorizeUrl.searchParams.set('state', challenge.state || '');
                    authorizeUrl.searchParams.set('portal_session_token', activePortalToken);
                    authorizeUrl.searchParams.set('approved', '1');
                    window.location.assign(authorizeUrl.toString());
                } catch (_error) {
                    showAlert('Unable to continue Google authorization. Please try again.');
                    googleConsentApproveBtn.disabled = false;
                    googleConsentApproveBtn.textContent = 'Allow and Continue';
                }
            };
        }

        if (googleConsentDenyBtn) {
            googleConsentDenyBtn.onclick = () => {
                const redirectUri = challenge.redirect_uri;
                const denyUrl = new URL('/api/google/home/oauth', window.location.origin);
                denyUrl.searchParams.set('client_id', challenge.client_id);
                denyUrl.searchParams.set('redirect_uri', redirectUri);
                denyUrl.searchParams.set('response_type', 'code');
                denyUrl.searchParams.set('state', challenge.state || '');
                denyUrl.searchParams.set('portal_session_token', activePortalToken);
                denyUrl.searchParams.set('deny', '1');
                window.location.assign(denyUrl.toString());
            };
        }

        return true;
    }

    function stopAccountAutoRefresh() {
        if (accountRefreshTimer) {
            window.clearInterval(accountRefreshTimer);
            accountRefreshTimer = null;
        }
        accountRefreshInFlight = false;
    }

    function buildGoogleEntitiesFingerprint(entities) {
        const items = Array.isArray(entities) ? entities : [];
        return items
            .map((entity) => [
                entity?.entity_id || '',
                entity?.display_name || '',
                entity?.entity_type || '',
                entity?.exposed ? '1' : '0',
                entity?.online ? '1' : '0',
                // Include the HA device identity so a rename/regroup in Home
                // Assistant is reflected by the next silent refresh.
                entity?.state?._ha_device_id || '',
                entity?.state?._ha_device_name || ''
            ].join('|'))
            .sort()
            .join('||');
    }

    function getGoogleEntitiesRefreshKey(userData) {
        if (!userData?.portal_session_token || !userData?.google_home_linked) {
            return '';
        }

        return `${userData.portal_session_token}:${userData.id || userData.email || ''}`;
    }

    function stopGoogleEntitiesAutoRefresh() {
        if (googleEntitiesRefreshTimer) {
            window.clearInterval(googleEntitiesRefreshTimer);
            googleEntitiesRefreshTimer = null;
        }
        googleEntitiesRefreshInFlight = false;
        googleEntitiesRefreshKey = '';
        googleEntitiesLastFingerprint = null;
    }

    async function refreshGoogleHomeEntitiesSilently() {
        if (googleEntitiesRefreshInFlight) {
            return;
        }

        const storedUser = JSON.parse(localStorage.getItem('apex_user') || 'null');
        if (!storedUser?.portal_session_token || !storedUser.google_home_linked) {
            stopGoogleEntitiesAutoRefresh();
            return;
        }

        const nextRefreshKey = getGoogleEntitiesRefreshKey(storedUser);
        if (googleEntitiesRefreshKey && googleEntitiesRefreshKey !== nextRefreshKey) {
            stopGoogleEntitiesAutoRefresh();
        }

        googleEntitiesRefreshInFlight = true;
        try {
            const res = await fetch('/api/account/google-home/entities', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ portal_session_token: storedUser.portal_session_token })
            });

            const data = await res.json();
            if (!res.ok) {
                return;
            }

            const entities = Array.isArray(data.entities) ? data.entities : [];
            const fingerprint = buildGoogleEntitiesFingerprint(entities);
            if (fingerprint !== googleEntitiesLastFingerprint) {
                googleEntitiesLastFingerprint = fingerprint;
                await loadGoogleHomeEntities(storedUser);
            }
        } catch (_error) {
            // Keep the existing UI state on background refresh errors.
        } finally {
            googleEntitiesRefreshInFlight = false;
        }
    }

    function startGoogleEntitiesAutoRefresh(userData) {
        if (!userData?.portal_session_token || !userData.google_home_linked) {
            stopGoogleEntitiesAutoRefresh();
            return;
        }

        const nextRefreshKey = getGoogleEntitiesRefreshKey(userData);
        if (googleEntitiesRefreshTimer && googleEntitiesRefreshKey === nextRefreshKey) {
            return;
        }

        stopGoogleEntitiesAutoRefresh();
        googleEntitiesRefreshKey = nextRefreshKey;
        googleEntitiesRefreshTimer = window.setInterval(() => {
            void refreshGoogleHomeEntitiesSilently();
        }, GOOGLE_ENTITIES_REFRESH_MS);
    }

    async function refreshAccountState({ silent = true } = {}) {
        if (accountRefreshInFlight) {
            return;
        }

        const storedUser = JSON.parse(localStorage.getItem('apex_user') || 'null');
        if (!storedUser?.portal_session_token) {
            stopAccountAutoRefresh();
            return;
        }

        accountRefreshInFlight = true;
        try {
            const res = await fetch('/api/account/me', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ portal_session_token: storedUser.portal_session_token })
            });

            const data = await res.json();
            if (!res.ok) {
                const refreshError = new Error(data.error || 'Unable to refresh account status');
                refreshError.status = res.status;
                throw refreshError;
            }

            const nextData = data.data || {};
            const previousData = storedUser || {};
            const nextFingerprint = buildAccountRenderFingerprint(nextData);
            const previousFingerprint = buildAccountRenderFingerprint(previousData);
            const onlySessionTokenChanged = nextFingerprint === previousFingerprint
                && nextData.portal_session_token
                && previousData.portal_session_token
                && nextData.portal_session_token !== previousData.portal_session_token;

            localStorage.setItem('apex_user', JSON.stringify(nextData));

            if (!onlySessionTokenChanged || nextFingerprint !== accountRenderFingerprint) {
                accountRenderFingerprint = nextFingerprint;
                renderDashboard(nextData, { scroll: false });
            }
        } catch (err) {
            if (err?.status === 401 || err?.status === 404) {
                void clearSessionAndShowAuth();
                if (isGoogleOauthLinkingIntent()) {
                    showAlert('Session expired. Sign in again to continue Google linking.');
                }
                return;
            }

            if (!silent) {
                showAlert(err.message);
            }
        } finally {
            accountRefreshInFlight = false;
        }
    }

    function startAccountAutoRefresh() {
        stopAccountAutoRefresh();
        accountRefreshTimer = window.setInterval(() => {
            refreshAccountState({ silent: true });
        }, ACCOUNT_REFRESH_MS);
    }

    window.addEventListener('beforeunload', () => {
        stopAccountAutoRefresh();
        stopGoogleEntitiesAutoRefresh();
    });

    async function verifyPayment(response, button, fallbackText) {
        const storedUser = JSON.parse(localStorage.getItem('apex_user') || 'null');
        const res = await fetch('/api/billing/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ...response,
                portal_session_token: storedUser?.portal_session_token || undefined
            })
        });

        const data = await res.json();
        if (!res.ok) {
            restoreButton(button, fallbackText);
            throw new Error(data.error);
        }

        const mergedData = {
            ...data.data,
            portal_session_token: data.data.portal_session_token || storedUser?.portal_session_token
        };
        localStorage.setItem('apex_user', JSON.stringify(mergedData));
        renderDashboard(mergedData);
        restoreButton(button, fallbackText);
        showAlert('Payment successful. Remote access is now active.', false);
    }

    function openCheckout(checkout, button, fallbackText) {
        if (!checkout) {
            restoreButton(button, fallbackText);
            showAlert('Billing session was not created. Please try again later.');
            return;
        }

        if (!window.Razorpay) {
            restoreButton(button, fallbackText);
            showAlert('Razorpay Checkout failed to load. Please refresh and try again.');
            return;
        }

        // Razorpay's checkout card is a cross-origin iframe that is ALWAYS light —
        // theme.color only tints its accent/button, there is no dark checkout. On a
        // dark page that white card (and, on mobile, Razorpay's own light backdrop)
        // looks jarring. So present the whole payment in light: flip the page to
        // light while checkout is open, then restore the user's theme when it closes.
        // Dark-mode checkout then looks exactly like light-mode (the consistent
        // intent). We flip only the data-theme-effective attribute the CSS keys off —
        // NOT the saved apex_theme choice — so the user's preference is untouched and
        // restored verbatim. The status-bar meta is kept in sync for mobile.
        const rootEl = document.documentElement;
        const previousEffective = rootEl.getAttribute('data-theme-effective');
        const forceLightForCheckout = previousEffective === 'dark';
        const themeColorMeta = document.querySelector('meta[name="theme-color"]');

        function applyCheckoutTheme() {
            if (!forceLightForCheckout) return;
            rootEl.setAttribute('data-theme-effective', 'light');
            if (themeColorMeta) themeColorMeta.setAttribute('content', '#f8fafc');
        }
        function restoreUserTheme() {
            if (!forceLightForCheckout) return;
            rootEl.setAttribute('data-theme-effective', previousEffective);
            if (themeColorMeta) themeColorMeta.setAttribute('content', '#121c2e');
        }

        const razorpay = new window.Razorpay({
            key: checkout.key,
            subscription_id: checkout.subscription_id,
            name: checkout.name,
            description: checkout.description,
            prefill: checkout.prefill,
            notes: checkout.notes,
            theme: { color: '#1d4ed8' },
            modal: {
                ondismiss: () => {
                    restoreUserTheme();
                    restoreButton(button, fallbackText);
                    showAlert('Payment was not completed. You can resume it anytime from your account.');
                }
            },
            handler: async (response) => {
                restoreUserTheme();
                try {
                    await verifyPayment(response, button, fallbackText);
                } catch (err) {
                    showAlert(err.message);
                }
            }
        });

        razorpay.on('payment.failed', (response) => {
            restoreUserTheme();
            const error = response?.error || {};
            const detailParts = [
                error.description,
                error.reason,
                error.source,
                error.step
            ].filter(Boolean);

            restoreButton(button, fallbackText);
            showAlert(detailParts.length > 0 ? detailParts.join(' | ') : 'Razorpay reported a payment failure.');
            console.error('Razorpay payment failed:', response);
        });

        applyCheckoutTheme();
        razorpay.open();
    }

    // Forgot password toggle
    if (forgotPasswordLink) {
        forgotPasswordLink.addEventListener('click', function (e) {
            e.preventDefault();
            hideAlert();
            if (loginForm) loginForm.classList.add('hidden');
            if (forgotPasswordForm) forgotPasswordForm.classList.remove('hidden');
            accountTitle.textContent = 'Reset your password';
            headerSubtitle.textContent = 'Enter your email and we\'ll send you a reset link.';
        });
    }

    if (backToLoginLink) {
        backToLoginLink.addEventListener('click', function (e) {
            e.preventDefault();
            hideAlert();
            if (forgotPasswordForm) forgotPasswordForm.classList.add('hidden');
            if (loginForm) loginForm.classList.remove('hidden');
            resetLoginSteps();
            accountTitle.textContent = 'Sign in to your Cloud account';
            headerSubtitle.textContent = 'Manage access, billing and your cloud address from one place.';
        });
    }

    if (forgotPasswordForm) {
        forgotPasswordForm.addEventListener('submit', async function (e) {
            e.preventDefault();
            const forgotBtn = document.getElementById('forgotBtn');
            const forgotEmail = document.getElementById('forgotEmail');
            if (!forgotEmail || !forgotBtn) return;

            const emailValue = forgotEmail.value.trim();
            if (!emailValue) {
                showAlert('Please enter your email address.');
                return;
            }

            forgotBtn.disabled = true;
            forgotBtn.textContent = 'Sending...';
            hideAlert();

            try {
                const res = await fetch('/api/auth/forgot-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: emailValue })
                });

                const data = await res.json();
                if (!res.ok) throw new Error(data.error);

                showAlert(data.message || 'If an account exists with that email, a reset link has been sent.', false);
            } catch (err) {
                showAlert(err.message);
            } finally {
                forgotBtn.textContent = 'Send Reset Link';
                forgotBtn.disabled = false;
            }
        });
    }

    // Resend verification email
    if (resendVerificationBtn) {
        resendVerificationBtn.addEventListener('click', async function () {
            const storedUser = JSON.parse(localStorage.getItem('apex_user') || 'null');
            if (!storedUser?.portal_session_token) {
                showAlert('Please log in again to continue.');
                return;
            }

            resendVerificationBtn.disabled = true;
            resendVerificationBtn.textContent = 'Sending...';
            hideAlert();

            try {
                const res = await fetch('/api/auth/resend-verification', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ portal_session_token: storedUser.portal_session_token })
                });

                const data = await res.json();
                if (!res.ok) throw new Error(data.error);

                showAlert(data.message || 'Verification email sent. Check your inbox.', false);
            } catch (err) {
                showAlert(err.message);
            } finally {
                resendVerificationBtn.textContent = 'Resend Verification Email';
                resendVerificationBtn.disabled = false;
            }
        });
    }

    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            void clearSessionAndShowAuth();
        });
    }

    if (headerLogoutBtn) {
        headerLogoutBtn.addEventListener('click', () => {
            void clearSessionAndShowAuth();
        });
    }

    // Manage Account view (in-place panel — sibling of #dashboard inside #account-shell)
    const manageAccountBtn = document.getElementById('manageAccountBtn');
    const manageAccountView = document.getElementById('manageAccountView');
    const manageBackBtn = document.getElementById('manageBackBtn');
    const dashboardSection = document.getElementById('dashboard');
    const logoutAllDevicesBtn = document.getElementById('logoutAllDevicesBtn');
    const changePasswordForm = document.getElementById('changePasswordForm');
    const currentPasswordInput = document.getElementById('currentPasswordInput');
    const newPasswordInput = document.getElementById('newPasswordInput');
    const changePasswordMsg = document.getElementById('changePasswordMsg');
    const changePasswordBtn = document.getElementById('changePasswordBtn');

    function showManageView(options = {}) {
        if (!manageAccountView || !dashboardSection) return;
        if (changePasswordMsg) changePasswordMsg.textContent = '';
        if (currentPasswordInput) currentPasswordInput.value = '';
        if (newPasswordInput) newPasswordInput.value = '';

        manageViewActive = true;
        dashboardSection.classList.add('hidden');
        manageAccountView.classList.remove('hidden');
        loadPasskeys();

        // Opening Manage Account should start at the very top of the page —
        // otherwise, on small screens where you'd scrolled the dashboard down,
        // the swapped-in view inherits that scroll and lands mid-page. We use
        // window.scrollTo(top:0) rather than scrollIntoView so this can ONLY
        // scroll up to the top, never down (that downward yank is exactly the
        // on-load auto-scroll we removed elsewhere). The passkey nudge still
        // overrides this to jump straight to the passkey section.
        if (options.scrollTo === 'passkey') {
            const passkeyTarget = document.getElementById('passkeySection') || manageAccountView;
            passkeyTarget.scrollIntoView({ behavior: 'smooth', block: 'start' });
        } else {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }
    }

    function hideManageView() {
        if (!manageAccountView) return;
        manageViewActive = false;
        manageAccountView.classList.add('hidden');
        const storedUser = JSON.parse(localStorage.getItem('apex_user') || 'null');
        if (storedUser) {
            renderDashboard(storedUser, { scroll: false, fromManageBack: true });
        } else {
            dashboardSection.classList.remove('hidden');
        }
    }

    if (manageAccountBtn) {
        manageAccountBtn.addEventListener('click', () => showManageView());
    }

    if (manageBackBtn) {
        manageBackBtn.addEventListener('click', hideManageView);
    }

    // Log out from all devices
    if (logoutAllDevicesBtn) {
        logoutAllDevicesBtn.addEventListener('click', async () => {
            const storedUser = JSON.parse(localStorage.getItem('apex_user') || 'null');
            if (!storedUser?.portal_session_token) {
                hideManageView();
                showAlert('Please log in again to continue.');
                return;
            }

            if (!confirm('Log out from all devices? This will revoke access for Apex MCU Plus, Google Home, Alexa, and all browsers.')) {
                return;
            }

            logoutAllDevicesBtn.disabled = true;
            logoutAllDevicesBtn.textContent = 'Logging out...';

            try {
                const res = await fetch('/api/account/logout-all-devices', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ portal_session_token: storedUser.portal_session_token })
                });

                const data = await res.json();
                if (!res.ok) throw new Error(data.error);

                if (data.data) {
                    localStorage.setItem('apex_user', JSON.stringify(data.data));
                    renderDashboard(data.data, { scroll: false });
                }

                hideManageView();
                showAlert(data.message || 'All devices have been logged out.', false);
            } catch (err) {
                showAlert(err.message);
            } finally {
                logoutAllDevicesBtn.textContent = 'Log Out All Devices';
                logoutAllDevicesBtn.disabled = false;
            }
        });
    }

    // Change password
    if (changePasswordForm) {
        changePasswordForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const storedUser = JSON.parse(localStorage.getItem('apex_user') || 'null');
            if (!storedUser?.portal_session_token) {
                hideManageView();
                showAlert('Please log in again to continue.');
                return;
            }

            const currentPassword = (currentPasswordInput?.value || '').trim();
            const newPassword = (newPasswordInput?.value || '').trim();

            if (!currentPassword) {
                if (changePasswordMsg) changePasswordMsg.textContent = 'Current password is required.';
                return;
            }
            if (!newPassword || newPassword.length < 8) {
                if (changePasswordMsg) changePasswordMsg.textContent = 'New password must be at least 8 characters.';
                return;
            }

            if (changePasswordBtn) {
                changePasswordBtn.disabled = true;
                changePasswordBtn.textContent = 'Changing...';
            }
            if (changePasswordMsg) changePasswordMsg.textContent = '';

            try {
                const res = await fetch('/api/account/change-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        portal_session_token: storedUser.portal_session_token,
                        current_password: currentPassword,
                        new_password: newPassword
                    })
                });

                const data = await res.json();
                if (!res.ok) throw new Error(data.error);

                if (currentPasswordInput) currentPasswordInput.value = '';
                if (newPasswordInput) newPasswordInput.value = '';
                if (changePasswordMsg) {
                    changePasswordMsg.textContent = data.message || 'Password changed successfully.';
                    changePasswordMsg.classList.remove('danger-label');
                }
            } catch (err) {
                if (changePasswordMsg) {
                    changePasswordMsg.textContent = err.message;
                    changePasswordMsg.classList.add('danger-label');
                }
            } finally {
                if (changePasswordBtn) {
                    changePasswordBtn.textContent = 'Change Password';
                    changePasswordBtn.disabled = false;
                }
            }
        });
    }

    // Delete account modal (opens from within Manage Account)
    const deleteAccountBtn = document.getElementById('deleteAccountBtn');
    const deleteAccountModal = document.getElementById('deleteAccountModal');
    const deleteAccountForm = document.getElementById('deleteAccountForm');
    const deleteConfirmPassword = document.getElementById('deleteConfirmPassword');
    const deleteModalError = document.getElementById('deleteModalError');
    const deleteModalClose = document.getElementById('deleteModalClose');
    const deleteModalConfirmBtn = document.getElementById('deleteModalConfirmBtn');

    function openDeleteModal() {
        if (!deleteAccountModal) return;
        if (deleteConfirmPassword) deleteConfirmPassword.value = '';
        if (deleteModalError) deleteModalError.textContent = '';
        if (deleteModalConfirmBtn) {
            deleteModalConfirmBtn.textContent = 'Permanently Delete Account';
            deleteModalConfirmBtn.disabled = false;
        }
        deleteAccountModal.classList.remove('hidden');
        if (deleteConfirmPassword) deleteConfirmPassword.focus();
    }

    function closeDeleteModal() {
        if (!deleteAccountModal) return;
        deleteAccountModal.classList.add('hidden');
        if (deleteConfirmPassword) deleteConfirmPassword.value = '';
        if (deleteModalError) deleteModalError.textContent = '';
    }

    if (deleteAccountBtn) {
        deleteAccountBtn.addEventListener('click', openDeleteModal);
    }

    if (deleteModalClose) {
        deleteModalClose.addEventListener('click', closeDeleteModal);
    }

    if (deleteAccountModal) {
        deleteAccountModal.addEventListener('click', (event) => {
            if (event.target.closest('[data-close-delete-modal]')) {
                closeDeleteModal();
            }
        });
    }

    if (deleteAccountForm) {
        deleteAccountForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const storedUser = JSON.parse(localStorage.getItem('apex_user') || 'null');
            if (!storedUser?.portal_session_token) {
                closeDeleteModal();
                showAlert('Please log in again to continue.');
                return;
            }

            const password = (deleteConfirmPassword?.value || '').trim();
            if (!password) {
                if (deleteModalError) deleteModalError.textContent = 'Password is required.';
                return;
            }

            if (deleteModalConfirmBtn) {
                deleteModalConfirmBtn.disabled = true;
                deleteModalConfirmBtn.textContent = 'Deleting...';
            }
            if (deleteModalError) deleteModalError.textContent = '';

            try {
                const res = await fetch('/api/account/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        portal_session_token: storedUser.portal_session_token,
                        password
                    })
                });

                const data = await res.json();
                if (!res.ok) throw new Error(data.error);

                closeDeleteModal();
                localStorage.removeItem('apex_user');
                stopAccountAutoRefresh();
                stopGoogleEntitiesAutoRefresh();

                if (pageMode === 'signup') {
                    showSignupView();
                } else {
                    showLoginView();
                }
                showAlert('Your account has been permanently deleted.', false);
            } catch (err) {
                if (deleteModalError) deleteModalError.textContent = err.message;
                if (deleteModalConfirmBtn) {
                    deleteModalConfirmBtn.textContent = 'Permanently Delete Account';
                    deleteModalConfirmBtn.disabled = false;
                }
            }
        });
    }

    // ── Passkeys (passwordless sign-in) ─────────────────────────────────────
    const passkeySection = document.getElementById('passkeySection');
    const passkeyList = document.getElementById('passkeyList');
    const passkeyStatus = document.getElementById('passkeyStatus');
    const addPasskeyBtn = document.getElementById('addPasskeyBtn');
    const removePasskeyModal = document.getElementById('removePasskeyModal');
    const removePasskeyForm = document.getElementById('removePasskeyForm');
    const removePasskeyPassword = document.getElementById('removePasskeyPassword');
    const removePasskeyError = document.getElementById('removePasskeyError');
    const removePasskeyClose = document.getElementById('removePasskeyModalClose');
    const removePasskeyConfirmBtn = document.getElementById('removePasskeyConfirmBtn');
    let passkeyPendingRemovalId = null;

    function getStoredToken() {
        const storedUser = JSON.parse(localStorage.getItem('apex_user') || 'null');
        return storedUser?.portal_session_token || null;
    }

    // Shared passkey UI helpers (one copy in /passkey-helpers.js, loaded before
    // this script). Destructured so existing call sites keep using the bare names.
    const { withTimeout, describePasskeyError, describePasskeyDevice, formatPasskeyDate } = window.PasskeyHelpers;

    function renderPasskeys(passkeys) {
        if (!passkeyList) return;
        passkeyList.innerHTML = '';
        if (!passkeys || !passkeys.length) {
            const empty = document.createElement('p');
            empty.className = 'detail-copy passkey-empty';
            empty.textContent = 'No passkeys yet. Add one to sign in without a password.';
            passkeyList.appendChild(empty);
            return;
        }
        passkeys.forEach((pk) => {
            const item = document.createElement('div');
            item.className = 'passkey-item';

            const info = document.createElement('div');
            info.className = 'passkey-item__info';
            const name = document.createElement('span');
            name.className = 'passkey-item__name';
            // Prefer the provider name resolved server-side from the AAGUID
            // (e.g. "1Password"); fall back to the device nickname or "Passkey".
            name.textContent = pk.display_name || pk.nickname || 'Passkey';
            const meta = document.createElement('span');
            meta.className = 'passkey-item__meta';
            // Show the device/method nickname as secondary context, but only
            // when it adds info beyond the (provider) name already shown.
            const detail = pk.nickname && pk.nickname !== name.textContent ? pk.nickname + ' · ' : '';
            meta.textContent =
                detail + 'Added ' + formatPasskeyDate(pk.created_at) +
                (pk.last_used_at ? ' · Last used ' + formatPasskeyDate(pk.last_used_at) : '');
            info.appendChild(name);
            info.appendChild(meta);

            const removeBtn = document.createElement('button');
            removeBtn.type = 'button';
            removeBtn.className = 'button button-secondary button-small';
            removeBtn.textContent = 'Remove';
            removeBtn.addEventListener('click', () => openRemovePasskeyModal(pk.id));

            item.appendChild(info);
            item.appendChild(removeBtn);
            passkeyList.appendChild(item);
        });
    }

    async function loadPasskeys() {
        if (!passkeySection) return;
        const token = getStoredToken();
        if (!token) return;
        try {
            const res = await fetch('/api/account/passkeys', {
                method: 'GET',
                headers: { Authorization: 'Bearer ' + token }
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.error);
            renderPasskeys(data.passkeys);
        } catch (_err) {
            renderPasskeys([]);
        }
    }

    function setPasskeyStatus(message, isError = false) {
        if (!passkeyStatus) return;
        passkeyStatus.textContent = message || '';
        passkeyStatus.classList.toggle('danger-label', Boolean(isError));
    }

    // Shared passkey enrollment: register options -> WebAuthn attestation ->
    // verify. Returns { ok: true } or { ok: false, isError, message }. Reused
    // by the Manage Account "Add a passkey" button and the welcome interstitial.
    async function enrollPasskey() {
        const token = getStoredToken();
        if (!token) {
            return { ok: false, isError: true, message: 'Please log in again to continue.' };
        }
        if (!window.SimpleWebAuthnBrowser) {
            return { ok: false, isError: true, message: 'Passkeys are not supported in this browser.' };
        }
        try {
            const optRes = await fetch('/api/account/passkeys/register/options', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }
            });
            const optData = await optRes.json();
            if (!optRes.ok) throw new Error(optData.error);

            const attestation = await withTimeout(
                window.SimpleWebAuthnBrowser.startRegistration(optData.options),
                90000
            );

            const nickname = describePasskeyDevice(attestation);
            const verifyRes = await fetch('/api/account/passkeys/register/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
                body: JSON.stringify({ response: attestation, nickname })
            });
            const verifyData = await verifyRes.json();
            if (!verifyRes.ok) throw new Error(verifyData.error);
            return { ok: true };
        } catch (err) {
            // WebAuthn failures are DOMExceptions whose diagnostic is in
            // err.name (err.message is usually empty). Map to a friendly message.
            const r = describePasskeyError(err);
            return { ok: false, isError: r.isError, message: r.message };
        }
    }

    // Refresh the cached user so passkey_2fa_enabled flips on without a reload
    // (hides the banner/interstitial after a successful enrollment).
    function markPasskeyEnrolledLocally() {
        try {
            const stored = JSON.parse(localStorage.getItem('apex_user') || 'null');
            if (stored) {
                stored.passkey_2fa_enabled = true;
                localStorage.setItem('apex_user', JSON.stringify(stored));
            }
        } catch (_e) {
            // best-effort; the next /me poll will correct it anyway
        }
    }

    if (addPasskeyBtn) {
        addPasskeyBtn.addEventListener('click', async () => {
            addPasskeyBtn.disabled = true;
            addPasskeyBtn.textContent = 'Waiting for passkey...';
            setPasskeyStatus('');
            const result = await enrollPasskey();
            if (result.ok) {
                markPasskeyEnrolledLocally();
                setPasskeyStatus('Passkey added. You can now sign in without a password.', false);
                await loadPasskeys();
            } else {
                setPasskeyStatus(result.message, result.isError);
                // Re-render the list so a blocking/existing passkey is visible
                // (e.g. InvalidStateError = a passkey already exists here).
                await loadPasskeys();
            }
            addPasskeyBtn.disabled = false;
            addPasskeyBtn.textContent = 'Add a Passkey';
        });
    }

    function openRemovePasskeyModal(id) {
        passkeyPendingRemovalId = id;
        if (removePasskeyPassword) removePasskeyPassword.value = '';
        if (removePasskeyError) removePasskeyError.textContent = '';
        if (removePasskeyConfirmBtn) {
            removePasskeyConfirmBtn.textContent = 'Remove Passkey';
            removePasskeyConfirmBtn.disabled = false;
        }
        if (removePasskeyModal) removePasskeyModal.classList.remove('hidden');
        if (removePasskeyPassword) removePasskeyPassword.focus();
    }

    function closeRemovePasskeyModal() {
        passkeyPendingRemovalId = null;
        if (removePasskeyModal) removePasskeyModal.classList.add('hidden');
        if (removePasskeyPassword) removePasskeyPassword.value = '';
        if (removePasskeyError) removePasskeyError.textContent = '';
    }

    if (removePasskeyClose) {
        removePasskeyClose.addEventListener('click', closeRemovePasskeyModal);
    }
    if (removePasskeyModal) {
        removePasskeyModal.addEventListener('click', (event) => {
            if (event.target.closest('[data-close-remove-passkey-modal]')) {
                closeRemovePasskeyModal();
            }
        });
    }
    if (removePasskeyForm) {
        removePasskeyForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const token = getStoredToken();
            if (!token || !passkeyPendingRemovalId) {
                closeRemovePasskeyModal();
                showAlert('Please log in again to continue.');
                return;
            }
            const password = (removePasskeyPassword?.value || '').trim();
            if (!password) {
                if (removePasskeyError) removePasskeyError.textContent = 'Password is required.';
                return;
            }
            if (removePasskeyConfirmBtn) {
                removePasskeyConfirmBtn.disabled = true;
                removePasskeyConfirmBtn.textContent = 'Removing...';
            }
            try {
                const res = await fetch('/api/account/passkeys/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
                    body: JSON.stringify({ id: passkeyPendingRemovalId, password })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error);
                closeRemovePasskeyModal();
                setPasskeyStatus(
                    data.remaining === 0
                        ? 'Passkey removed. You will sign in with your password again.'
                        : 'Passkey removed.',
                    false
                );
                await loadPasskeys();
            } catch (err) {
                if (removePasskeyError) removePasskeyError.textContent = err.message;
                if (removePasskeyConfirmBtn) {
                    removePasskeyConfirmBtn.textContent = 'Remove Passkey';
                    removePasskeyConfirmBtn.disabled = false;
                }
            }
        });
    }

    // ── Passkey enrollment prompts ──────────────────────────────────────────
    // Two nudges for users who haven't enrolled a passkey, shown after login
    // until they do. Dismiss state persists in sessionStorage (survives reloads
    // within the session, clears on a new browser session) and is also reset on
    // an explicit logout so the next same-tab login re-shows them:
    //   1. A full-screen welcome interstitial that can enrol inline.
    //   2. A minimal dismissible dashboard banner (kept as a persistent nudge).
    const passkeyPromptBanner = document.getElementById('passkeyPromptBanner');
    const passkeyPromptAddBtn = document.getElementById('passkeyPromptAddBtn');
    const passkeyPromptDismiss = document.getElementById('passkeyPromptDismiss');
    const passkeyInterstitial = document.getElementById('passkeyInterstitial');
    const passkeyInterstitialSetup = document.getElementById('passkeyInterstitialSetup');
    const passkeyInterstitialLater = document.getElementById('passkeyInterstitialLater');
    const passkeyInterstitialStatus = document.getElementById('passkeyInterstitialStatus');
    // Dismissal persists in sessionStorage so it survives page reloads (F5)
    // within the same browser session, but clears when the tab/session ends —
    // so the nudge returns on a genuinely new login, not on every refresh.
    const PASSKEY_DISMISS_KEY = 'apex_passkey_prompt_dismissed';
    const PASSKEY_INTERSTITIAL_KEY = 'apex_passkey_interstitial_seen';
    function readSessionFlag(key) {
        try {
            return sessionStorage.getItem(key) === '1';
        } catch (_e) {
            return false;
        }
    }
    function writeSessionFlag(key) {
        try {
            sessionStorage.setItem(key, '1');
        } catch (_e) {
            // sessionStorage unavailable (private mode etc.) — module var still holds for this page
        }
    }
    let passkeyPromptDismissed = readSessionFlag(PASSKEY_DISMISS_KEY);
    // Initialize from storage so the interstitial does NOT re-pop on soft refresh.
    let passkeyInterstitialSeen = readSessionFlag(PASSKEY_INTERSTITIAL_KEY);
    let passkeyBannerShownThisSession = false;

    function markInterstitialSeen() {
        passkeyInterstitialSeen = true;
        writeSessionFlag(PASSKEY_INTERSTITIAL_KEY);
    }

    function updatePasskeyPromptBanner(userData) {
        const enrolled = Boolean(userData && userData.passkey_2fa_enabled);

        // Full-screen interstitial: show once per session for non-enrolled users.
        if (passkeyInterstitial) {
            const showInterstitial = !enrolled && !passkeyInterstitialSeen && !passkeyPromptDismissed;
            if (showInterstitial) {
                markInterstitialSeen();
                if (passkeyInterstitialStatus) passkeyInterstitialStatus.textContent = '';
                passkeyInterstitial.classList.remove('hidden');
            } else if (enrolled) {
                passkeyInterstitial.classList.add('hidden');
            }
        }

        // Minimal banner: reveal ONCE per login. renderDashboard runs on every
        // 5s poll + visibilitychange, so we must not re-show it each time — the
        // latch separates "eligible" from the one-time reveal. Once enrolled or
        // dismissed it stays hidden; it only returns on a fresh page load/login.
        if (passkeyPromptBanner) {
            if (enrolled || passkeyPromptDismissed) {
                passkeyPromptBanner.classList.add('hidden');
            } else if (!passkeyBannerShownThisSession) {
                passkeyBannerShownThisSession = true;
                passkeyPromptBanner.classList.remove('hidden');
            }
            // else: already shown this session — leave its current state alone
            // so a poll never re-reveals a banner the user manually dismissed.
        }
    }

    function closeInterstitial() {
        if (passkeyInterstitial) passkeyInterstitial.classList.add('hidden');
    }

    // Banner "Add a passkey": jump to Manage Account and scroll to the passkey
    // section (previously only opened the view at the top).
    if (passkeyPromptAddBtn) {
        passkeyPromptAddBtn.addEventListener('click', () => {
            closeInterstitial();
            showManageView({ scrollTo: 'passkey' });
        });
    }
    if (passkeyPromptDismiss) {
        passkeyPromptDismiss.addEventListener('click', () => {
            passkeyPromptDismissed = true;
            writeSessionFlag(PASSKEY_DISMISS_KEY);
            if (passkeyPromptBanner) passkeyPromptBanner.classList.add('hidden');
        });
    }

    // Interstitial "Set up passkey": enrol right here, no navigation needed.
    if (passkeyInterstitialSetup) {
        passkeyInterstitialSetup.addEventListener('click', async () => {
            passkeyInterstitialSetup.disabled = true;
            passkeyInterstitialSetup.textContent = 'Waiting for passkey...';
            if (passkeyInterstitialStatus) {
                passkeyInterstitialStatus.textContent = '';
                passkeyInterstitialStatus.classList.remove('danger-label');
            }
            const result = await enrollPasskey();
            if (result.ok) {
                markInterstitialSeen();
                markPasskeyEnrolledLocally();
                closeInterstitial();
                if (passkeyPromptBanner) passkeyPromptBanner.classList.add('hidden');
                showAlert('Passkey added. You can now sign in without a password.', false);
                loadPasskeys();
            } else {
                if (passkeyInterstitialStatus) {
                    passkeyInterstitialStatus.textContent = result.message;
                    passkeyInterstitialStatus.classList.toggle('danger-label', Boolean(result.isError));
                }
                loadPasskeys();
            }
            passkeyInterstitialSetup.disabled = false;
            passkeyInterstitialSetup.textContent = 'Set up passkey';
        });
    }

    // Interstitial "Maybe later": dismiss to the dashboard (banner stays). Mark
    // it seen so it does not re-pop on the next refresh/poll this session.
    if (passkeyInterstitialLater) {
        passkeyInterstitialLater.addEventListener('click', () => {
            markInterstitialSeen();
            closeInterstitial();
        });
    }

    // Cancel Subscription modal (opens from within Manage Account)
    const cancelSubBtn = document.getElementById('cancelSubscriptionBtn');
    const cancelSubModal = document.getElementById('cancelSubscriptionModal');
    const cancelSubForm = document.getElementById('cancelSubscriptionForm');
    const cancelSubPassword = document.getElementById('cancelSubConfirmPassword');
    const cancelSubError = document.getElementById('cancelSubModalError');
    const cancelSubClose = document.getElementById('cancelSubModalClose');
    const cancelSubConfirmBtn = document.getElementById('cancelSubModalConfirmBtn');

    function openCancelSubModal() {
        if (!cancelSubModal) return;
        if (cancelSubPassword) cancelSubPassword.value = '';
        if (cancelSubError) cancelSubError.textContent = '';
        if (cancelSubConfirmBtn) {
            cancelSubConfirmBtn.textContent = 'Cancel My Subscription';
            cancelSubConfirmBtn.disabled = false;
        }
        cancelSubModal.classList.remove('hidden');
        if (cancelSubPassword) cancelSubPassword.focus();
    }

    function closeCancelSubModal() {
        if (!cancelSubModal) return;
        cancelSubModal.classList.add('hidden');
        if (cancelSubPassword) cancelSubPassword.value = '';
        if (cancelSubError) cancelSubError.textContent = '';
    }

    if (cancelSubBtn) {
        cancelSubBtn.addEventListener('click', openCancelSubModal);
    }
    if (cancelSubClose) {
        cancelSubClose.addEventListener('click', closeCancelSubModal);
    }
    if (cancelSubModal) {
        cancelSubModal.addEventListener('click', (event) => {
            if (event.target.closest('[data-close-cancel-sub-modal]')) {
                closeCancelSubModal();
            }
        });
    }
    if (cancelSubForm) {
        cancelSubForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const storedUser = JSON.parse(localStorage.getItem('apex_user') || 'null');
            if (!storedUser?.portal_session_token) {
                closeCancelSubModal();
                showAlert('Please log in again to continue.');
                return;
            }
            const password = (cancelSubPassword?.value || '').trim();
            if (!password) {
                if (cancelSubError) cancelSubError.textContent = 'Password is required.';
                return;
            }
            if (cancelSubConfirmBtn) {
                cancelSubConfirmBtn.disabled = true;
                cancelSubConfirmBtn.textContent = 'Cancelling...';
            }
            if (cancelSubError) cancelSubError.textContent = '';
            try {
                const res = await fetch('/api/account/cancel-subscription', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        portal_session_token: storedUser.portal_session_token,
                        password
                    })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Unable to cancel subscription.');
                closeCancelSubModal();
                showAlert(data.message || 'Subscription cancelled.', false);
                // Refresh dashboard so the Cancel button hides and status reflects reality.
                refreshAccountState({ silent: true });
            } catch (err) {
                if (cancelSubError) cancelSubError.textContent = err.message;
                if (cancelSubConfirmBtn) {
                    cancelSubConfirmBtn.textContent = 'Cancel My Subscription';
                    cancelSubConfirmBtn.disabled = false;
                }
            }
        });
    }

    // Plan picker — clicking a plan option selects exactly one plan at a time.
    const billingCard = document.getElementById('billingCard');
    const subscribePlanBtn = document.getElementById('subscribePlanBtn');

    function selectPlan(planBtn) {
        if (!planBtn || !billingCard) return;
        const allPlanBtns = billingCard.querySelectorAll('.plan-option');
        allPlanBtns.forEach((btn) => {
            const isSelected = btn === planBtn;
            btn.classList.toggle('plan-option--selected', isSelected);
            btn.setAttribute('aria-pressed', isSelected ? 'true' : 'false');
        });
        // Drop focus so the :focus/:focus-visible state doesn't keep the
        // just-clicked (or previously-clicked) button visually highlighted
        // alongside the selected one.
        if (typeof planBtn.blur === 'function') planBtn.blur();
    }

    if (billingCard) {
        billingCard.addEventListener('click', (event) => {
            const planBtn = event.target.closest('.plan-option');
            if (!planBtn || planBtn.disabled) return;
            selectPlan(planBtn);
        });
    }

    // Subscribe button — creates checkout for the currently selected plan
    if (subscribePlanBtn && billingCard) {
        subscribePlanBtn.addEventListener('click', async () => {
            const storedUser = JSON.parse(localStorage.getItem('apex_user') || 'null');
            if (!storedUser) {
                showAlert('Please log in again to continue payment.');
                return;
            }

            if (!hasSubdomain(storedUser)) {
                renderDashboard(storedUser);
                showAlert('Set your desired cloud address before continuing payment.');
                return;
            }

            const selectedBtn = billingCard.querySelector('.plan-option--selected');
            if (!selectedBtn) {
                showAlert('Please select a plan first.');
                return;
            }

            const planType = selectedBtn.dataset.plan;
            if (planType !== 'monthly' && planType !== 'annual') return;

            // Disable subscribe button and plan options during checkout creation
            subscribePlanBtn.disabled = true;
            subscribePlanBtn.textContent = 'Preparing checkout...';
            const allPlanBtns = billingCard.querySelectorAll('.plan-option');
            allPlanBtns.forEach((btn) => { btn.disabled = true; });
            hideAlert();

            try {
                const res = await fetch('/api/billing/create-checkout', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        portal_session_token: storedUser.portal_session_token,
                        plan: planType
                    })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error);

                const prevUser = JSON.parse(localStorage.getItem('apex_user') || 'null');
                const mergedCheckoutData = {
                    ...data.data,
                    portal_session_token: data.data.portal_session_token || prevUser?.portal_session_token
                };
                localStorage.setItem('apex_user', JSON.stringify(mergedCheckoutData));
                // Skip renderDashboard here — status is still payment_pending
                // so nothing visual changes, and re-rendering would reset the
                // plan picker selection back to the annual default.

                // Thin wrapper so openCheckout's restoreButton works
                // without wiping the subscribe button's inner HTML.
                const restoreControls = () => {
                    subscribePlanBtn.textContent = 'Subscribe';
                    subscribePlanBtn.disabled = false;
                    allPlanBtns.forEach((btn) => { btn.disabled = false; });
                };
                const pseudoBtn = {
                    set textContent(_v) { restoreControls(); },
                    set disabled(_v) { /* handled above */ }
                };
                openCheckout(data.checkout, pseudoBtn, 'Subscribe');
            } catch (err) {
                showAlert(err.message);
                subscribePlanBtn.textContent = 'Subscribe';
                subscribePlanBtn.disabled = false;
                allPlanBtns.forEach((btn) => { btn.disabled = false; });
            }
        });
    }

    if (saveSubdomainBtn) {
        saveSubdomainBtn.addEventListener('click', async () => {
            const storedUser = JSON.parse(localStorage.getItem('apex_user') || 'null');
            if (!storedUser) {
                showAlert('Please log in again to continue.');
                return;
            }

            const nextSubdomain = (dashSubdomain?.value || '').trim().toLowerCase();
            if (!/^[a-z0-9\-]{3,20}$/.test(nextSubdomain)) {
                showAlert('Subdomain can only contain lowercase letters, numbers, and hyphens (3-20 chars).');
                return;
            }

            const originalText = saveSubdomainBtn.textContent;
            saveSubdomainBtn.textContent = 'Saving...';
            saveSubdomainBtn.disabled = true;
            hideAlert();

            try {
                const res = await fetch('/api/account/subdomain', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        portal_session_token: storedUser.portal_session_token,
                        subdomain: nextSubdomain
                    })
                });

                const data = await res.json();
                if (!res.ok) throw new Error(data.error);

                localStorage.setItem('apex_user', JSON.stringify(data.data));
                renderDashboard(data.data);
                showAlert('Cloud address saved.', false);
            } catch (err) {
                showAlert(err.message);
            } finally {
                restoreButton(saveSubdomainBtn, originalText);
            }
        });
    }

    // Click-to-copy on the access-token container. The token is masked with a
    // placeholder until clicked; clicking copies it to the clipboard and
    // reveals the real value (which then stays shown).
    const dashTokenCopy = document.getElementById('dashTokenCopy');
    if (dashTokenCopy) {
        dashTokenCopy.addEventListener('click', async () => {
            const tokenEl = document.getElementById('dashToken');
            const token = (tokenEl?.dataset.token || '').trim();
            if (!token) {
                return;
            }

            try {
                await copyToClipboard(token);
                // Reveal the real token in place of the placeholder.
                if (tokenEl) tokenEl.textContent = token;
                dashTokenCopy.classList.add('is-revealed', 'is-copied');
                window.clearTimeout(dashTokenCopy.copiedTimer);
                dashTokenCopy.copiedTimer = window.setTimeout(() => {
                    dashTokenCopy.classList.remove('is-copied');
                }, 1800);
                showAlert('Access token copied to clipboard.', false);
            } catch (err) {
                showAlert('Could not copy token. Click again or copy it manually.');
            }
        });
    }

    // Clicking the cloud-address tile when not yet configured jumps to the
    // subdomain setter; the live/reserved states are handled by the anchor
    // itself (live opens in a new tab, reserved is inert).
    const dashUrlTile = document.getElementById('dashUrl');
    if (dashUrlTile) {
        dashUrlTile.addEventListener('click', (event) => {
            if (!dashUrlTile.classList.contains('domain-link--setup')) {
                return;
            }
            event.preventDefault();
            if (subdomainCard) {
                subdomainCard.classList.remove('hidden');
                subdomainCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
            if (dashSubdomain) {
                window.setTimeout(() => dashSubdomain.focus(), 300);
            }
        });
    }

    // Security PIN save/change/remove handlers
    const pinSaveBtn = document.getElementById('googleSecurityPinSave');
    const pinChangeBtn = document.getElementById('googleSecurityPinChange');
    const pinRemoveBtn = document.getElementById('googleSecurityPinRemove');
    const pinCancelBtn = document.getElementById('googleSecurityPinCancel');
    const pinInput = document.getElementById('googleSecurityPinInput');
    const pinStatus = document.getElementById('googleSecurityPinStatus');
    const pinSetView = document.getElementById('googleSecurityPinSetView');
    const pinEditView = document.getElementById('googleSecurityPinEditView');

    // UI state: true when a PIN is already stored on the server. Drives
    // whether we show the "Change / Remove" summary or the input+Save row.
    let pinIsSet = false;
    // True while the user is actively editing a PIN (clicked Change). Keeps
    // the 5s account-refresh poll from yanking them out of edit mode back
    // to the set-view when loadSecurityPinStatus re-runs.
    let pinEditing = false;

    function renderPinUi() {
        if (!pinSetView || !pinEditView) return;
        const showEdit = !pinIsSet || pinEditing;
        if (showEdit) {
            pinSetView.classList.add('hidden');
            pinEditView.classList.remove('hidden');
            // Cancel only makes sense when a PIN already exists to fall back to.
            if (pinCancelBtn) pinCancelBtn.classList.toggle('hidden', !pinIsSet);
        } else {
            pinSetView.classList.remove('hidden');
            pinEditView.classList.add('hidden');
            if (pinCancelBtn) pinCancelBtn.classList.add('hidden');
        }
    }

    if (pinSaveBtn && pinInput) {
        pinSaveBtn.addEventListener('click', async () => {
            const userData = JSON.parse(localStorage.getItem('apex_user') || 'null');
            if (!userData?.portal_session_token) {
                showAlert('Please log in again to continue.');
                return;
            }
            const pin = pinInput.value.trim();
            if (!/^\d{4,8}$/.test(pin)) {
                if (pinStatus) pinStatus.textContent = 'PIN must be 4 to 8 digits.';
                return;
            }
            pinSaveBtn.disabled = true;
            try {
                const res = await fetch('/api/account/google-home/security-pin', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ portal_session_token: userData.portal_session_token, pin })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Unable to save PIN');
                pinIsSet = true;
                pinEditing = false;
                if (pinInput) pinInput.value = '';
                renderPinUi();
                if (pinStatus) pinStatus.textContent = 'PIN saved. Google will ask for this PIN before lock/alarm commands.';
            } catch (err) {
                if (pinStatus) pinStatus.textContent = err.message;
            } finally {
                pinSaveBtn.disabled = false;
            }
        });
    }

    if (pinChangeBtn) {
        pinChangeBtn.addEventListener('click', () => {
            if (pinStatus) pinStatus.textContent = '';
            pinEditing = true;
            if (pinInput) pinInput.value = '';
            renderPinUi();
            if (pinInput) pinInput.focus();
        });
    }

    if (pinCancelBtn) {
        pinCancelBtn.addEventListener('click', () => {
            if (pinStatus) pinStatus.textContent = '';
            pinEditing = false;
            if (pinInput) pinInput.value = '';
            renderPinUi();
        });
    }

    if (pinRemoveBtn) {
        pinRemoveBtn.addEventListener('click', async () => {
            const userData = JSON.parse(localStorage.getItem('apex_user') || 'null');
            if (!userData?.portal_session_token) {
                showAlert('Please log in again to continue.');
                return;
            }
            pinRemoveBtn.disabled = true;
            try {
                const res = await fetch('/api/account/google-home/security-pin', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ portal_session_token: userData.portal_session_token, pin: '' })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Unable to remove PIN');
                pinIsSet = false;
                pinEditing = false;
                if (pinInput) pinInput.value = '';
                renderPinUi();
                if (pinStatus) pinStatus.textContent = 'PIN removed. No challenge will be required.';
            } catch (err) {
                if (pinStatus) pinStatus.textContent = err.message;
            } finally {
                pinRemoveBtn.disabled = false;
            }
        });
    }

    // Load current PIN status when Google Home card becomes visible
    async function loadSecurityPinStatus(userData) {
        if (!userData?.portal_session_token || !userData.google_home_linked) return;
        try {
            const res = await fetch('/api/account/google-home/security-pin?portal_session_token=' + encodeURIComponent(userData.portal_session_token));
            const data = await res.json();
            if (!res.ok) return;
            const nextIsSet = Boolean(data.has_pin);
            // Never clobber an in-progress edit. The user clicked Change and
            // is looking at the input — a background poll must not yank them
            // back to the set-view.
            if (pinEditing) {
                pinIsSet = nextIsSet;
                return;
            }
            // If the observed state matches what's already rendered, skip the
            // re-render entirely (no DOM churn, no status-text flash).
            if (nextIsSet === pinIsSet && pinSetView && pinEditView) {
                return;
            }
            pinIsSet = nextIsSet;
            renderPinUi();
        } catch (_) {
            // ignore
        }
    }

    if (loginForm) {
        function finishLoginSuccess(userData) {
            localStorage.setItem('apex_user', JSON.stringify(userData));
            renderDashboard(userData);
            if (!hasSubdomain(userData)) {
                showAlert('Set your desired cloud address to continue setup.', false);
            } else if (userData.status === 'payment_pending') {
                showAlert('Account found. Complete payment from your account to activate remote access.');
            }
        }

        // Run a passkey assertion ceremony for `loginEmailValue` and finish the
        // login. Shared by the auto-start on entering the passkey step and the
        // explicit "Sign in with a passkey" button. `btn` is whichever control
        // triggered it (so we can show progress + restore it); returns true on
        // success so callers can early-return.
        async function runPasskeyLogin(btn) {
            if (!window.SimpleWebAuthnBrowser) {
                showAlert('Passkeys are not supported in this browser. Use another way to sign in.');
                return false;
            }
            const restore = btn ? btn.textContent : null;
            if (btn) {
                btn.disabled = true;
                btn.textContent = 'Waiting for passkey...';
            }
            hideAlert();
            try {
                const beginRes = await fetch('/api/auth/login/passkey/begin', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: loginEmailValue })
                });
                const beginData = await beginRes.json();
                if (!beginRes.ok) throw new Error(beginData.error || 'Could not start passkey sign-in.');

                let assertion;
                try {
                    assertion = await withTimeout(
                        window.SimpleWebAuthnBrowser.startAuthentication(beginData.options),
                        90000
                    );
                } catch (authErr) {
                    // Surface the real reason (hang/timeout, cancel, NotSupported)
                    // instead of a generic failure.
                    throw new Error(describePasskeyError(authErr).message);
                }

                const verifyRes = await fetch('/api/auth/login/passkey/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: loginEmailValue, assertion })
                });
                const verifyData = await verifyRes.json();
                if (!verifyRes.ok) throw new Error(verifyData.error || 'Passkey verification failed.');
                finishLoginSuccess(verifyData.data);
                return true;
            } catch (err) {
                showAlert(err.message);
                return false;
            } finally {
                if (btn) {
                    btn.disabled = false;
                    if (restore !== null) btn.textContent = restore;
                }
            }
        }

        // Step 1 → lookup the email and branch to the right next step.
        async function submitLoginEmail(btn) {
            const input = document.getElementById('loginEmail');
            const value = (input ? input.value : '').trim().toLowerCase();
            if (!value || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
                showAlert('Please enter a valid email address.');
                return;
            }
            const restore = btn ? btn.textContent : null;
            if (btn) {
                btn.disabled = true;
                btn.textContent = 'Checking...';
            }
            hideAlert();
            try {
                const res = await fetch('/api/auth/login/lookup', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: value })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Could not look up that email.');

                loginEmailValue = value;
                const hint = document.getElementById('loginPasswordHint');

                if (data.has_passkey) {
                    const passkeyEmail = document.getElementById('loginPasskeyEmail');
                    if (passkeyEmail) passkeyEmail.textContent = value;
                    goLoginStep('passkey');
                    // Auto-start the assertion so the platform UI appears without
                    // an extra click; the button remains for an explicit retry.
                    runPasskeyLogin(document.getElementById('loginPasskeyBtn'));
                } else {
                    // No passkey: password is this account's primary factor. Show
                    // a gentle hint when the email isn't even registered (we still
                    // route to the password step so the form behaves like a normal
                    // sign-in and reveals nothing extra beyond what lookup already
                    // returned).
                    if (hint) {
                        if (data.exists) {
                            hint.textContent = '';
                            hint.classList.add('hidden');
                        } else {
                            hint.innerHTML =
                                'We couldn\'t find an account for that email. Check it, or <a href="/signup" class="link-inline">create an account</a>.';
                            hint.classList.remove('hidden');
                        }
                    }
                    goLoginStep('password');
                }
            } catch (err) {
                showAlert(err.message);
            } finally {
                if (btn) {
                    btn.disabled = false;
                    if (restore !== null) btn.textContent = restore;
                }
            }
        }

        // Step 2b → verify the password. A passkey account that lands here is
        // falling back: the server answers 202 and emails an OTP, so we advance
        // to the code step instead of signing in.
        async function submitLoginPassword(btn) {
            const pwInput = document.getElementById('loginPassword');
            const password = pwInput ? pwInput.value : '';
            if (!password) {
                showAlert('Please enter your password.');
                return;
            }
            const restore = btn ? btn.textContent : null;
            if (btn) {
                btn.disabled = true;
                btn.textContent = 'Signing In...';
            }
            hideAlert();
            try {
                const res = await fetch('/api/auth/login/password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: loginEmailValue, password })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Sign-in failed.');

                if (res.status === 202 && data.otp_required) {
                    const otpEmail = document.getElementById('loginOtpEmail');
                    if (otpEmail) otpEmail.textContent = loginEmailValue;
                    if (pwInput) pwInput.value = '';
                    goLoginStep('otp');
                    showAlert(data.message || 'We emailed you a 6-digit sign-in code.', false);
                    return;
                }

                finishLoginSuccess(data.data);
            } catch (err) {
                showAlert(err.message);
            } finally {
                if (btn) {
                    btn.disabled = false;
                    if (restore !== null) btn.textContent = restore;
                }
            }
        }

        // Step 3 → verify the emailed 6-digit code and sign in.
        async function submitLoginOtp(btn) {
            const otpInput = document.getElementById('loginOtp');
            const code = (otpInput ? otpInput.value : '').replace(/\D/g, '').trim();
            if (code.length !== 6) {
                showAlert('Enter the 6-digit code from your email.');
                return;
            }
            const restore = btn ? btn.textContent : null;
            if (btn) {
                btn.disabled = true;
                btn.textContent = 'Verifying...';
            }
            hideAlert();
            try {
                const res = await fetch('/api/auth/login/otp/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: loginEmailValue, code })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Invalid or expired code.');
                finishLoginSuccess(data.data);
            } catch (err) {
                showAlert(err.message);
            } finally {
                if (btn) {
                    btn.disabled = false;
                    if (restore !== null) btn.textContent = restore;
                }
            }
        }

        // Single submit dispatcher: the active step decides which handler runs.
        loginForm.addEventListener('submit', (e) => {
            e.preventDefault();
            if (loginCurrentStep === 'email') {
                submitLoginEmail(document.getElementById('loginEmailBtn'));
            } else if (loginCurrentStep === 'passkey') {
                runPasskeyLogin(document.getElementById('loginPasskeyBtn'));
            } else if (loginCurrentStep === 'password') {
                submitLoginPassword(document.getElementById('loginPasswordBtn'));
            } else if (loginCurrentStep === 'otp') {
                submitLoginOtp(document.getElementById('loginOtpBtn'));
            }
        });

        // "Use another way" — drop from the passkey step to the password step.
        const useAnotherWay = document.getElementById('loginUseAnotherWay');
        if (useAnotherWay) {
            useAnotherWay.addEventListener('click', (e) => {
                e.preventDefault();
                hideAlert();
                const hint = document.getElementById('loginPasswordHint');
                if (hint) {
                    hint.textContent = '';
                    hint.classList.add('hidden');
                }
                goLoginStep('password');
            });
        }

        // "Resend code" — re-trigger the password step's OTP send. We don't have
        // the password in scope anymore (cleared on advancing), so bounce the
        // user back to re-enter it; this also naturally rate-limits resends.
        const resendOtp = document.getElementById('loginResendOtp');
        if (resendOtp) {
            resendOtp.addEventListener('click', (e) => {
                e.preventDefault();
                hideAlert();
                showAlert('Re-enter your password to get a fresh sign-in code.', false);
                goLoginStep('password');
            });
        }

        // Every "← Use a different email" link resets to step 1.
        document.querySelectorAll('.login-back-to-email').forEach((link) => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                hideAlert();
                resetLoginSteps();
            });
        });
    }

    if (signupForm) {
        signupForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('signupBtn');
            const defaultText = 'Create Account';
            btn.textContent = 'Creating Account...';
            btn.disabled = true;
            hideAlert();

            const subdomainInput = document.getElementById('signupSubdomain');
            const subdomain = subdomainInput ? subdomainInput.value.trim().toLowerCase() : '';
            if (subdomain && !/^[a-z0-9\-]{3,20}$/.test(subdomain)) {
                showAlert('Subdomain can only contain lowercase letters, numbers, and hyphens (3-20 chars).');
                restoreButton(btn, defaultText);
                return;
            }

            try {
                const res = await fetch('/api/auth/signup', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: document.getElementById('signupEmail').value,
                        password: document.getElementById('signupPassword').value,
                        ...(subdomain ? { subdomain } : {})
                    })
                });

                const data = await res.json();
                if (!res.ok) throw new Error(data.error);

                localStorage.setItem('apex_user', JSON.stringify(data.data));
                renderDashboard(data.data);
                showAlert(data.message, false);
            } catch (err) {
                showAlert(err.message);
            } finally {
                restoreButton(btn, defaultText);
            }
        });
    }

    const storedUser = localStorage.getItem('apex_user');
    if (storedUser) {
        let parsedUser = null;
        try {
            parsedUser = JSON.parse(storedUser);
        } catch (error) {
            parsedUser = null;
        }

        if (!parsedUser || !isWellFormedPortalToken(parsedUser.portal_session_token)) {
            localStorage.removeItem('apex_user');
            void fetch('/api/account/logout', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            }).catch(() => {
                // ignore
            });
            if (pageMode === 'signup') {
                showSignupView();
            } else {
                showLoginView();
            }

            if (isGoogleOauthLinkingIntent()) {
                showAlert('Your session needs refresh. Please sign in again to continue Google linking.', false);
            } else if (alexaOAuthMode) {
                showAlert('Your session needs refresh. Please sign in again to continue Alexa linking.', false);
            }
        } else {
            accountRenderFingerprint = buildAccountRenderFingerprint(parsedUser);
            renderDashboard(parsedUser);
            refreshAccountState({ silent: true });

            document.addEventListener('visibilitychange', () => {
                if (document.visibilityState === 'visible') {
                    refreshAccountState({ silent: true });
                }
            });
        }
    } else if (pageMode === 'signup') {
        showSignupView();
    } else {
        showLoginView();
    }

    if (isGoogleOauthLinkingIntent() && !storedUser) {
        showAlert(googleOAuthConsentMode
            ? 'Sign in to review and approve Google Assistant access.'
            : 'Sign in to continue Google account linking.', false);
    } else if (alexaOAuthMode && !storedUser) {
        showAlert('Sign in to continue Alexa account linking.', false);
    }
})();
