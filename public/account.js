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
    const accountShell = document.getElementById('account-shell');
    const logoutBtn = document.getElementById('logoutBtn');
    const headerLogoutBtn = document.getElementById('headerLogoutBtn');
    const headerUserEmail = document.getElementById('headerUserEmail');
    const guestNavActions = document.getElementById('guestNavActions');
    const signedInNavActions = document.getElementById('signedInNavActions');
    const subdomainCard = document.getElementById('subdomainCard');
    const dashSubdomain = document.getElementById('dashSubdomain');
    const saveSubdomainBtn = document.getElementById('saveSubdomainBtn');
    const dashUrlHelp = document.getElementById('dashUrlHelp');
    const googleHomeCard = document.getElementById('googleHomeCard');
    const googleHomeStatus = document.getElementById('googleHomeStatus');
    const googleHomeEntities = document.getElementById('googleHomeEntities');
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
    let googleEntitiesRefreshTimer = null;
    let googleEntitiesRefreshInFlight = false;
    let googleEntitiesRefreshKey = '';
    let googleEntitiesLastFingerprint = null;
    const oauthParams = new URLSearchParams(window.location.search);
    const googleOAuthMode = oauthParams.get('google_oauth') === '1';
    const googleOAuthClientId = oauthParams.get('client_id') || '';
    const googleOAuthRedirectUri = oauthParams.get('redirect_uri') || '';
    const googleOAuthState = oauthParams.get('state') || '';
    const googleOAuthError = oauthParams.get('error') || '';
    const googleOAuthConsentMode = oauthParams.get('google_oauth_consent') === '1';
    const googleOAuthChallengeParam = oauthParams.get('oauth_challenge') || '';
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

    function scrollToAccountShell() {
        accountShell.scrollIntoView({ behavior: 'smooth', block: 'start' });
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

    function restoreButton(button, fallbackText) {
        if (!button) return;
        button.textContent = fallbackText;
        button.disabled = false;
    }

    function setPageTitle(title) {
        document.title = title;
    }

    function normalizeSignedInUrl() {
        if (googleOAuthMode) {
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

        if (headerUserEmail) {
            headerUserEmail.textContent = isSignedIn ? userData.email : '';
        }
    }

    async function clearSessionAndShowAuth() {
        stopAccountAutoRefresh();
        stopGoogleEntitiesAutoRefresh();
        googleOAuthRedirectInFlight = false;
        localStorage.removeItem('apex_user');
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
        setHeaderState(null);
        setPageTitle(loginTitle);
        accountTitle.textContent = 'Sign in to your Cloud account';
        headerSubtitle.textContent = 'Manage access, billing and your cloud address from one place.';
        hideAlert();
        scrollToAccountShell();

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
        scrollToAccountShell();

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

    async function loadGoogleHomeEntities(userData) {
        if (!googleHomeEntities || !userData?.portal_session_token) {
            return;
        }

        if (!userData.google_home_enabled) {
            googleHomeEntities.innerHTML = '<p class="detail-copy">Enable Google Home to manage exposed entities.</p>';
            return;
        }

        googleHomeEntities.innerHTML = '<p class="detail-copy">Loading entities...</p>';

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
            if (entities.length === 0) {
                googleHomeEntities.innerHTML = '<p class="detail-copy">No entities synced yet. Keep addon online and wait for next sync.</p>';
                return;
            }

            googleHomeEntities.innerHTML = entities.map((entity) => `
                <label class="google-entity-row">
                    <input type="checkbox" class="google-entity-toggle" data-entity-id="${escapeHtml(entity.entity_id)}" ${entity.exposed ? 'checked' : ''}>
                    <span class="google-entity-name">${escapeHtml(entity.display_name || entity.entity_id)}</span>
                    <span class="google-entity-meta">${escapeHtml(entity.entity_type || 'switch')} | ${entity.online ? 'online' : 'offline'}</span>
                </label>
            `).join('');
        } catch (error) {
            googleHomeEntities.innerHTML = `<p class="detail-copy">${escapeHtml(error.message || 'Unable to load Google Home entities right now.')}</p>`;
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
        const shouldScroll = options.scroll !== false;
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
        const showBillingCard = userData.status === 'payment_pending' && subdomainConfigured && emailVerified;
        billingCard.classList.toggle('hidden', !showBillingCard);
        tokenCard.classList.toggle('hidden', !accessEnabled);

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

        document.getElementById('dashToken').textContent = userData.access_token || 'Issued when service is enabled';

        if (googleHomeCard) {
            const linked = Boolean(userData.google_home_linked);
            const showGoogleCard = accessEnabled && linked;
            googleHomeCard.classList.toggle('hidden', !showGoogleCard);
            if (showGoogleCard) {
                if (googleHomeStatus) {
                    googleHomeStatus.textContent = 'Linked to Google';
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
            }
        } else {
            stopGoogleEntitiesAutoRefresh();
        }

        const dashUrl = document.getElementById('dashUrl');
        const dashUrlLabel = document.getElementById('dashUrlLabel');
        if (!subdomainConfigured) {
            dashUrlLabel.textContent = 'Cloud Address';
            dashUrl.textContent = 'Not set';
            dashUrl.href = '#';
            dashUrl.removeAttribute('target');
            dashUrl.className = 'domain-link domain-link--disabled';
            if (dashUrlHelp) {
                dashUrlHelp.textContent = 'Set your desired cloud address to continue account activation.';
            }
        } else {
            dashUrl.textContent = `https://${userData.domain}`;
            if (accessEnabled) {
                dashUrlLabel.textContent = 'Live Cloud Address';
                dashUrl.href = `https://${userData.domain}`;
                dashUrl.target = '_blank';
                dashUrl.className = 'domain-link domain-link--live';
                if (dashUrlHelp) {
                    dashUrlHelp.textContent = 'Your cloud address is active and ready to use.';
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
            if (shouldScroll) {
                scrollToAccountShell();
            }
            return;
        }

        if (shouldScroll) {
            scrollToAccountShell();
        }

        startAccountAutoRefresh();
        void appendGoogleOAuthPortalToken(userData);
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

        if (userData.google_home_linked === true) {
            googleOAuthRedirectInFlight = false;
            return;
        }

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
                entity?.online ? '1' : '0'
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
                    restoreButton(button, fallbackText);
                    showAlert('Payment was not completed. You can resume it anytime from your account.');
                }
            },
            handler: async (response) => {
                try {
                    await verifyPayment(response, button, fallbackText);
                } catch (err) {
                    showAlert(err.message);
                }
            }
        });

        razorpay.on('payment.failed', (response) => {
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

    function showManageView() {
        if (!manageAccountView || !dashboardSection) return;
        if (changePasswordMsg) changePasswordMsg.textContent = '';
        if (currentPasswordInput) currentPasswordInput.value = '';
        if (newPasswordInput) newPasswordInput.value = '';

        manageViewActive = true;
        dashboardSection.classList.add('hidden');
        manageAccountView.classList.remove('hidden');
        manageAccountView.scrollIntoView({ behavior: 'smooth', block: 'start' });
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
        manageAccountBtn.addEventListener('click', showManageView);
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

    if (googleHomeEntities) {
        googleHomeEntities.addEventListener('change', async (event) => {
            const toggle = event.target.closest('.google-entity-toggle');
            if (!toggle) {
                return;
            }

            const userData = JSON.parse(localStorage.getItem('apex_user') || 'null');
            if (!userData?.portal_session_token) {
                showAlert('Please log in again to continue.');
                return;
            }

            if (!userData.google_home_linked) {
                showAlert('Link Apex Connect+ in Google Home app first.');
                toggle.checked = false;
                return;
            }

            const entityId = toggle.dataset.entityId;
            const exposed = toggle.checked;

            toggle.disabled = true;
            try {
                const res = await fetch(`/api/account/google-home/entities/${encodeURIComponent(entityId)}/expose`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        portal_session_token: userData.portal_session_token,
                        exposed
                    })
                });
                const data = await res.json();
                if (!res.ok) {
                    throw new Error(data.error || 'Unable to update entity exposure');
                }
                showAlert(data.message, false);
                googleEntitiesLastFingerprint = null;
                const refreshedUser = JSON.parse(localStorage.getItem('apex_user') || 'null');
                await loadGoogleHomeEntities(refreshedUser || userData);
            } catch (error) {
                toggle.checked = !exposed;
                showAlert(error.message);
            } finally {
                toggle.disabled = false;
            }
        });
    }

    // Security PIN save/clear handlers
    const pinSaveBtn = document.getElementById('googleSecurityPinSave');
    const pinClearBtn = document.getElementById('googleSecurityPinClear');
    const pinInput = document.getElementById('googleSecurityPinInput');
    const pinStatus = document.getElementById('googleSecurityPinStatus');

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
                pinInput.value = '';
                if (pinStatus) pinStatus.textContent = 'PIN saved. Google will ask for this PIN before lock/alarm commands.';
            } catch (err) {
                if (pinStatus) pinStatus.textContent = err.message;
            } finally {
                pinSaveBtn.disabled = false;
            }
        });
    }

    if (pinClearBtn) {
        pinClearBtn.addEventListener('click', async () => {
            const userData = JSON.parse(localStorage.getItem('apex_user') || 'null');
            if (!userData?.portal_session_token) {
                showAlert('Please log in again to continue.');
                return;
            }
            pinClearBtn.disabled = true;
            try {
                const res = await fetch('/api/account/google-home/security-pin', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ portal_session_token: userData.portal_session_token, pin: '' })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || 'Unable to clear PIN');
                pinInput.value = '';
                if (pinStatus) pinStatus.textContent = 'PIN cleared. No challenge will be required.';
            } catch (err) {
                if (pinStatus) pinStatus.textContent = err.message;
            } finally {
                pinClearBtn.disabled = false;
            }
        });
    }

    // Load current PIN status when Google Home card becomes visible
    async function loadSecurityPinStatus(userData) {
        if (!pinStatus || !userData?.portal_session_token || !userData.google_home_linked) return;
        try {
            const res = await fetch('/api/account/google-home/security-pin?portal_session_token=' + encodeURIComponent(userData.portal_session_token));
            const data = await res.json();
            if (res.ok) {
                pinStatus.textContent = data.has_pin ? 'PIN is set. Lock and alarm commands will require this PIN.' : 'No PIN set.';
            }
        } catch (_) {
            // ignore
        }
    }

    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const btn = document.getElementById('loginBtn');
            btn.textContent = 'Signing In...';
            btn.disabled = true;
            hideAlert();

            try {
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: document.getElementById('loginEmail').value,
                        password: document.getElementById('loginPassword').value
                    })
                });

                const data = await res.json();
                if (!res.ok) throw new Error(data.error);

                localStorage.setItem('apex_user', JSON.stringify(data.data));
                renderDashboard(data.data);
                if (!hasSubdomain(data.data)) {
                    showAlert('Set your desired cloud address to continue setup.', false);
                } else if (data.data.status === 'payment_pending') {
                    showAlert('Account found. Complete payment from your account to activate remote access.');
                }
            } catch (err) {
                showAlert(err.message);
            } finally {
                btn.textContent = 'Sign In';
                btn.disabled = false;
            }
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
    }
})();
