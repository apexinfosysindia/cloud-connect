(function accountPortal() {
    const pageMode = document.body.dataset.authMode;
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');
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
    const payNowBtn = document.getElementById('payNowBtn');
    const subdomainCard = document.getElementById('subdomainCard');
    const dashSubdomain = document.getElementById('dashSubdomain');
    const saveSubdomainBtn = document.getElementById('saveSubdomainBtn');
    const dashUrlHelp = document.getElementById('dashUrlHelp');
    const portalBrandTitle = 'ApexOS Cloud Connect Oasis';
    const loginTitle = `Sign In | ${portalBrandTitle}`;
    const signupTitle = `Create Account | ${portalBrandTitle}`;
    const dashboardTitle = `Account | ${portalBrandTitle}`;

    function scrollToAccountShell() {
        accountShell.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function showAlert(message, isError = true) {
        alertBox.textContent = message;
        alertBox.className = `alert is-visible ${isError ? 'is-error' : 'is-success'}`;
    }

    function hideAlert() {
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
        if (window.location.pathname !== '/') {
            window.history.replaceState({}, '', '/');
        }
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

    function clearSessionAndShowAuth() {
        localStorage.removeItem('apex_user');
        setHeaderState(null);

        if (pageMode === 'signup') {
            showSignupView();
        } else {
            showLoginView();
        }
    }

    function showLoginView() {
        if (signupForm) signupForm.classList.add('hidden');
        if (loginForm) loginForm.classList.remove('hidden');
        if (dashboard) dashboard.classList.add('hidden');
        setHeaderState(null);
        setPageTitle(loginTitle);
        accountTitle.textContent = 'Sign in to your Cloud account';
        headerSubtitle.textContent = 'Manage access, billing and your cloud address from one place.';
        hideAlert();
        scrollToAccountShell();
    }

    function showSignupView() {
        if (loginForm) loginForm.classList.add('hidden');
        if (signupForm) signupForm.classList.remove('hidden');
        if (dashboard) dashboard.classList.add('hidden');
        setHeaderState(null);
        setPageTitle(signupTitle);
        accountTitle.textContent = 'Create your Cloud account';
        headerSubtitle.textContent = 'Create your account, reserve your cloud address and complete billing.';
        hideAlert();
        scrollToAccountShell();
    }

    function getStatusMessage(userData) {
        if (userData.status === 'payment_pending') {
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

    function renderDashboard(userData) {
        if (loginForm) loginForm.classList.add('hidden');
        if (signupForm) signupForm.classList.add('hidden');
        dashboard.classList.remove('hidden');
        setHeaderState(userData);
        setPageTitle(dashboardTitle);
        normalizeSignedInUrl();
        accountTitle.textContent = `Cloud account for ${userData.email}`;
        headerSubtitle.textContent = 'Manage access status, billing and cloud address from one place.';

        const accessEnabled = ['active', 'trial'].includes(userData.status);
        const subdomainConfigured = hasSubdomain(userData);
        const tone = getStatusTone(userData.status);

        const statusCard = document.getElementById('statusCard');
        const statusBadge = document.getElementById('dashStatus');
        statusCard.className = tone.card;
        statusBadge.className = tone.badge;
        statusBadge.textContent = tone.label;
        document.getElementById('dashStatusTitle').textContent = tone.title;
        document.getElementById('dashStatusDetail').textContent = getStatusMessage(userData);

        const billingCard = document.getElementById('billingCard');
        const tokenCard = document.getElementById('tokenCard');
        subdomainCard.classList.toggle('hidden', subdomainConfigured);
        billingCard.classList.toggle('hidden', userData.status !== 'payment_pending' || !subdomainConfigured);
        tokenCard.classList.toggle('hidden', !accessEnabled);

        if (dashSubdomain) {
            dashSubdomain.value = subdomainConfigured ? userData.subdomain : '';
        }

        document.getElementById('dashToken').textContent = userData.access_token || 'Issued when service is enabled';

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

        scrollToAccountShell();
    }

    async function verifyPayment(response, button, fallbackText) {
        const res = await fetch('/api/billing/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(response)
        });

        const data = await res.json();
        if (!res.ok) {
            restoreButton(button, fallbackText);
            throw new Error(data.error);
        }

        localStorage.setItem('apex_user', JSON.stringify(data.data));
        renderDashboard(data.data);
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

    if (logoutBtn) {
        logoutBtn.addEventListener('click', clearSessionAndShowAuth);
    }

    if (headerLogoutBtn) {
        headerLogoutBtn.addEventListener('click', clearSessionAndShowAuth);
    }

    if (payNowBtn) {
        payNowBtn.addEventListener('click', async () => {
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

            const originalText = payNowBtn.textContent;
            payNowBtn.textContent = 'Preparing Checkout...';
            payNowBtn.disabled = true;
            hideAlert();

            try {
                const res = await fetch('/api/billing/create-checkout', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ portal_session_token: storedUser.portal_session_token })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error);

                localStorage.setItem('apex_user', JSON.stringify(data.data));
                renderDashboard(data.data);
                openCheckout(data.checkout, payNowBtn, originalText);
            } catch (err) {
                showAlert(err.message);
                restoreButton(payNowBtn, originalText);
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
                if (data.checkout) {
                    openCheckout(data.checkout, btn, defaultText);
                }
            } catch (err) {
                showAlert(err.message);
            } finally {
                restoreButton(btn, defaultText);
            }
        });
    }

    const storedUser = localStorage.getItem('apex_user');
    if (storedUser) {
        renderDashboard(JSON.parse(storedUser));
    } else if (pageMode === 'signup') {
        showSignupView();
    } else {
        showLoginView();
    }
})();
