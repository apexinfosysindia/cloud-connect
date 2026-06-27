// Shared light/dark/auto theme controller for all Cloud Connect pages
// (Oasis customer portal + Vista admin portal + marketing/auth pages).
//
// Mechanism:
//   - localStorage key `apex_theme` holds the user's CHOICE: 'light' | 'dark' | 'auto'.
//     'auto' (the default) follows the OS via prefers-color-scheme.
//   - <html> carries two attributes:
//       data-theme            = the raw choice (light/dark/auto)
//       data-theme-effective  = the RESOLVED mode (light/dark) the CSS keys off.
//   - A tiny inline script in each page's <head> applies these synchronously
//     BEFORE the stylesheet loads to avoid a flash of the wrong theme. This
//     file re-applies on load, wires the header toggle button, and repaints
//     when the OS preference changes while in 'auto'.
(function themeController() {
    const STORAGE_KEY = 'apex_theme';
    const ORDER = ['light', 'dark', 'auto'];

    // Per-page default used only when the user has made no explicit choice.
    // The Vista admin pages set <html data-theme-default="dark"> so the admin
    // portal opens in dark; customer/marketing pages omit it and default to
    // 'auto' (follow the OS). This must agree with each page's inline <head>
    // bootstrap so there's no flash between the two.
    function pageDefault() {
        try {
            const def = document.documentElement.getAttribute('data-theme-default');
            if (def === 'light' || def === 'dark') return def;
        } catch (_error) {
            // documentElement always exists in practice — defensive only.
        }
        return 'auto';
    }
    // Crisp inline SVGs (stroke = currentColor so they adopt the button color
    // and theme). Far more consistent across platforms than emoji glyphs.
    const ICONS = {
        light:
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>',
        dark:
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>',
        // Half-filled circle = the conventional "auto / follow system" mark.
        auto:
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor" stroke="none"/></svg>'
    };
    const LABELS = { light: 'Light', dark: 'Dark', auto: 'Auto' };

    function readChoice() {
        try {
            const stored = window.localStorage.getItem(STORAGE_KEY);
            if (stored === 'light' || stored === 'dark' || stored === 'auto') {
                return stored;
            }
        } catch (_error) {
            // localStorage unavailable (private mode / blocked) — fall through.
        }
        return pageDefault();
    }

    function writeChoice(choice) {
        try {
            window.localStorage.setItem(STORAGE_KEY, choice);
        } catch (_error) {
            // ignore persistence failures
        }
    }

    function prefersDark() {
        return Boolean(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
    }

    function resolveEffective(choice) {
        if (choice === 'dark') return 'dark';
        if (choice === 'light') return 'light';
        return prefersDark() ? 'dark' : 'light';
    }

    // The phone status-bar / address-bar tint. Mobile browsers read
    // <meta name="theme-color"> to color that chrome; we keep it in sync with
    // the resolved theme so the bar matches the page background (it blends into
    // the top of the page) instead of defaulting to black. Values mirror the
    // body's top gradient stop: light #f8fafc, dark --bg-soft #121c2e.
    const THEME_COLORS = { light: '#f8fafc', dark: '#121c2e' };
    function applyThemeColorMeta(effective) {
        let meta = document.querySelector('meta[name="theme-color"]');
        if (!meta) {
            meta = document.createElement('meta');
            meta.setAttribute('name', 'theme-color');
            document.head.appendChild(meta);
        }
        meta.setAttribute('content', THEME_COLORS[effective] || THEME_COLORS.light);
    }

    function applyChoice(choice) {
        const root = document.documentElement;
        const effective = resolveEffective(choice);
        root.setAttribute('data-theme', choice);
        root.setAttribute('data-theme-effective', effective);
        applyThemeColorMeta(effective);
    }

    function renderToggle(choice) {
        const btns = document.querySelectorAll('.theme-toggle');
        if (!btns.length) return;
        const icon = ICONS[choice] || ICONS.auto;
        const label = LABELS[choice] || LABELS.auto;
        btns.forEach((btn) => {
            btn.innerHTML =
                '<span class="theme-toggle__icon">' +
                icon +
                '</span><span class="theme-toggle__label">' +
                label +
                '</span>';
            btn.setAttribute('aria-label', 'Theme: ' + label + '. Click to change.');
            btn.setAttribute('title', 'Theme: ' + label + ' (click to change)');
        });
    }

    function setChoice(choice) {
        applyChoice(choice);
        writeChoice(choice);
        renderToggle(choice);
    }

    // Keep the footer copyright year current without a build step: each footer
    // ships a static fallback year inside <span class="footer-year"> and this
    // overwrites it with the actual current year on load.
    function updateFooterYear() {
        const year = String(new Date().getFullYear());
        document.querySelectorAll('.footer-year').forEach((el) => {
            el.textContent = year;
        });
    }

    function cycle() {
        const current = readChoice();
        const nextIndex = (ORDER.indexOf(current) + 1) % ORDER.length;
        setChoice(ORDER[nextIndex]);
    }

    function init() {
        const choice = readChoice();
        // Re-apply (the inline head script already did this; harmless + keeps
        // this file self-sufficient if the inline snippet is ever removed).
        applyChoice(choice);
        renderToggle(choice);
        updateFooterYear();

        document.querySelectorAll('.theme-toggle').forEach((btn) => {
            btn.addEventListener('click', cycle);
        });

        // Repaint live when the OS flips light/dark and we're following it.
        if (window.matchMedia) {
            const media = window.matchMedia('(prefers-color-scheme: dark)');
            const onChange = function onPrefChange() {
                if (readChoice() === 'auto') {
                    applyChoice('auto');
                }
            };
            if (typeof media.addEventListener === 'function') {
                media.addEventListener('change', onChange);
            } else if (typeof media.addListener === 'function') {
                // Safari < 14 fallback
                media.addListener(onChange);
            }
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
