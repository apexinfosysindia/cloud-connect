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
    const META = {
        light: { icon: '☀️', label: 'Light' },
        dark: { icon: '🌙', label: 'Dark' },
        auto: { icon: '◐', label: 'Auto' }
    };

    function readChoice() {
        try {
            const stored = window.localStorage.getItem(STORAGE_KEY);
            if (stored === 'light' || stored === 'dark' || stored === 'auto') {
                return stored;
            }
        } catch (_error) {
            // localStorage unavailable (private mode / blocked) — fall through.
        }
        return 'auto';
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

    function applyChoice(choice) {
        const root = document.documentElement;
        root.setAttribute('data-theme', choice);
        root.setAttribute('data-theme-effective', resolveEffective(choice));
    }

    function renderToggle(choice) {
        const btns = document.querySelectorAll('.theme-toggle');
        if (!btns.length) return;
        const meta = META[choice] || META.auto;
        btns.forEach((btn) => {
            btn.innerHTML =
                '<span class="theme-toggle__icon" aria-hidden="true">' +
                meta.icon +
                '</span><span class="theme-toggle__label">' +
                meta.label +
                '</span>';
            btn.setAttribute('aria-label', 'Theme: ' + meta.label + '. Click to change.');
            btn.setAttribute('title', 'Theme: ' + meta.label);
        });
    }

    function setChoice(choice) {
        applyChoice(choice);
        writeChoice(choice);
        renderToggle(choice);
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
