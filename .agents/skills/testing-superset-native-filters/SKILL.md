---
name: testing-superset-native-filters
description: How to run Superset locally (venv + webpack dev server) and drive the dashboard native-filter config modal in a browser/Playwright for end-to-end testing.
---

# Local Superset for native-filter modal testing

## Backend
- Use Python 3.11 (`uv venv -p 3.11 .venv`); Python 3.14 and 3.10 fail to build/install.
- The full `requirements/development.txt` may have resolver conflicts (bigquery vs grpcio-status); install `requirements/base.txt` + `pip install -e .` instead.
- Minimal `superset_config.py`: SECRET_KEY, sqlite SQLALCHEMY_DATABASE_URI, `WTF_CSRF_ENABLED=False`, `TALISMAN_ENABLED=False`. Export `SUPERSET_CONFIG_PATH`.
- `superset db upgrade && superset fab create-admin ... && superset init`, then `superset run -p 8088 --no-reload --no-debugger` (reload + webpack ts-checker can OOM the box).
- Run long-lived services (Xvfb, backend, frontend) in `tmux` sessions; plain background shells may die.

## Frontend
- Node version must match `superset-frontend/.nvmrc` (24.x); Node 20 fails on ESM `webpack-manifest-plugin`. `zstd` system package is required (`apt-get install zstd`).
- `DISABLE_TS_CHECKER=true npm run dev-server` on :9000 proxies API to :8088. Dev server hot-reloads code changes; verify served chunk contains a new identifier if unsure.

## Driving the UI (Playwright / selectors)
- Login: `[data-test="username-input"]`, `[data-test="password-input"]`, `[data-test="login-button"]`.
- The filter bar is hidden in dashboard edit mode; open the dashboard in view mode. Horizontal bar: expand via `[data-test="filter-bar__expand-button"]`, gear is `[data-test="filterbar-orientation-icon"]`, menu item "Add or edit filters and controls" opens the modal.
- In the modal the "New" control (`[data-test="new-item-dropdown-button"]`) opens on HOVER, then click "Add filter".
- Multiple filter panes exist in the DOM; always scope selectors with `:visible` (e.g. `input[id$="_filterType"]:visible`, `label:visible:has-text("Filter has default value")`).
- Ant Select options are async; type to filter and retry if the option isn't present yet. Real mouse move/down/up (not `.click()`) is more reliable for menus.
- If the `computer` tool is unavailable (enigo init failed), use headed Chrome on Xvfb (`DISPLAY=:5`) with Playwright `recordVideo` (needs `npx playwright install ffmpeg`) and the Devin Chrome executable under `/opt/.devin/chrome/`.

## Reproducing a failing chart-data request
Create a virtual dataset whose SQL references a dropped table, add a chart on it to a dashboard; new filters then fire `/api/v1/chart/data` (metrics count) → 400.
