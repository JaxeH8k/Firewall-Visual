# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

**Firewall GPO Visualizer** — a zero-dependency, single-file static web app (`index.html`) that parses GPMC-exported HTML firewall policy reports and renders them as an interactive visual dashboard. No build step, no package manager, no server required — just open `index.html` in a browser.

## Running the App

Open `index.html` directly in a browser, or serve it with any static file server:

```bash
python3 -m http.server 8080
# or
npx serve .
```

## Generating Test Data

The `demo/` directory contains:
- `Inbound_Firewall_Test_GPO.htm` — a pre-built sample GPO report ready to load
- `New-RandomFirewallGpo.ps1` — PowerShell script (requires AD + admin) to generate a GPO with randomized inbound firewall rules, then export via GPMC as an HTML report

To generate a new test report:
1. Run `New-RandomFirewallGpo.ps1` on a domain-joined Windows machine (requires `GroupPolicy` and `NetSecurity` modules, admin rights)
2. Export the GPO as an HTML report from GPMC
3. Drop the `.htm` file into the visualizer

## Architecture

Everything lives in `index.html` in three sequential blocks:

### `<style>` — CSS
CSS custom properties defined on `:root` drive the dark-mode color theme (`--bg-primary`, `--accent-blue`, `--accent-green`, `--accent-red`, etc.). All component styles follow these variables. No CSS framework.

### HTML structure
- `#landing` — file upload screen (drag-and-drop or click to browse)
- `#app` — main application (hidden until a file loads), containing:
  - `.topbar` — logo + GPO name + reload button
  - `.tab-nav` — four tabs: Overview, Corporate Office, Coffee Shop, Home Network
  - `.main-content` — tab content panels (`#tab-overview`, `#tab-corporate`, `#tab-coffeeshop`, `#tab-home`)
  - `.side-panel` — slides in from the right with full rule details on click

### `<script>` — JavaScript
Global state: `rules[]` (all parsed rules), `gpoName`, `selectedRule`.

Key functions and their roles:

| Function | Purpose |
|---|---|
| `processFile(file)` | Reads the file; detects UTF-16 vs UTF-8 by null-byte presence and re-reads accordingly |
| `parseGPOHtml(html)` | DOM-parses the GPMC HTML, finds the "Inbound Rules" section, walks the `table.info` rows to extract rule name/description (2-cell rows) and rule properties (subtable rows) |
| `renderAll()` | Calls `renderOverview()` and `renderEnvironment()` for each of the three profiles |
| `renderOverview()` | Builds stat cards + filterable/searchable full rules table |
| `renderOverviewTable()` | Re-filters and re-renders the overview table body based on current filter values |
| `renderEnvironment(tabId, profileKey, ...)` | Builds per-profile view: stat cards, animated computer illustration, port tiles grid |
| `rulesForProfile(profileKey)` | Filters `rules[]` to those whose `profile` field is `'all'` or includes the given key (Domain/Private/Public) |
| `portTile(r, animIdx)` | Returns HTML for a single port tile; color-coded allow (green left border) vs block (red left border) |
| `selectRule(r)` / `openSidePanel()` / `closeSidePanel()` | Manages side panel state and renders full rule details |

### GPO HTML parsing details
The GPMC HTML format uses a specific structure:
- `span.sectionTitle` with text "Inbound Rules" identifies the section
- Rules are in a `table.info` where alternating rows contain:
  1. A 2-cell row: rule name + description
  2. A row containing a `table.subtable` with key/value property rows

Protocol numbers are numeric strings in the `protocol` field (`'6'` = TCP, `'17'` = UDP, `'1'` = ICMP, `'58'` = ICMPv6). The `PROTO_MAP` constant handles display translation.
