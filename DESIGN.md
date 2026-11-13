---
name: CheckBackdoor
description: Offline scan report for Windows; a completed integrity check, read like the library of a game launcher.
colors:
  hue: "#1d5fbf"
  hue-ink: "#ffffff"
  ground: "#f2f4f7"
  surface: "#ffffff"
  raised: "#f6f7f9"
  active: "#e8ebef"
  border: "#e3e6ea"
  rule: "#eceef1"
  control: "#cdd2d8"
  text: "#0b0c0d"
  muted: "#596069"
  neg: "#c4242a"
  warn: "#b45309"
  warn-ink: "#92400e"
  pill-high-bg: "#ffedea"
  pill-high: "#831c1e"
  pill-medium-bg: "#fdf0dc"
  pill-medium: "#7c3a06"
  pill-low-bg: "#eceef1"
  pill-low: "#3d434a"
  note-bg: "#fffbeb"
  note-line: "#fde68a"
  note-ink: "#92400e"
  dark-hue: "#6f9dff"
  dark-hue-ink: "#0b0c0d"
  dark-ground: "#0c0d0e"
  dark-surface: "#151618"
  dark-raised: "#1c1d20"
  dark-active: "#26282c"
  dark-border: "#282a2e"
  dark-rule: "#1f2124"
  dark-control: "#3b3e43"
  dark-text: "#f0f1f2"
  dark-muted: "#a2a8af"
  dark-neg: "#ff6b6b"
  dark-warn: "#f0a43c"
  dark-warn-ink: "#f5c27a"
  dark-pill-high-bg: "#3b191b"
  dark-pill-high: "#ffb4b0"
  dark-pill-medium-bg: "#3a2810"
  dark-pill-medium: "#f5c27a"
  dark-pill-low-bg: "#24262a"
  dark-pill-low: "#c9cdd2"
  dark-note-bg: "#241c0c"
  dark-note-line: "#4a3815"
  dark-note-ink: "#f5c27a"
typography:
  display:
    fontFamily: "Segoe UI Variable Display, Segoe UI, system-ui, -apple-system, Helvetica Neue, Arial, sans-serif"
    fontSize: "30px"
    fontWeight: 600
    lineHeight: "36px"
    letterSpacing: "-0.015em"
    fontFeature: "tnum"
  headline:
    fontFamily: "Segoe UI Variable Display, Segoe UI, system-ui, -apple-system, Helvetica Neue, Arial, sans-serif"
    fontSize: "24px"
    fontWeight: 600
    lineHeight: "30px"
    letterSpacing: "-0.01em"
    fontFeature: "tnum"
  title:
    fontFamily: "Segoe UI Variable Text, Segoe UI, system-ui, -apple-system, Helvetica Neue, Arial, sans-serif"
    fontSize: "16px"
    fontWeight: 600
    lineHeight: "24px"
  body:
    fontFamily: "Segoe UI Variable Text, Segoe UI, system-ui, -apple-system, Helvetica Neue, Arial, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: "20px"
    fontFeature: "tnum"
  body-sm:
    fontFamily: "Segoe UI Variable Text, Segoe UI, system-ui, -apple-system, Helvetica Neue, Arial, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: "18px"
  label:
    fontFamily: "Segoe UI Variable Text, Segoe UI, system-ui, -apple-system, Helvetica Neue, Arial, sans-serif"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: "16px"
  mono:
    fontFamily: "Cascadia Mono, Cascadia Code, Consolas, SF Mono, monospace"
    fontSize: "12.5px"
    fontWeight: 400
    lineHeight: "18px"
rounded:
  sm: "4px"
  control: "6px"
  sheet: "8px"
  full: "999px"
spacing:
  xxs: "2px"
  xs: "4px"
  sm: "8px"
  gap: "12px"
  md: "16px"
  lg: "24px"
  xl: "32px"
  xxl: "48px"
components:
  button:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.control}"
    padding: "0 12px"
    height: "32px"
  button-hover:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.text}"
  sheet:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.sheet}"
  verify-panel:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    typography: "{typography.display}"
    rounded: "{rounded.sheet}"
    padding: "24px 24px 20px"
  verification-bar:
    backgroundColor: "{colors.hue}"
    rounded: "{rounded.full}"
    height: "8px"
  severity-cell:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.muted}"
    typography: "{typography.label}"
    padding: "12px 16px 14px"
  severity-cell-hover:
    backgroundColor: "{colors.raised}"
  area-item:
    backgroundColor: "transparent"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "4px 8px"
    height: "44px"
  area-item-selected:
    backgroundColor: "{colors.active}"
    textColor: "{colors.hue}"
  pill-high:
    backgroundColor: "{colors.pill-high-bg}"
    textColor: "{colors.pill-high}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "0 8px"
    height: "22px"
  pill-medium:
    backgroundColor: "{colors.pill-medium-bg}"
    textColor: "{colors.pill-medium}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "0 8px"
    height: "22px"
  pill-low:
    backgroundColor: "{colors.pill-low-bg}"
    textColor: "{colors.pill-low}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "0 8px"
    height: "22px"
  pill-info:
    backgroundColor: "transparent"
    textColor: "{colors.muted}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "0 8px"
    height: "22px"
  search-field:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "0 10px"
    height: "32px"
  finding-row:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    padding: "14px 16px"
  finding-row-hover:
    backgroundColor: "{colors.raised}"
  todo-box:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "10px 12px"
  note-warning:
    backgroundColor: "{colors.note-bg}"
    textColor: "{colors.note-ink}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.control}"
    padding: "8px 12px"
---


# Design System: CheckBackdoor

## Overview

**Creative North Star: "Verifying the game files"**

The report is an integrity check that has already finished, like when a launcher verifies the installed files of a game: a completed bar, then the library of the PC areas, each with its own status. The frame is an achromatic ledger: grey-blue ground, white sheets with 1px borders, near-black ink, tabular figures. Color does not decorate: a single blue hue marks the check and the selection, red and amber appear only where there is a severity to read.

The density is that of a work tool, not a landing page: 14px base text, compact rows, a centered column with 1088px of usable width. The verdict is the only large text on the page (30px) and is read first; everything else is list, filter and expandable detail. The system rejects the default security dashboard: no shield, no circular score gauge, no four colored KPI tiles.

The report is a single offline HTML file: no external request when it opens, so the typeface is Windows' own, the environment the tool lives in, and the icons are hand-drawn inline SVGs. It works without JavaScript (filters hidden, all findings visible) and follows the system light or dark theme, with a manual switch.

**Key Characteristics:**
- Achromatic sheet frame: ground, white sheets, 1px borders, no shadows.
- A single hue (verification blue) for the bar, selection, focus and interactive states.
- Red and amber reserved for severity and incomplete-check warnings.
- Segoe UI Variable with tabular figures; Cascadia Mono for paths and hashes.
- Single-stroke 1.5px icons, color inherited from the text.
- Two complete themes (light and dark) with the same roles.

## Colors

An achromatic ledger with a single cool accent and two severity colors, each with its pair for the dark theme.

### Primary
- **Verification Blue** (hue; dark: dark-hue): the color of a successful check. It fills the bar of passed items and its legend dot, colors the tick in the mark and in "Scan completed", the name of the selected area, the focus ring, the text selection, the border of the active search and link hover. It never becomes the background of surfaces or of filled buttons.

### Secondary
- **Risk Red** (neg; dark: dark-neg): the "high risk" segment of the bar, the High count in the severity strip, the "at risk" state in the library.
- **Review Amber** (warn for the bar and the dots; warn-ink for text, darker for AA contrast): items "to review".
- **Severity pills** (pill-high, pill-medium, pill-low with their backgrounds): pairs of a soft tint + dark ink of the same family; Info is outline only with muted text.

### Tertiary
- **Amber Note** (note-bg, note-line, note-ink): only for the "Incomplete checks" warning and for scan errors. The informational variant of the note (comparison with the previous scan) goes back to achromatic: normal surface, border and text.

### Neutral
- **Light Slate Ground** (ground): the plane of the page and of the top bar.
- **Sheet** (surface): scan panel, severity strip, list of findings, fields.
- **Raised Sheet** (raised): hover of rows and cells, "What to do" box, code background.
- **Selection** (active): selected area and hover in the library, theme button hover.
- **Border** (border) and **Rule** (rule): the outer border of sheets and the softer inner dividers.
- **Control Outline** (control): border of buttons and search, unchecked severity box, scrollbar.
- **Ink** (text) and **Muted** (muted): main text and metadata, labels, secondary counts.

### Named Rules
**The One Hue Rule.** Blue belongs to the check and to interaction: bar, selection, focus, link hover. Never as a fill for buttons, headings or decoration.

**The Severity-Only Warmth Rule.** Red and amber appear only where there is a severity (pills, counts, bar segments, area states) or an incomplete check. An area without problems stays achromatic: "Checked" in grey with the tick.

**The Paired Theme Rule.** Every role has a light and a dark value (dark- prefix); the dark theme is a near-black neutral ground, not blue. A new color without its dark pair does not enter the system.

## Typography

**Display Font:** Segoe UI Variable Display (with Segoe UI, system-ui, Helvetica Neue, Arial)
**Body Font:** Segoe UI Variable Text (with Segoe UI, system-ui, Helvetica Neue, Arial)
**Label/Mono Font:** Cascadia Mono (with Cascadia Code, Consolas, SF Mono)

**Character:** Windows' own typeface, because the report lives on Windows and cannot download fonts: sober, readable, with tabular figures on the whole body because counts are compared in columns. Mono is reserved for raw data (paths, hashes, file names).

### Hierarchy
- **Display** (600, 30px/36px, -0.015em): only the verdict in the scan panel; drops to 24px/30px below 760px.
- **Headline** (600, 24px/30px, -0.01em): the page title "Scan of [PC]" and the numbers of the severity strip.
- **Title** (600, 16px/24px): the heading of the "Findings" list and of the blocks of the closing guide.
- **Body** (400, 14px/20px): running text; finding titles at 600, area names at 500. Long lines limited to 70-78ch.
- **Body small** (400, 13px/18px): buttons, bar legend, key-value pairs, notes.
- **Label** (400, 12px/16px): subtitle with date and duration, severity labels, area metadata, pills (500), footer. Never spaced uppercase.
- **Mono** (400, 12.5px/18px): paths, technical details, SHA-256, file names in text.

### Named Rules
**The Tabular Ledger Rule.** Figures are always tabular (font-variant-numeric: tabular-nums on the body); numbers use thousands separators (6,795).

**The One Loud Line Rule.** The verdict is the only display line. No other heading reaches 30px.

## Layout

A centered column with a maximum width of 1136px and 24px inner margins (1088px usable), repeated identically in the 48px top bar. Vertical sequence: title with date and actions, any notes, scan panel, severity strip, then the work grid: the 264px area library on the left (sticky 16px from the top) and the list of findings on the right, separated by the 12px gap. At the bottom, the two-column guide with 48px of space, separated by a rule.

Rhythm: 12px gap between the main blocks, 16px inside lists, 24px inside the scan panel and between page blocks, 32-48px only between the work area and the guide.

Responsive: below 1000px the library becomes a horizontal scrolling row of cards (min 168px, with border and surface) above the list. Below 760px the margins drop to 16px, the title and actions stack, the severity strip becomes 2x2, the search takes the full width at 40px height, in rows the pill moves above the title and the key-value pairs become one column. In print the bar, actions, search and theme disappear and the ground becomes white.

## Elevation & Depth

The system is flat: no shadows. Depth comes from the tonal contrast between the ground and the sheets (surface) and from 1px borders; inside the sheets, levels read through softer rules and the raised background for hover and secondary boxes. The selected state uses the active tone, not elevation.

### Named Rules
**The Paper On Slate Rule.** A container stands out with surface + a 1px border, never with a shadow. If an element seems to need to "float", rethink it as a sheet or a row.

## Shapes

Slightly soft corners at three levels: 8px for sheets (scan panel, severity strip, list), 6px for controls (buttons, search, library areas, notes, "What to do" box), 4px for the smallest elements (pills, inline code, focus ring). The scan bar is the only capsule shape (999px), with segments separated by 2px of space; legend dots are 8px circles. Icons are single 1.5px strokes with round caps on a 16x16 grid (12px for the "open outside" icon); the mark is a broken circle with a tick in verification blue.

## Components

### Buttons
Quiet, tool-like: they are for downloading data, not for selling.
- **Shape:** control corners (6px), 32px height, 12px horizontal padding, 16px icon with 6px spacing.
- **Default:** sheet with control border and ink text at 13px.
- **Hover / Focus:** raised background and muted border (0.15s transition); pressed moves down 1px; focus with a 2px blue ring at 2px distance.
- **Ghost (theme button):** 32x32px, transparent, muted icon; on hover active background and ink icon. Visible only with JavaScript.
- **Link-button:** underlined text at 600 in the text color, blue on hover; used for "go to area" in notes.

### Chips (severity pills)
- **Style:** 22px height, 0 8px padding, 4px corners, 12px at 500. High, Review and Low with a soft background and ink of the same family; Info outline only.
- **State:** static; they are not filters. The filters are the cells of the severity strip.

### Cards / Containers
- **Corner Style:** 8px for sheets.
- **Background:** surface on ground.
- **Shadow Strategy:** none (see Elevation & Depth).
- **Border:** 1px border outside, 1px rule between rows and cells.
- **Internal Padding:** 24px in the scan panel, 12-16px in lists and cells.

### Inputs / Fields
- **Style:** 32px search field with a magnifier icon, control border, 6px corners, maximum width 360px; muted placeholder.
- **Focus:** 1px border and outline in verification blue (visual double border, no glow).
- **Disabled:** without JavaScript the field is not shown.

### Navigation
- **Top bar:** 48px on the ground, bottom rule; mark + "CheckBackdoor" at 600, then muted PC and user with ellipsis, theme switch on the right.
- **Area library:** a list of buttons at least 44px tall with name (500), 12px metadata and state on the right (grey tick "Checked", red triangle "at risk", amber circle "to review", italic "Not run"). Selected: active background and name in blue. On tablet and mobile it becomes a scrolling row of cards.

### Scan panel (signature)
The 30px verdict on the left, "Scan completed in [duration]" with a blue tick on the right, one sentence of explanation (max 72ch), then the full-width 8px bar: a blue segment for passed items, amber and red at the end for items to review and at risk (each segment at least 4px). The bar fills from the left in 0.9s with cubic-bezier(.16,1,.3,1), disabled with prefers-reduced-motion. Below, the legend with dots and bold numbers.

### Severity strip (signature)
A single sheet split into four cells by vertical rules; each cell is a filter (aria-pressed) with a checkbox, a 12px label and a 24px number (red or amber only if greater than zero). Off: empty box, muted number at 400, "· hidden". Info starts off.

### Finding row
A details element: pill (72px column), title at 600 with a muted one-line subtitle with ellipsis, chevron that rotates 180 degrees in 0.2s. High rows start open. The body contains the reasons as a list, the key-value pairs (104px labels, code on raised) with external links followed by the "open outside" icon, and the "What to do." box on raised with 6px corners.

## Do's and Don'ts

### Do:
- **Do** build every new container as a sheet: surface, 1px border, 8px corners, no shadow.
- **Do** use verification blue only for a successful check, selection, focus and link hover.
- **Do** give every new color its pair for the dark theme, both in the system preference and in data-theme.
- **Do** show paths, hashes and file names in Cascadia Mono at 12.5px, with forced wrapping (overflow-wrap: anywhere).
- **Do** draw icons as inline single-stroke 1.5px SVGs on a 16x16 grid, color currentColor.
- **Do** keep everything inline and offline: no external fonts, scripts or images.
- **Do** make sure the report stays complete without JavaScript: controls that depend on scripts hide, content does not.

### Don't:
- **Don't** use shields, circular score gauges or colored KPI tiles: the summary is the scan bar and the severity strip.
- **Don't** color an area or a number red or amber without a severity; zero stays ink.
- **Don't** use blue as a fill for buttons or surfaces.
- **Don't** add shadows, gradients or blurs.
- **Don't** use spaced uppercase labels above headings: labels are 12px grey, lowercase.
- **Don't** use characters or emoji as icons.
