# Lore UI Style Guide

All styles live in `src/ui.rs` inside the `render_styles()` function. There are no external CSS files.

## Design Tokens (CSS Variables)

### Spacing Scale
```
--s-1: 4px    --s-2: 8px    --s-3: 12px   --s-4: 16px
--s-5: 24px   --s-6: 32px   --s-7: 48px   --s-8: 64px
```

### Color Variables
| Variable | Purpose |
|---|---|
| `--bg` | Page background |
| `--panel` | Panel/nav background |
| `--panel-strong` | Card/block background |
| `--ink` | Primary text color |
| `--muted` | Secondary/dimmed text |
| `--line` | Borders and dividers |
| `--accent` | Primary accent (blue) |
| `--accent-soft` | Light accent background |
| `--surface-hover` | Hover state background |
| `--input-bg` | Form input background |
| `--button-bg` / `--button-ink` | Standard button colors |
| `--hero-button-bg` / `--hero-button-ink` | Prominent button colors (blue fill) |

### Typography
- `--font-sans` — body text, UI labels
- `--font-mono` — code, textareas, metadata
- `--radius` — standard border radius for cards and inputs

---

## Button Sizes

Two canonical size classes that can be combined with any color/style class:

### Small (`.btn-sm`)
28x28px square icon buttons. `border-radius: 5px`, no padding, inline-flex centered, flex-shrink: 0.
Use for: icon-only action buttons in headers, toolbars, chat panes.

### Large (`.btn-lg`)
48px min-height with `padding: var(--s-3) var(--s-4)`, 16px font.
Use for: full form buttons, prominent actions. This matches the default `<button>` sizing but provides an explicit class when needed.

---

## Button Categories

### 1. Prominent Buttons (`.button-link`)
Blue-filled oval buttons used for primary actions in page headers.

**CSS:** `min-height: 44px`, `padding: 0 var(--s-5)`, `border-radius: 999px`, `font-weight: 700`, `font-size: 0.95rem`. Background is `--hero-button-bg`, text is `--hero-button-ink`. Hover lifts 1px (`translateY(-1px)`) with slight opacity reduction.

**Examples:**
- "Search", "Audit", "History" buttons in the project header
- "Ask" button in the librarian panel
- "Back to project" links on audit/history pages
- "Copy" buttons on the Agents page
- "Save" / "Cancel" in the project title rename form

**Usage:** Page-level actions, navigation between major views, primary form actions in headers.

### 2. Inline Icon Buttons (`.block-header-btn`)
Small square icon-only buttons used on block headers.

**CSS:** `width: 28px`, `height: 28px`, `border-radius: 6px`, `border: 1px solid transparent`, `background: transparent`, `color: var(--muted)`. Hover shows `--accent-soft` background with `--accent` border and color. The `.danger` variant shows red on hover.

**Examples:**
- Copy link button (chain-link icon) on each block
- Edit button (pencil icon) on each block
- Delete button (X icon) on each block

**Usage:** Per-item actions on blocks. Always grouped together in a `.block-header-actions` flex container on the right side of the block header. Order: copy, edit, delete.

### 3. Tree Action Buttons (`.tree-add-child`, `.tree-add-btn`, `.tree-drag-handle`)
Small inline buttons used in the project tree sidebar.

**CSS:** `border: 1px solid var(--line)`, `border-radius: var(--radius)`, `padding: 2px 8px`, `font-size: 0.85rem`, `color: var(--muted)`, `background: none`. Hover shows `--surface-hover` background with `--ink` color.

**Examples:**
- "+" button to create a child project under a tree node
- "+ New project" button at the bottom of the tree
- Burger/grip handle for drag-and-drop reordering

**Usage:** Compact actions alongside tree rows. The drag handle uses `cursor: grab` / `cursor: grabbing`.

### 4. Inserter Toggle Button (`.inserter-btn`)
Circular "+" button that appears between blocks on hover.

**CSS:** `width: 32px`, `height: 32px`, `border-radius: 50%`, `border: 2px solid var(--line)`, `background: var(--panel-strong)`, `font-size: 1.2rem`. Hidden by default (`opacity: 0`), shown on hover via `.inserter-hover-zone:hover .inserter-btn`. Has a subtle `box-shadow`. Hover shows accent colors.

**Examples:**
- The "+" that appears between any two blocks when hovering the gap

**Usage:** Only used in the block timeline for inserting new blocks.

### 5. Inserter Type Buttons (`.inserter-type-btn`)
Small rectangular buttons for choosing block type in the inserter form.

**CSS:** `padding: var(--s-2) var(--s-4)`, `border: 1px solid var(--line)`, `border-radius: var(--radius)`, `font-size: 0.85rem`, `font-weight: 600`, `color: var(--muted)`. Active/hover shows accent border and text.

**Examples:**
- "Markdown", "SVG", "Image" type selector buttons inside the block inserter

**Usage:** Only inside the expanded block inserter.

### 6. Standard Form Buttons
Default `<button>` elements inside forms.

**CSS (global):** `width: 100%`, `min-height: 44px`, `border-radius: var(--radius)`, `background: var(--button-bg)`, `color: var(--button-ink)`, `font-weight: 600`.

**Examples:**
- "Sign in" on the login page
- "Save" / "Cancel" in block edit forms (overridden to `width: auto` via `.block-edit-actions button`)
- "Create" in the admin token form

**Usage:** Full-width form submission buttons, or auto-width inside edit forms.

---

## Glyphs (SVG Icons)

All icons are inline SVGs using a consistent style:
- `width="14" height="14"` (fits inside 28px icon buttons)
- `viewBox="0 0 24 24"`
- `fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"`

This matches the Lucide/Feather icon style. Use `currentColor` for stroke so icons inherit the parent's text color and respond to hover states.

### Icon Reference

| Icon | SVG Path Summary | Used For |
|---|---|---|
| **Pencil** (edit) | `M17 3a2.83 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z` + `m15 5 4 4` | Block edit button |
| **X** (delete) | Two diagonal lines: `(18,6)-(6,18)` and `(6,6)-(18,18)` | Block delete button |
| **Chain link** (copy link) | Two curved paths forming interlocking chain links | Block/project copy-link button |
| **Burger menu** (drag handle) | Three horizontal lines at y=6, y=12, y=18 | Project tree drag handle |

### Adding New Icons
1. Use the same SVG attributes: `width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"`
2. Source paths from Lucide (https://lucide.dev) for consistency
3. Place inline in the Rust format string, not as external files

---

## Selectable List (`.sel-list`)

A standard pattern for any list where items can be selected and a detail panel appears below. Used for admin users, endpoints, agents, and any future list-with-detail UI.

### Structure

```html
<div class="sel-list">
  <div class="sel-item" data-sel-id="item-1">
    <div>
      <span class="sel-item-name">Item Name</span>
      <span class="sel-item-meta"><span class="pill">badge</span> &middot; extra info</span>
    </div>
    <span class="sel-item-actions">
      <button class="btn-sm" title="Action"><!-- SVG glyph --></button>
    </span>
  </div>
</div>
<div class="sel-detail" data-sel-id="item-1" style="display:none">
  <!-- detail content shown when item is selected -->
</div>
```

### Classes

| Class | Purpose |
|---|---|
| `.sel-list` | Container. Bordered, rounded, column flex. No margin (panel provides edge spacing). |
| `.sel-item` | Row. Flex between, padded `var(--s-3) var(--s-4)`, bottom border, hover highlight. |
| `.sel-item.active` | Selected state: `var(--bg-hover)` background + 4px `var(--accent)` left border. |
| `.sel-item-name` | Primary label. `font-weight: 600`, mono font, `0.9rem`. |
| `.sel-item-meta` | Secondary text/badges. `0.82rem`, `var(--fg-muted)`, flex with gap. |
| `.sel-item-actions` | Right-side button group. Flex, `gap: var(--s-1)`, no shrink. Use `btn-sm` buttons with SVG glyphs and `title` tooltips. |
| `.sel-detail` | Detail panel below list. Fully bordered with full border-radius. Hidden by default (`display:none`), shown when parent `.sel-item` is active. |

### Behaviour (JS)

Use `data-sel-id` on both `.sel-item` and `.sel-detail` elements with matching values. The standard initialiser wires up click-to-toggle:

```js
function initSelList(scope) {
  var items = scope.querySelectorAll('.sel-list .sel-item');
  var details = scope.querySelectorAll('.sel-detail');
  items.forEach(function(item) {
    item.addEventListener('click', function() {
      var id = item.getAttribute('data-sel-id');
      var wasActive = item.classList.contains('active');
      items.forEach(function(i) { i.classList.remove('active'); });
      details.forEach(function(d) { d.style.display = 'none'; });
      if (!wasActive) {
        item.classList.add('active');
        var detail = scope.querySelector('.sel-detail[data-sel-id="' + id + '"]');
        if (detail) detail.style.display = '';
      }
    });
  });
}
```

Call `initSelList(scopeElement)` where `scopeElement` is the nearest container that holds both the list and its detail panels (e.g. a `[data-panel]` section). On the admin page this is auto-initialised for all `[data-panel]` sections.

### Action buttons

Buttons inside `.sel-item-actions` should use `btn-sm` (28x28 icon buttons) with:
- Inline SVG glyphs (14x14, Lucide style)
- A `title` attribute for the tooltip
- `event.stopPropagation()` in onclick to prevent triggering item selection

### Examples in codebase

- **Admin users list** — username items with role badge, detail panel for password/session management
- **Admin endpoints list** — provider endpoints with kind badge, detail panel for config/test/delete
- **Agents page** — agent list with status badge and stop/restart buttons, detail panel for grants and setup

---

## Panel (`.panel`)

A bordered, rounded container used to group related content throughout the UI.

**CSS:** `background: var(--panel)`, `border: 1px solid var(--line)`, `border-radius: var(--radius)`, `box-shadow: var(--shadow)`, `backdrop-filter: blur(8px)`, `padding: var(--s-5)`.

**Rule: internal content must never touch the panel borders.** The panel provides `var(--s-5)` padding on all sides. Children should not add their own side margins or padding to create edge spacing — the panel handles it. Use only top margins between sibling elements inside a panel for vertical spacing.

### Typical structure
```html
<section class="panel">
  <div class="panel-title">Title</div>
  <!-- content: sel-list, forms, text, etc. -->
</section>
```

Panels can omit `.panel-title` entirely — they just have no title. When present, `.panel-title` provides consistent bottom spacing (`var(--s-3)`) before the content.

### `.panel-title`
Small uppercase label inside a panel. `font-size: 0.75em`, `font-weight: 600`, `text-transform: uppercase`, `letter-spacing: 0.05em`, `color: var(--fg)`, `opacity: 0.35`. Always the first child inside the panel. Do NOT place titles outside panels — the title is part of the panel.

### `.panel-header`
The title area inside a panel. `display: grid`, `gap: var(--s-2)`, no padding (panel provides it). Contains an `<h2>` and optional `<p>` description. Used for admin sections with richer headings.

### Examples
- Admin page sections (Users, Endpoints, Roles, etc.)
- Settings page sections
- Agent detail panels
- Project document and agent-context sections

---

## Expanded Text Editor

A standard full-screen editing pattern for any multiline field that is expected to hold real content rather than a short note. This is the default pattern for long prompt/config/note editing surfaces across phone, tablet, and desktop.

### When to use it

Use the expanded text editor for:
- Prompt-like config such as `Pinned Context`, `Goals`, `Stopping Point`, `Periodic Checks`, and `Red Flags`
- Any textarea that is not effectively single-line
- Any multiline field where focused editing matters more than seeing surrounding controls

Do not keep these fields as the primary inline editing surface inside dense panels. The inline field should act as the visible summary/preview surface; the actual edit interaction should open the expanded editor.

### Interaction Model

- The editor is always full-screen and shown as an overlay without navigating away from the current page
- Opening the editor should feel like temporarily switching into an editing mode, not like expanding the current card a bit
- `Cancel` discards the overlay edits and returns to the previous page state
- `Save` commits the new value back to the source field and runs that field's normal save/update flow
- The source field remains in place underneath as the summary/preview surface
- Open the editor by clicking/tapping the multiline field or preview surface itself; do not add a separate edit button beside expanded text areas unless a specific workflow needs an alternate action.

### Layout

- Full-screen overlay, edge to edge
- Field label/title at the top
- One large mono textarea filling most of the height
- Inline summary/preview surfaces should span the full width of their parent container while remaining `max-width: 100%` on mobile
- Fixed bottom action row
- Respect safe-area insets on mobile

### Buttons

- Desktop and iPad: use `btn-lg` text buttons for `Save` and `Cancel`
- iPhone: use `btn-sm` icon buttons for `Save` and `Cancel` to save space
- On iPhone, `btn-sm` actions must use glyphs, not text
- Optional field-specific extra actions may appear in the same footer row, but the standard save/cancel actions remain the anchor

### Consistency Rules

- Reuse one shared expanded-editor shell instead of inventing field-specific fullscreen editors
- Keep typography and textarea styling consistent with the underlying field
- Open the expanded editor from tapping/clicking the multiline field itself; avoid separate edit glyphs for expanded text areas.
- Treat this as the default target for multiline editing; inline typing inside cramped config panels should be the exception, not the rule

---

## Layout Components

### `.block-meta`
The header row of each block. Uses `display: flex`, `align-items: center`, `justify-content: space-between`. Left side holds the type `.pill`, right side holds `.block-header-actions` (copy, edit, delete buttons).

### `.pill`
Type label badge. `border-radius: 999px`, `background: var(--accent-soft)`, `color: var(--accent)`, `font-weight: 700`, `font-size: 0.8rem`, `text-transform: uppercase`.

### `.block`
Content block card. `padding: var(--s-5)`, `border: 1px solid var(--line)`, `border-radius: var(--s-5)`, `background: var(--panel-strong)`. Blocks are spaced with `gap: 6px` in the `.timeline` grid.

### `.timeline`
The vertical stack of blocks. `display: grid`, `gap: 6px`. Block inserters sit in between blocks with `height: 0` and overlay on hover.

### `.tree-node-row`
A project row in the tree. `display: flex`, `gap: var(--s-3)`, `padding: var(--s-2) var(--s-3)`. Contains the link (`.tree-link`, flex: 1), permission label, and action buttons in `.tree-row-right`.

---

## Lore Links

Internal links use the `lore://` protocol with standard markdown syntax. Rendered with CSS pseudo-elements:
- `.lore-link-project::before` — document emoji prefix
- `.lore-link-block::before` — link emoji prefix
- `.lore-link-broken` — red, strikethrough, `cursor: not-allowed`

---

## Responsive Breakpoint

Single breakpoint at `max-width: 860px`:
- `.layout`, `.admin-layout`, `.agents-options` collapse to single column
- `.shell` width becomes `min(100vw - 16px, 1080px)`
- Block header buttons keep 28px size
