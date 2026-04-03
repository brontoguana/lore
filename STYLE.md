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
