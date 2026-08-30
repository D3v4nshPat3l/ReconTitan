# ReconTitan design system

Extracted from the reference site (agiloft.com) by reading its live computed
styles and CSS custom properties, then adapted to ReconTitan's content and
constraints.

**What was taken:** the design *language* — type scale, colour relationships,
spacing rhythm, the sharp-cornered geometry, the alternating section pattern.

**What was not taken:** the reference's fonts (proprietary), logo, imagery,
copy, or page structure. Everything here is rebuilt with free typefaces and
ReconTitan's own words. This is a design system in the same idiom, not a clone.

---

## 1. The idea in one line

**Editorial restraint over technical noise.** A very large, very light serif
headline set on a black field; everything under it quiet, sharp-cornered and
precisely aligned. Colour is withheld until it means something.

That suits a scanner. The findings are the loud part; the interface around them
should not compete.

---

## 2. Typography

The reference pairs a light display serif with a neo-grotesque body face. Both
are licensed, so each is replaced with the closest free equivalent — both were
already loaded by this project.

| Role | Reference | Ours | Why it matches |
|---|---|---|---|
| Display | Teodor Light (200) | **Instrument Serif** | High-contrast modern serif, same open apertures, reads light at display sizes |
| Body | Messina Sans (400) | **Inter** | Neo-grotesque with the same neutral, slightly narrow character |
| Data | — | **JetBrains Mono** | Added for targets, logs and evidence — a security tool needs unambiguous `0`/`O`, `1`/`l` |

### Scale

Taken verbatim from the reference's `--_typography---heading-size--*` tokens:

```
h1   4.625rem   74px      display serif, weight 400, tracking −0.02em
h2   4rem       64px
h3   3.5rem     56px
h4   3rem       48px
h5   1.5rem     24px
h6   1.375rem   22px

body large     1.25rem
body medium    1.125rem
body regular   1rem       ← base
body small     0.875rem
body tiny      0.75rem
```

Two rules carried over from the reference, and they matter more than the numbers:

- **Display type is set tight.** Line-height `1.05`, letter-spacing `−0.02em`.
  A 74px headline at default line-height looks like a mistake.
- **Body type is set loose.** Line-height `1.6`, measure capped at ~70
  characters. The reference caps its text columns at `740px`.

---

## 3. Colour

Sampled from the reference's painted surfaces, with ReconTitan's severity
palette kept deliberately separate.

### Surfaces and ink

```
--paper        #ffffff    default page
--cream        #f6f3ea    alternating section
--cream-deep   #edeae1    insets, table headers
--ink          #0d0d0d    body text, primary buttons
--black        #000000    the hero field
--slate        #141c25    the one dark section below the fold
--line         #dedede    1px borders
--muted        #606060    secondary text
--faint        #979797    tertiary, timestamps
```

### Accent

```
--accent        #ee7501    blaze orange
--accent-hover  #f9922f
```

**One accent, used sparingly.** In the reference it appears on a thin
announcement bar, secondary buttons, and small marks — never as a field.

### Severity — deliberately not the accent

A scanner cannot spend its only strong colour on decoration. Severity keeps its
own scale, and orange is reserved for *interface* emphasis:

```
--sev-critical  #b42318
--sev-high      #d92d20
--sev-medium    #b54708
--sev-low       #175cd3
--sev-info      #606060
```

`--sev-medium` sits near the accent on purpose — medium severity *is* a caution
state. Critical and high stay red so they never read as "just an accent".

---

## 4. Geometry

The single most recognisable trait of the reference:

```
--radius: 0
```

**Nothing is rounded.** Not buttons, not inputs, not cards. Every rounded
corner in the old ReconTitan interface is removed. Combined with hairline
`1px` borders, this is what makes the design read as considered rather than
templated.

```
--border: 1px solid var(--line)
```

### Spacing

An 8px base, matching the reference's rhythm:

```
4 · 8 · 12 · 16 · 24 · 32 · 48 · 64 · 96 · 128
```

### Containers

```
--wide     1440px    full-bleed sections
--shell    1232px    default content width
--narrow    740px    text columns — the measure cap
```

---

## 5. Section rhythm

The reference alternates section backgrounds down the page rather than relying
on borders or shadows to separate them:

```
black  →  white  →  cream  →  slate  →  white  →  black
```

Applied here:

| Section | Surface | Why |
|---|---|---|
| Hero | `--black` | The display headline needs a field, not a background |
| Scanner | `--paper` | The working surface. Maximum legibility |
| What it checks | `--cream` | Reading section — warmer, lower contrast |
| Danger Mode | `--slate` | Its own dark band. The visual weight is the warning |
| Feed | `--paper` | Back to neutral for scannable cards |
| Footer | `--black` | Closes the frame the hero opened |

Sections carry their own vertical padding (`96px` desktop, `64px` mobile);
there are no margins between them.

---

## 6. Components

### Buttons

Flat, sharp, no shadow. From the reference's computed styles: `0px` radius,
`1px` border, weight 400.

```
Primary     ink background,    paper text
Secondary   accent background, ink text
Ghost       transparent,       1px border, ink text
```

### Inputs

Sharp corners, 1px border, focus is a **2px accent outline** rather than a glow.
The target field uses the mono face — a domain is data, not prose.

### Cards

`1px` border, no radius, no shadow. Separation comes from the border and the
surface change, never from elevation.

---

## 7. Motion

The reference animates on scroll but never gratuitously. Applied here:

- Section content fades up `12px` on entry, `400ms`, once
- Hover transitions `150ms`
- The scan progress bar animates width only
- **Everything is disabled under `prefers-reduced-motion`**

The previous cinematic hero — a ~16,000px scroll-driven stage — is removed. It
made the scanner, the actual product, unreachable without a long scroll, and it
could not be screenshotted or linked to.

---

## 8. Accessibility

- Body text `#0d0d0d` on `#ffffff` — **19.2:1**
- Muted text `#606060` on `#ffffff` — **6.6:1**
- Accent `#ee7501` is used for **fills and marks, not for text on white**
  (3.1:1, below AA). Where it must carry text, it sits behind `--ink`.
- Focus is always visible: 2px accent outline, 2px offset
- Severity is never encoded by colour alone — every badge carries its label
