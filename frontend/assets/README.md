# Stage artwork

Six images drive the cinematic stage. Save them here with **exactly** these
filenames — `cinema.css` references them by name.

| Filename | Layer | Source image |
|---|---|---|
| `backdrop.webp` | Farthest back | Dark sky with the cyan glow low on the horizon |
| `skyline.webp` | Far city | Wide night skyline with dishes and masts |
| `ops-floor.webp` | Mid | Operations room, silhouetted operators at consoles |
| `monolith.webp` | Revealed by the split | Lit monolith among dark slabs |
| `core-sphere.webp` | Hero object | Wireframe globe (white background is fine — it is masked out) |
| `pylons.webp` | Foreground | Two structural pylons framing a black centre |

## Notes

`core-sphere.webp` arrived on a white background. Rather than ask for a re-cut,
the stylesheet masks it to a circle and composites it with `screen`, so the
white never reaches the page. That does mean the sphere must stay centred in
the frame — a re-crop that shifts it will show a clipped edge.

The other five are near-black already and composite with `lighten`, so their
black backgrounds merge into the stage instead of showing as rectangles. Each
also carries a soft edge mask, so none of them ends on a visible hard line.

If a file is missing the layer simply renders empty; the stage still works.

## Format

The page loads **WebP**; the PNG masters sit beside them and are gitignored.
Converting cut the set from 8403 KB to 497 KB — 6% of the original — for a
mean per-pixel difference under 2.5/255, which is not visible. Re-encode with
quality 90 and method 6 if you replace an image:

```
from PIL import Image
Image.open("new.png").save("new.webp", "WEBP", quality=90, method=6)
```

Quality matters more than usual here: these are dark gradients, where cheap
encoding shows as banding, and `lighten` blending amplifies exactly that.

## Original format note

All six are PNG. That is lossless, which matters more than usual here: these
are very dark images with long, subtle gradients, and JPEG blocking shows up
badly in near-black — `mix-blend-mode: lighten` then amplifies exactly those
artefacts, because it keeps whichever pixel is brighter.

The cost is file size. If the stage feels slow to paint, convert the five
photographic layers to WebP (keep `core-sphere.webp` as PNG for its mask) and
update the URLs in `cinema.css`. WebP keeps the gradient quality and is
typically a fifth of the size.
