# Cursor artwork

The PNGs in this folder are renders of the macOS cursor artwork from
[ful1e5/apple_cursor](https://github.com/ful1e5/apple_cursor) (GPL-3.0),
`macOS-White` variant (white fill, black outline — the cursor macOS shows).

- `apple-arrow.png` — `left_ptr.svg`, the default pointer
- `apple-hand.png` — `hand2.svg`, the pointing hand for links/buttons
- `apple-text.png` — `xterm.svg`, the I-beam for text fields

Rendered at 32x32 from the repo's SVGs with the color keys replaced
(`#00FF00` -> white, `#0000FF` -> black) as the repo's own `render.json`
does for its `macOS-White` theme. Hotspots measured from the renders:
arrow 9 4, hand 9 6, text 15 16.

License: GNU GPL v3 — see https://github.com/ful1e5/apple_cursor/blob/main/LICENSE
