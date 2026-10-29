#!/usr/bin/env python3
"""Draws the DLB icon (32x32 pixel art, in the spirit of 90s desktop shells) and writes every
size the platforms need into ../branding/. Needs Pillow; the results are committed, so CI and
`scripts/setup.sh` do not run this. Run it only after changing the artwork:

    python3 tools/make_icons.py
"""
import os
import shutil
import struct
import sys

from PIL import Image

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "branding")

P = {
    "bg": (0x12, 0x35, 0x24),
    "hi": (0x2F, 0x6B, 0x4A),
    "lo": (0x0A, 0x1F, 0x15),
    "K": (0x0B, 0x0B, 0x0B),
    "Y": (0xE8, 0xB8, 0x4A),
    "L": (0xFA, 0xE3, 0x9A),
    "O": (0xB0, 0x7E, 0x1F),
    "T": (0x7A, 0x54, 0x10),
    "W": (0xF4, 0xF4, 0xF4),
    "S": (0x9A, 0xA4, 0xAE),
    "R": (0xD8, 0x42, 0x3B),
    "r": (0xF2, 0x8A, 0x80),
    "D": (0x8E, 0x24, 0x20),
    "P": (0xFF, 0xFF, 0xFF),
}


def sprite():
    """The box with a zipper, on a transparent 32x32 canvas."""
    g = [[None] * 32 for _ in range(32)]

    def rect(x0, y0, x1, y1, c):
        for y in range(y0, y1 + 1):
            for x in range(x0, x1 + 1):
                g[y][x] = P[c]

    def frame(x0, y0, x1, y1, c="K"):
        for x in range(x0, x1 + 1):
            g[y0][x] = P[c]
            g[y1][x] = P[c]
        for y in range(y0, y1 + 1):
            g[y][x0] = P[c]
            g[y][x1] = P[c]

    # ground shadow
    rect(7, 28, 26, 28, "lo")
    # body
    rect(6, 13, 25, 26, "Y")
    rect(6, 13, 25, 13, "O")          # shade under the lid
    rect(25, 14, 25, 26, "O")         # right side shade
    rect(6, 26, 25, 26, "O")          # bottom shade
    rect(6, 14, 6, 25, "L")           # left light edge
    frame(5, 12, 26, 27)
    # lid
    rect(5, 8, 26, 11, "Y")
    rect(5, 8, 26, 8, "L")
    rect(5, 8, 5, 11, "L")
    rect(26, 9, 26, 11, "O")
    rect(5, 11, 26, 11, "O")
    frame(4, 7, 27, 12)
    # label
    rect(8, 17, 13, 22, "W")
    frame(7, 16, 14, 23)
    rect(9, 18, 12, 18, "S")
    rect(9, 20, 12, 20, "S")
    rect(9, 22, 11, 22, "S")
    # zipper tape and teeth, running through the lid and down the body
    rect(14, 8, 17, 22, "T")
    for y in range(8, 23):
        a, b = ("W", "S") if y % 2 == 0 else ("S", "W")
        g[y][15] = P[a]
        g[y][16] = P[b]
    # slider
    rect(14, 21, 17, 24, "R")
    rect(14, 21, 17, 21, "r")
    rect(14, 21, 14, 24, "r")
    rect(17, 22, 17, 24, "D")
    frame(13, 20, 18, 25)
    # pull tab
    rect(15, 26, 16, 26, "R")
    return g


def tile(g):
    """The sprite on a bevelled dark-green tile with chipped corners."""
    t = [[P["bg"] for _ in range(32)] for _ in range(32)]
    for i in range(32):
        t[0][i] = P["hi"]
        t[i][0] = P["hi"]
        t[31][i] = P["lo"]
        t[i][31] = P["lo"]
    t[0][31] = P["lo"]
    t[31][0] = P["hi"]
    for y in range(32):
        for x in range(32):
            if g[y][x] is not None:
                t[y][x] = g[y][x]
    out = [[(*c, 255) for c in row] for row in t]
    for (x, y) in [(0, 0), (1, 0), (0, 1), (31, 0), (30, 0), (31, 1),
                   (0, 31), (1, 31), (0, 30), (31, 31), (30, 31), (31, 30)]:
        out[y][x] = (0, 0, 0, 0)
    return out


def to_image(px):
    im = Image.new("RGBA", (32, 32))
    for y in range(32):
        for x in range(32):
            c = px[y][x]
            im.putpixel((x, y), (*c[:3], c[3] if len(c) > 3 else 255) if c else (0, 0, 0, 0))
    return im


def up(im, size):
    return im.resize((size, size), Image.NEAREST)


def save(im, *parts):
    p = os.path.join(OUT, *parts)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    im.save(p)


def main():
    if os.path.isdir(OUT):
        shutil.rmtree(OUT)
    spr = sprite()
    full = to_image(tile(spr))
    sp_img = to_image(spr)

    for s in (16, 32, 48, 64, 128, 256, 512, 1024):
        save(up(full, s), "png", f"icon-{s}.png")
    save(up(full, 256), "linux", "dlb.png")

    # Windows .ico (PNG-compressed entries)
    sizes = [16, 24, 32, 48, 64, 128, 256]
    up(full, 256).save(os.path.join(OUT, "app_icon.ico"), sizes=[(s, s) for s in sizes])

    # macOS AppIcon.appiconset file names used by the Flutter template
    for s in (16, 32, 64, 128, 256, 512, 1024):
        save(up(full, s), "macos", f"app_icon_{s}.png")

    # Android: legacy square icons + adaptive icon (foreground on a flat colour) + themed icon
    legacy = {"mdpi": 48, "hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192}
    for d, s in legacy.items():
        save(up(full, s), "android", f"mipmap-{d}", "ic_launcher.png")
    fg = {"mdpi": 108, "hdpi": 162, "xhdpi": 216, "xxhdpi": 324, "xxxhdpi": 432}
    for d, s in fg.items():
        canvas = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        inner = int(round(s * 0.62))           # stays inside the 66 % safe zone
        art = sp_img.resize((inner, inner), Image.NEAREST)
        canvas.alpha_composite(art, ((s - inner) // 2, (s - inner) // 2))
        save(canvas, "android", f"drawable-{d}", "ic_launcher_foreground.png")
        mono = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        for y in range(s):
            for x in range(s):
                if canvas.getpixel((x, y))[3]:
                    mono.putpixel((x, y), (255, 255, 255, 255))
        save(mono, "android", f"drawable-{d}", "ic_launcher_monochrome.png")
    adaptive = os.path.join(OUT, "android", "mipmap-anydpi-v26", "ic_launcher.xml")
    os.makedirs(os.path.dirname(adaptive), exist_ok=True)
    with open(adaptive, "w") as f:
        f.write('<?xml version="1.0" encoding="utf-8"?>\n'
                '<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
                '    <background android:drawable="@color/dlb_icon_background"/>\n'
                '    <foreground android:drawable="@drawable/ic_launcher_foreground"/>\n'
                '    <monochrome android:drawable="@drawable/ic_launcher_monochrome"/>\n'
                '</adaptive-icon>\n')
    colors = os.path.join(OUT, "android", "values", "dlb_icon_colors.xml")
    os.makedirs(os.path.dirname(colors), exist_ok=True)
    with open(colors, "w") as f:
        f.write('<?xml version="1.0" encoding="utf-8"?>\n<resources>\n'
                '    <color name="dlb_icon_background">#123524</color>\n</resources>\n')

    # SVG (one <rect> per pixel run) for the README / web
    px = tile(spr)
    rects = []
    for y in range(32):
        x = 0
        while x < 32:
            c = px[y][x]
            if c[3] == 0:
                x += 1
                continue
            x2 = x
            while x2 + 1 < 32 and px[y][x2 + 1] == c:
                x2 += 1
            rects.append(f'<rect x="{x}" y="{y}" width="{x2 - x + 1}" height="1" '
                         f'fill="#{c[0]:02x}{c[1]:02x}{c[2]:02x}"/>')
            x = x2 + 1
    with open(os.path.join(OUT, "dlb.svg"), "w") as f:
        f.write('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" '
                'shape-rendering="crispEdges" width="256" height="256">\n'
                + "\n".join(rects) + "\n</svg>\n")
    print("icons written to", os.path.normpath(OUT))


if __name__ == "__main__":
    sys.exit(main())
