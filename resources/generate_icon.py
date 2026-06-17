"""
Генератор иконки приложения VPN Gov.
Создаёт resources/icon.ico с размерами 16, 32, 48, 64, 128, 256 пикселей.

Запуск: python resources/generate_icon.py
"""

import os
import math
from PIL import Image, ImageDraw, ImageFont


# Цвета темы "Pulse"
BG_COLOR      = (13, 13, 15)        # #0d0d0f
ACCENT_1      = (255, 107, 53)      # #FF6B35 (orange)
ACCENT_2      = (232, 76, 76)       # #E84C4C (red)
WHITE         = (255, 255, 255)
WHITE_80      = (255, 255, 255, 204)


def _lerp_color(c1, c2, t):
    return tuple(int(c1[i] + (c2[i] - c1[i]) * t) for i in range(3))


def draw_icon(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    s = size
    pad = s * 0.06
    r = s * 0.18  # corner radius for background

    # --- Background: rounded square with dark color ---
    draw.rounded_rectangle(
        [pad, pad, s - pad, s - pad],
        radius=r,
        fill=BG_COLOR + (255,),
    )

    # --- Shield shape ---
    # Shield: a polygon approximating a classic shield
    cx = s / 2
    top = s * 0.14
    bottom = s * 0.86
    hw = s * 0.34   # half-width at top

    # Draw gradient by stacking horizontal lines inside the shield bounding box
    shield_pts = [
        (cx - hw, top),
        (cx + hw, top),
        (cx + hw, s * 0.60),
        (cx,      bottom),
        (cx - hw, s * 0.60),
    ]

    # Draw filled shield with gradient (simulate by drawing slices)
    shield_height = bottom - top
    num_slices = int(shield_height) + 1
    for i in range(num_slices):
        y = top + i
        t = i / shield_height
        color = _lerp_color(ACCENT_1, ACCENT_2, t) + (255,)
        # Compute x bounds at this y
        if y <= s * 0.60:
            x0 = cx - hw
            x1 = cx + hw
        else:
            frac = (y - s * 0.60) / (bottom - s * 0.60)
            x0 = (cx - hw) + frac * hw
            x1 = (cx + hw) - frac * hw
        if x1 > x0:
            draw.line([(x0, y), (x1, y)], fill=color)

    # --- Lock icon inside shield ---
    lw = s * 0.18   # lock body width
    lh = s * 0.16   # lock body height
    lx = cx - lw / 2
    ly = s * 0.52 - lh / 2

    # Lock body
    draw.rounded_rectangle(
        [lx, ly, lx + lw, ly + lh],
        radius=s * 0.03,
        fill=WHITE + (230,),
    )

    # Lock shackle (arc on top)
    arc_r = lw * 0.30
    arc_cx = cx
    arc_cy = ly
    arc_box = [
        arc_cx - arc_r, arc_cy - arc_r * 1.1,
        arc_cx + arc_r, arc_cy + arc_r * 0.5,
    ]
    arc_w = max(1, int(s * 0.04))
    draw.arc(arc_box, start=200, end=340, fill=WHITE + (230,), width=arc_w)

    # Keyhole dot
    dot_r = max(1, int(s * 0.025))
    draw.ellipse(
        [cx - dot_r, ly + lh * 0.35 - dot_r,
         cx + dot_r, ly + lh * 0.35 + dot_r],
        fill=BG_COLOR + (200,),
    )

    return img


def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))
    ico_path = os.path.join(out_dir, "icon.ico")
    png_path = os.path.join(out_dir, "icon.png")

    sizes = [256, 128, 64, 48, 32, 16]
    images = [draw_icon(s) for s in sizes]

    # Save PNG (largest size) for reference
    images[0].save(png_path)
    print(f"Saved PNG: {png_path}")

    # Save ICO with all sizes
    images[0].save(
        ico_path,
        format="ICO",
        sizes=[(s, s) for s in sizes],
        append_images=images[1:],
    )
    print(f"Saved ICO: {ico_path}  ({len(sizes)} sizes: {sizes})")


if __name__ == "__main__":
    main()
