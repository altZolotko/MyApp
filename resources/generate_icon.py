"""
Генератор иконки приложения VPN-клиент СКЗИ.
Создаёт resources/icon.ico с размерами 16, 32, 48, 64, 128, 256 пикселей.

Стиль: тёмно-зелёный фон + градиент мятно-бирюзовый (#55C69B) щит.

Запуск: python resources/generate_icon.py
"""

import os
from PIL import Image, ImageDraw


BG_COLOR  = (12, 22, 16)         # #0C1610 dark green-black
TEAL_1    = (85, 198, 155)       # #55C69B mint teal (top)
TEAL_2    = (46, 138, 98)        # #2E8A62 mid teal
TEAL_3    = (26, 82, 64)         # #1A5240 dark teal (bottom)
WHITE     = (255, 255, 255, 230)
HIGHLIGHT = (255, 255, 255, 30)  # right-edge glint


def _lerp_color(c1, c2, t):
    return tuple(int(c1[i] + (c2[i] - c1[i]) * t) for i in range(3))


def draw_icon(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    s = size
    pad = s * 0.06
    corner_r = s * 0.20

    # Rounded square background
    draw.rounded_rectangle(
        [pad, pad, s - pad, s - pad],
        radius=corner_r,
        fill=BG_COLOR + (255,),
    )

    # Shield geometry
    cx   = s / 2
    top  = s * 0.12
    mid  = s * 0.60   # where sides start converging
    bot  = s * 0.88   # bottom point
    hw   = s * 0.36   # half-width

    # Fill shield with vertical gradient
    total_h = bot - top
    for i in range(int(total_h) + 1):
        y = top + i
        t = i / total_h
        if t < 0.5:
            color = _lerp_color(TEAL_1, TEAL_2, t * 2) + (255,)
        else:
            color = _lerp_color(TEAL_2, TEAL_3, (t - 0.5) * 2) + (255,)

        if y <= mid:
            x0 = cx - hw
            x1 = cx + hw
        else:
            frac = (y - mid) / (bot - mid)
            x0 = (cx - hw) + frac * hw
            x1 = (cx + hw) - frac * hw
        if x1 > x0:
            draw.line([(x0, y), (x1, y)], fill=color)

    # Right-edge highlight glint
    for i in range(int(total_h) + 1):
        y = top + i
        t = i / total_h
        if y <= mid:
            x0 = cx + hw * 0.55
            x1 = cx + hw
        else:
            frac = (y - mid) / (bot - mid)
            x0 = cx + (hw - frac * hw) * 0.55
            x1 = cx + (hw - frac * hw)
        if x1 > x0 and x0 < x1:
            draw.line([(x0, y), (x1, y)], fill=HIGHLIGHT)

    # Lock body inside shield
    lw = s * 0.20
    lh = s * 0.17
    lx = cx - lw / 2
    ly = s * 0.52 - lh / 2
    draw.rounded_rectangle(
        [lx, ly, lx + lw, ly + lh],
        radius=s * 0.030,
        fill=WHITE,
    )

    # Lock shackle
    arc_r = lw * 0.30
    arc_box = [
        cx - arc_r, ly - arc_r * 1.1,
        cx + arc_r, ly + arc_r * 0.5,
    ]
    arc_w = max(1, int(s * 0.038))
    draw.arc(arc_box, start=200, end=340, fill=WHITE, width=arc_w)

    # Keyhole dot
    dot_r = max(1, int(s * 0.025))
    draw.ellipse(
        [cx - dot_r, ly + lh * 0.32 - dot_r,
         cx + dot_r, ly + lh * 0.32 + dot_r],
        fill=BG_COLOR + (200,),
    )

    return img


def main():
    out_dir = os.path.dirname(os.path.abspath(__file__))
    ico_path = os.path.join(out_dir, "icon.ico")
    png_path = os.path.join(out_dir, "icon.png")

    sizes = [256, 128, 64, 48, 32, 16]
    images = [draw_icon(s) for s in sizes]

    images[0].save(png_path)
    print(f"Saved PNG: {png_path}")

    images[0].save(
        ico_path,
        format="ICO",
        sizes=[(s, s) for s in sizes],
        append_images=images[1:],
    )
    print(f"Saved ICO: {ico_path}  ({len(sizes)} sizes: {sizes})")


if __name__ == "__main__":
    main()
