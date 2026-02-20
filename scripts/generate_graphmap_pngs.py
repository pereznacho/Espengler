#!/usr/bin/env python3
"""
Genera PNGs para static/images/graphmap/ a partir de los SVG o dibujándolos con PIL.
- Con cairosvg instalado (pip install cairosvg; en Mac: brew install cairo pango): los PNG
  se generan desde los SVG y los logos se ven perfectos (Ubuntu, Debian, Tux, etc.).
- Sin cairosvg: se usan dibujos PIL mejorados (reconocibles pero simplificados).
Ejecutar desde la raíz del proyecto: python3 scripts/generate_graphmap_pngs.py
"""
import os
import sys

SIZE = 256

def generate_with_pil(graphmap_dir):
    """Genera iconos con PIL (sin cairosvg)."""
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        return False
    icons = {
        'windows': lambda d, s: _draw_windows(d, s),
        'linux': lambda d, s: _draw_linux(d, s),
        'ubuntu': lambda d, s: _draw_ubuntu(d, s),
        'debian': lambda d, s: _draw_debian(d, s),
        'kali': lambda d, s: _draw_kali(d, s),
        'arch': lambda d, s: _draw_arch(d, s),
        'fedora': lambda d, s: _draw_fedora(d, s),
        'redhat': lambda d, s: _draw_redhat(d, s),
        'macos': lambda d, s: _draw_macos(d, s),
        'android': lambda d, s: _draw_android(d, s),
        'unknown': lambda d, s: _draw_unknown(d, s),
    }
    for name, draw_fn in icons.items():
        img = Image.new('RGBA', (SIZE, SIZE), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        scale = SIZE / 32
        draw_fn(d, scale)
        path = os.path.join(graphmap_dir, name + '.png')
        img.save(path)
        print("OK (PIL):", name + '.png')
    return True

def _draw_windows(d, s):
    # 4 cuadrados azules con separación (logo Windows reconocible)
    blue = (0, 120, 212, 255)
    margin = 2 * s
    cell = 11 * s
    gap = 3 * s
    for ix in (0, 1):
        for iy in (0, 1):
            ox = margin + ix * (cell + gap)
            oy = margin + iy * (cell + gap)
            d.rectangle([ox, oy, ox + cell, oy + cell], fill=blue, outline=blue)

def _draw_ubuntu(d, s):
    # Ubuntu: círculo naranja + 3 puntos grandes (bien visibles)
    orange = (233, 84, 32, 255)
    cx, cy = 16 * s, 16 * s
    r_out = 12 * s
    stroke = max(2, min(5, int(1.5 * s)))
    d.ellipse([cx - r_out, cy - r_out, cx + r_out, cy + r_out], outline=orange, width=stroke)
    r_dot = 3.2 * s
    for dx, dy in [(0, -5.5), (-5.5, 5.5), (5.5, 5.5)]:
        px, py = cx + dx * s, cy + dy * s
        d.ellipse([px - r_dot, py - r_dot, px + r_dot, py + r_dot], fill=orange)

def _draw_linux(d, s):
    # Tux simplificado: formas grandes para que se vea el pingüino a tamaño pequeño
    dark = (51, 51, 51, 255)
    white = (255, 255, 255, 255)
    yellow = (252, 198, 36, 255)
    # Cuerpo (óvalo oscuro)
    d.ellipse([5 * s, 6 * s, 27 * s, 26 * s], fill=dark)
    # Barriga blanca (óvalo grande abajo)
    d.ellipse([9 * s, 16 * s, 23 * s, 28 * s], fill=white)
    # Cabeza
    d.ellipse([10 * s, 4 * s, 22 * s, 16 * s], fill=dark)
    # Ojos (grandes)
    d.ellipse([12 * s, 8 * s, 16 * s, 12 * s], fill=white)
    d.ellipse([16 * s, 8 * s, 20 * s, 12 * s], fill=white)
    d.ellipse([13.5 * s, 9 * s, 14.5 * s, 10 * s], fill=dark)
    d.ellipse([17.5 * s, 9 * s, 18.5 * s, 10 * s], fill=dark)
    # Pico
    d.ellipse([14 * s, 12 * s, 18 * s, 16 * s], fill=yellow)

def _draw_debian(d, s):
    # Debian: círculo rojo + un arco blanco grueso (sugiere la espiral)
    red = (168, 0, 48, 255)
    white = (255, 255, 255, 255)
    d.ellipse([2 * s, 2 * s, 30 * s, 30 * s], fill=red)
    try:
        w = max(4, min(10, int(2.5 * s)))
        d.arc([3 * s, 3 * s, 29 * s, 29 * s], 200, 340, fill=white, width=w)
    except TypeError:
        d.arc([3 * s, 3 * s, 29 * s, 29 * s], 200, 340, fill=white)

def _draw_kali(d, s):
    blue = (85, 124, 148, 255)
    d.rounded_rectangle([4*s, 4*s, 28*s, 28*s], radius=4*s, fill=blue)
    d.ellipse([10*s, 10*s, 22*s, 22*s], outline=(255, 255, 255, 220), width=int(2*s))

def _draw_arch(d, s):
    blue = (23, 147, 209, 255)
    pts = [(16*s, 4*s), (28*s, 28*s), (16*s, 24*s), (4*s, 28*s)]
    d.polygon(pts, fill=blue, outline=blue)

def _draw_fedora(d, s):
    blue = (60, 110, 180, 255)
    d.ellipse([2*s, 2*s, 30*s, 30*s], fill=blue)
    d.ellipse([10*s, 10*s, 22*s, 22*s], fill=(255, 255, 255, 180))

def _draw_redhat(d, s):
    red = (238, 0, 0, 255)
    d.ellipse([2*s, 2*s, 30*s, 30*s], fill=red)
    d.ellipse([12*s, 12*s, 20*s, 20*s], fill=(255, 255, 255, 200))

def _draw_macos(d, s):
    gray = (85, 85, 85, 255)
    d.ellipse([4*s, 4*s, 28*s, 28*s], fill=gray)

def _draw_android(d, s):
    green = (61, 220, 132, 255)
    d.rounded_rectangle([6*s, 4*s, 26*s, 28*s], radius=3*s, fill=green)
    d.ellipse([10*s, 8*s, 14*s, 12*s], fill=(255, 255, 255, 255))
    d.ellipse([18*s, 8*s, 22*s, 12*s], fill=(255, 255, 255, 255))
    d.rectangle([8*s, 16*s, 12*s, 24*s], fill=(255, 255, 255, 255))
    d.rectangle([14*s, 16*s, 18*s, 24*s], fill=(255, 255, 255, 255))
    d.rectangle([20*s, 16*s, 24*s, 24*s], fill=(255, 255, 255, 255))

def _draw_unknown(d, s):
    gray = (110, 118, 129, 255)
    d.ellipse([2*s, 2*s, 30*s, 30*s], outline=gray, width=int(2*s))
    try:
        from PIL import ImageFont
        font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", int(18*s)) if os.path.exists("/System/Library/Fonts/Helvetica.ttc") else ImageFont.load_default()
    except Exception:
        font = ImageFont.load_default()
    # Centro aproximado del "?"
    d.text((16*s - 4, 16*s - 10), "?", fill=(13, 17, 23, 255), font=font)

def main():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    graphmap = os.path.join(base, 'static', 'images', 'graphmap')
    if not os.path.isdir(graphmap):
        print("No existe:", graphmap)
        sys.exit(1)

    # 1) Intentar cairosvg (mejor calidad)
    try:
        import cairosvg
        generated = 0
        for name in os.listdir(graphmap):
            if not name.endswith('.svg'):
                continue
            svg_path = os.path.join(graphmap, name)
            png_name = name[:-4] + '.png'
            png_path = os.path.join(graphmap, png_name)
            try:
                with open(svg_path, 'rb') as f:
                    svg_bytes = f.read()
                png_bytes = cairosvg.svg2png(bytestring=svg_bytes, output_width=SIZE, output_height=SIZE)
                if png_bytes:
                    with open(png_path, 'wb') as f:
                        f.write(png_bytes)
                    print("OK (cairosvg):", png_name)
                    generated += 1
            except Exception as e:
                print("Skip", name, e)
        if generated > 0:
            return
    except ImportError:
        pass

    # 2) Fallback: generar con PIL
    print("Generando iconos con PIL (sin cairosvg)...")
    if not generate_with_pil(graphmap):
        print("Error: instala Pillow. pip install Pillow")
        sys.exit(1)

if __name__ == '__main__':
    main()
