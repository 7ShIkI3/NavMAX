"""Génère une icône .ico pour NavMAX.

Utilise PIL (Pillow) pour créer une icône multi-résolution (16×16 à 256×256)
avec un design "N" stylisé sur fond bleu.

Usage:
    python scripts/generate-icon.py [--output path/to/icon.ico]

Le script est aussi importable :
    from scripts.generate_icon import generate_ico
"""

import argparse
import io
import struct
import zlib
from pathlib import Path


def _create_png_from_pixels(pixels: list[list[tuple[int, int, int, int]]]) -> bytes:
    """Crée un fichier PNG 32bpp RGBA à partir d'une matrice de pixels."""
    height = len(pixels)
    width = len(pixels[0]) if height > 0 else 0

    signature = b"\x89PNG\r\n\x1a\n"

    # IHDR
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)  # 8-bit RGBA
    ihdr_crc = struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF)
    ihdr = struct.pack(">I", 13) + b"IHDR" + ihdr_data + ihdr_crc

    # IDAT
    raw = b""
    for row in pixels:
        raw += b"\x00"  # filter byte None
        for r, g, b, a in row:
            raw += struct.pack("BBBB", r, g, b, a)
    compressed = zlib.compress(raw)
    idat_crc = struct.pack(">I", zlib.crc32(b"IDAT" + compressed) & 0xFFFFFFFF)
    idat = struct.pack(">I", len(compressed)) + b"IDAT" + compressed + idat_crc

    # IEND
    iend_crc = struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)
    iend = struct.pack(">I", 0) + b"IEND" + iend_crc

    return signature + ihdr + idat + iend


def _make_navmax_logo(size: int) -> list[list[tuple[int, int, int, int]]]:
    """Dessine le logo NavMAX (N stylisé) dans une matrice RGBA."""
    pixels = []
    for y in range(size):
        row = []
        for x in range(size):
            cx, cy = size // 2, size // 2
            margin = max(1, size // 16)

            # Distances
            border = min(x, y, size - 1 - x, size - 1 - y)
            dist_to_center = abs(x - cx) + abs(y - cy)

            # Diagonale N : de (margin, size-1-margin) à (size-1-margin, margin)
            # Soit l'équation: y = (size-1) - x
            diag_dist = abs(x + y - (size - 1))

            # Barre verticale gauche
            left_bar = abs(x - (cx - size // 3)) if cx - size // 3 >= 0 else 999
            # Barre verticale droite
            right_bar = abs(x - (cx + size // 3)) if cx + size // 3 < size else 999
            # Barre du haut (pour le N)
            top_bar = y if y < margin + 2 else 999

            # Détermine si on est sur le bord
            on_border = x < margin or y < margin or x >= size - margin or y >= size - margin

            # Fond bleu arrondi
            corner_radius = size // 4
            dx = min(x, size - 1 - x)
            dy = min(y, size - 1 - y)
            in_corner = dx < corner_radius and dy < corner_radius
            inside_rounded = False
            if in_corner:
                # Vérifie si dans le rayon
                cx_corner = dx if dx == min(x, size - 1 - x) else size - 1 - dx
                cy_corner = dy if dy == min(y, size - 1 - y) else size - 1 - dy
                corner_x = min(x, size - 1 - x)
                corner_y = min(y, size - 1 - y)
                if corner_x**2 + corner_y**2 <= (corner_radius + 1) ** 2:
                    inside_rounded = True
            else:
                inside_rounded = True

            if on_border:
                r, g, b, a = 0, 0, 0, 0  # transparent
            elif inside_rounded and (diag_dist <= max(2, size // 24) or left_bar <= 2 or right_bar <= 2):
                # Trait du N : diagonale + barres verticales
                r, g, b, a = 0, 200, 255, 255  # cyan vif
            elif inside_rounded:
                r, g, b, a = 15, 50, 140, 235  # bleu navire foncé
            else:
                r, g, b, a = 0, 0, 0, 0  # transparent

            row.append((r, g, b, a))
        pixels.append(row)
    return pixels


def generate_ico_manual(sizes: list[int]) -> bytes:
    """Génère un fichier .ico avec plusieurs résolutions (sans PIL)."""
    # Compter les entrées
    ico_header = struct.pack("<HHH", 0, 1, len(sizes))

    png_data_list = []
    for s in sizes:
        pixels = _make_navmax_logo(s)
        png_data_list.append(_create_png_from_pixels(pixels))

    # Calculer le décalage
    offset = 6 + 16 * len(sizes)
    dir_entries = b""
    for i, s in enumerate(sizes):
        png = png_data_list[i]
        dir_entries += struct.pack(
            "<BBBBHHII",
            s if s < 256 else 0,
            s if s < 256 else 0,
            0,  # palette
            0,  # reserved
            1,  # color planes
            32,  # bits per pixel
            len(png),
            offset,
        )
        offset += len(png)

    ico_data = ico_header + dir_entries
    for png in png_data_list:
        ico_data += png

    return ico_data


def generate_ico(output_path: Path, sizes: list[int] | None = None) -> Path:
    """Génère un fichier .ico multi-résolution pour NavMAX.

    Tente d'utiliser Pillow pour une meilleure qualité. Fallback
    sur une génération manuelle PNG si Pillow n'est pas disponible.
    """
    if sizes is None:
        sizes = [16, 32, 48, 64, 128, 256]

    try:
        from PIL import Image, ImageDraw

        # Générer toutes les tailles avec PIL
        pil_images = []
        for s in sorted(set(sizes)):
            img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)

            margin = max(1, s // 16)
            radius = s // 4

            # Fond : rectangle arrondi bleu foncé
            draw.rounded_rectangle(
                [margin, margin, s - margin - 1, s - margin - 1],
                radius=radius,
                fill=(15, 50, 140, 235),
                outline=(0, 180, 255, 255),
                width=max(1, s // 32),
            )

            c = s // 2
            bar_offset = s // 3
            bar_width = max(2, s // 16)

            # Barre verticale gauche du N
            draw.rectangle(
                [c - bar_offset - bar_width // 2, margin + 2,
                 c - bar_offset + bar_width // 2, s - margin - 2],
                fill=(0, 200, 255, 255),
            )

            # Barre verticale droite du N
            draw.rectangle(
                [c + bar_offset - bar_width // 2, margin + 2,
                 c + bar_offset + bar_width // 2, s - margin - 2],
                fill=(0, 200, 255, 255),
            )

            # Diagonale du N
            diag_width = max(2, s // 12)
            draw.line(
                [(c - bar_offset, margin + 2), (c + bar_offset, s - margin - 2)],
                fill=(0, 200, 255, 255),
                width=diag_width,
            )

            pil_images.append(img)

        # Sauvegarder comme ICO multi-résolution
        # Pillow ne supporte pas nativement append_images pour ICO,
        # donc on construit le fichier manuellement
        ico_data = _ico_from_pil_images(pil_images)
        output_path.write_bytes(ico_data)

    except ImportError:
        # Fallback sans PIL
        ico_data = generate_ico_manual(sizes)
        output_path.write_bytes(ico_data)

    return output_path


def _ico_from_pil_images(images: list) -> bytes:
    """Convertit une liste d'images PIL en fichier .ico."""
    png_data_list = []
    for img in images:
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        png_data_list.append(buf.getvalue())

    sizes = [(im.width, im.height) for im in images]
    ico_header = struct.pack("<HHH", 0, 1, len(images))

    offset = 6 + 16 * len(images)
    dir_entries = b""
    for i, (w, h) in enumerate(sizes):
        png = png_data_list[i]
        dir_entries += struct.pack(
            "<BBBBHHII",
            w if w < 256 else 0,
            h if h < 256 else 0,
            0,  # palette colors
            0,  # reserved
            1,  # color planes
            32,  # bits per pixel
            len(png),
            offset,
        )
        offset += len(png)

    ico_data = ico_header + dir_entries
    for png in png_data_list:
        ico_data += png
    return ico_data


def main() -> None:
    parser = argparse.ArgumentParser(description="Génère l'icône NavMAX (.ico multi-résolution)")
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=Path(__file__).parent / "navmax.ico",
        help="Chemin du fichier .ico de sortie",
    )
    args = parser.parse_args()

    output = generate_ico(args.output)
    size_kb = output.stat().st_size / 1024
    print(f"✓ Icône générée : {output} ({size_kb:.1f} KiB)")


if __name__ == "__main__":
    main()
