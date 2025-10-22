import math
import struct
import zlib
from pathlib import Path

DARK = (7, 18, 28, 255)
MID = (13, 34, 44, 255)
GREEN = (123, 224, 74, 255)
LIGHT = (228, 255, 235, 255)

OUTPUTS = [
    ("assets/bugbash_logo.png", 512),
    ("assets/apple-touch-icon.png", 180),
    ("assets/favicon-192.png", 192),
    ("assets/favicon-48.png", 48),
    ("assets/favicon-32.png", 32),
    ("assets/favicon-16.png", 16)
]

ACCENT = (123, 224, 74, 220)

BASE_SIZE = 512
ROW_STRIDE = BASE_SIZE * 4 + 1
pixels = bytearray(ROW_STRIDE * BASE_SIZE)

for y in range(BASE_SIZE):
    pixels[y * ROW_STRIDE] = 0
    for x in range(BASE_SIZE):
        idx = y * ROW_STRIDE + 1 + x * 4
        ratio = y / (BASE_SIZE - 1)
        r = int(DARK[0] * (1 - ratio) + MID[0] * ratio)
        g = int(DARK[1] * (1 - ratio) + MID[1] * ratio)
        b = int(DARK[2] * (1 - ratio) + MID[2] * ratio)
        pixels[idx:idx+4] = bytes((r, g, b, 255))

def clamp(v, lo, hi):
    return max(lo, min(hi, v))

def set_pixel(x, y, color):
    if 0 <= x < BASE_SIZE and 0 <= y < BASE_SIZE:
        idx = y * ROW_STRIDE + 1 + x * 4
        pixels[idx:idx+4] = bytes(color)

def draw_rect(x0, y0, x1, y1, color):
    x0, y0, x1, y1 = map(int, (x0, y0, x1, y1))
    for y in range(y0, y1):
        base = y * ROW_STRIDE + 1 + x0 * 4
        for x in range(x0, x1):
            pixels[base:base+4] = bytes(color)
            base += 4

def draw_round_rect(x0, y0, x1, y1, radius, color):
    radius = int(radius)
    for y in range(int(y0), int(y1)):
        for x in range(int(x0), int(x1)):
            dx = min(x - x0, x1 - 1 - x, radius)
            dy = min(y - y0, y1 - 1 - y, radius)
            if dx < radius and dy < radius:
                if (radius - dx) ** 2 + (radius - dy) ** 2 > radius ** 2:
                    continue
            # add subtle glow overlay
            if color == GREEN and radius > 0:
                mix = 0.12
                r = int(color[0] * (1 - mix) + LIGHT[0] * mix)
                g = int(color[1] * (1 - mix) + LIGHT[1] * mix)
                b = int(color[2] * (1 - mix) + LIGHT[2] * mix)
                set_pixel(x, y, (r, g, b, color[3]))
            else:
                set_pixel(x, y, color)

def draw_circle(cx, cy, r, color):
    r_sq = r * r
    for y in range(int(cy - r), int(cy + r) + 1):
        for x in range(int(cx - r), int(cx + r) + 1):
            if (x - cx) ** 2 + (y - cy) ** 2 <= r_sq:
                set_pixel(x, y, color)

# Draw bug outline and details
body_outer = (BASE_SIZE * 0.32, BASE_SIZE * 0.12, BASE_SIZE * 0.68, BASE_SIZE * 0.82)
body_inner = (BASE_SIZE * 0.36, BASE_SIZE * 0.17, BASE_SIZE * 0.64, BASE_SIZE * 0.78)

x0, y0, x1, y1 = body_outer
draw_round_rect(x0, y0, x1, y1, BASE_SIZE * 0.08, DARK)

x0, y0, x1, y1 = body_inner
draw_round_rect(x0, y0, x1, y1, BASE_SIZE * 0.08, GREEN)

# Top head plate
head = (BASE_SIZE * 0.4, BASE_SIZE * 0.04, BASE_SIZE * 0.6, BASE_SIZE * 0.22)
draw_round_rect(*head, BASE_SIZE * 0.04, DARK)
head_inner = (BASE_SIZE * 0.43, BASE_SIZE * 0.07, BASE_SIZE * 0.57, BASE_SIZE * 0.2)
draw_round_rect(*head_inner, BASE_SIZE * 0.04, GREEN)

# Eyes
draw_rect(BASE_SIZE*0.46, BASE_SIZE*0.23, BASE_SIZE*0.49, BASE_SIZE*0.26, DARK)
draw_rect(BASE_SIZE*0.51, BASE_SIZE*0.23, BASE_SIZE*0.54, BASE_SIZE*0.26, DARK)

# Mouth / crease
draw_rect(BASE_SIZE*0.49, BASE_SIZE*0.26, BASE_SIZE*0.51, BASE_SIZE*0.34, DARK)
draw_rect(BASE_SIZE*0.49, BASE_SIZE*0.34, BASE_SIZE*0.53, BASE_SIZE*0.36, DARK)

draw_rect(BASE_SIZE*0.48, BASE_SIZE*0.34, BASE_SIZE*0.49, BASE_SIZE*0.46, DARK)

# Antennae
draw_round_rect(BASE_SIZE*0.38, BASE_SIZE*0.0, BASE_SIZE*0.44, BASE_SIZE*0.09, BASE_SIZE*0.02, DARK)
draw_round_rect(BASE_SIZE*0.56, BASE_SIZE*0.0, BASE_SIZE*0.62, BASE_SIZE*0.09, BASE_SIZE*0.02, DARK)

draw_rect(BASE_SIZE*0.32, BASE_SIZE*0.18, BASE_SIZE*0.36, BASE_SIZE*0.28, DARK)
draw_rect(BASE_SIZE*0.64, BASE_SIZE*0.18, BASE_SIZE*0.68, BASE_SIZE*0.28, DARK)

draw_rect(BASE_SIZE*0.32, BASE_SIZE*0.34, BASE_SIZE*0.36, BASE_SIZE*0.44, DARK)
draw_rect(BASE_SIZE*0.64, BASE_SIZE*0.34, BASE_SIZE*0.68, BASE_SIZE*0.44, DARK)

draw_rect(BASE_SIZE*0.32, BASE_SIZE*0.52, BASE_SIZE*0.36, BASE_SIZE*0.62, DARK)
draw_rect(BASE_SIZE*0.64, BASE_SIZE*0.52, BASE_SIZE*0.68, BASE_SIZE*0.62, DARK)

# Legs
draw_rect(BASE_SIZE*0.22, BASE_SIZE*0.28, BASE_SIZE*0.32, BASE_SIZE*0.34, DARK)
draw_rect(BASE_SIZE*0.68, BASE_SIZE*0.28, BASE_SIZE*0.78, BASE_SIZE*0.34, DARK)

draw_rect(BASE_SIZE*0.22, BASE_SIZE*0.44, BASE_SIZE*0.32, BASE_SIZE*0.5, DARK)
draw_rect(BASE_SIZE*0.68, BASE_SIZE*0.44, BASE_SIZE*0.78, BASE_SIZE*0.5, DARK)

draw_rect(BASE_SIZE*0.22, BASE_SIZE*0.6, BASE_SIZE*0.32, BASE_SIZE*0.66, DARK)
draw_rect(BASE_SIZE*0.68, BASE_SIZE*0.6, BASE_SIZE*0.78, BASE_SIZE*0.66, DARK)

# Bitmap font for block lettering
FONT = {
    "A": [
        "0011100",
        "0100010",
        "1000001",
        "1000001",
        "1111111",
        "1000001",
        "1000001",
        "1000001",
        "0000000",
    ],
    "B": [
        "1111100",
        "1000010",
        "1000010",
        "1111100",
        "1000010",
        "1000010",
        "1000010",
        "1111100",
        "0000000",
    ],
    "C": [
        "0011110",
        "0100000",
        "1000000",
        "1000000",
        "1000000",
        "1000000",
        "0100000",
        "0011110",
        "0000000",
    ],
    "D": [
        "1111000",
        "1000100",
        "1000010",
        "1000010",
        "1000010",
        "1000010",
        "1000100",
        "1111000",
        "0000000",
    ],
    "E": [
        "1111110",
        "1000000",
        "1000000",
        "1111100",
        "1000000",
        "1000000",
        "1000000",
        "1111110",
        "0000000",
    ],
    "G": [
        "0011110",
        "0100000",
        "1000000",
        "1000000",
        "1001110",
        "1000010",
        "0100010",
        "0011110",
        "0000000",
    ],
    "H": [
        "1000001",
        "1000001",
        "1000001",
        "1111111",
        "1000001",
        "1000001",
        "1000001",
        "1000001",
        "0000000",
    ],
    "I": [
        "1111111",
        "0001000",
        "0001000",
        "0001000",
        "0001000",
        "0001000",
        "0001000",
        "1111111",
        "0000000",
    ],
    "K": [
        "1000001",
        "1000010",
        "1000100",
        "1001000",
        "1110000",
        "1001000",
        "1000100",
        "1000010",
        "0000000",
    ],
    "L": [
        "1000000",
        "1000000",
        "1000000",
        "1000000",
        "1000000",
        "1000000",
        "1000000",
        "1111111",
        "0000000",
    ],
    "R": [
        "1111100",
        "1000010",
        "1000010",
        "1111100",
        "1001000",
        "1000100",
        "1000010",
        "1000001",
        "0000000",
    ],
    "S": [
        "0111110",
        "1000000",
        "1000000",
        "0111100",
        "0000010",
        "0000010",
        "0000010",
        "1111100",
        "0000000",
    ],
    "U": [
        "1000001",
        "1000001",
        "1000001",
        "1000001",
        "1000001",
        "1000001",
        "0100010",
        "0011100",
        "0000000",
    ],
    " ": [
        "0000000",
        "0000000",
        "0000000",
        "0000000",
        "0000000",
        "0000000",
        "0000000",
        "0000000",
        "0000000",
    ],
    "-": [
        "0000000",
        "0000000",
        "0000000",
        "0111110",
        "0111110",
        "0000000",
        "0000000",
        "0000000",
        "0000000",
    ],
}

def draw_char(ch, x, y, size, color):
    pattern = FONT.get(ch.upper())
    if not pattern:
        pattern = FONT[" "]
    rows = len(pattern)
    cols = len(pattern[0])
    for row in range(rows):
        for col in range(cols):
            if pattern[row][col] == "1":
                x0 = int(x + col * size)
                y0 = int(y + row * size)
                draw_rect(x0, y0, x0 + size, y0 + size, color)

def draw_text(text, x, y, size, color, spacing=2):
    cursor = x
    for ch in text:
        pattern = FONT.get(ch.upper(), FONT[" "])
        cols = len(pattern[0])
        draw_char(ch, cursor, y, size, color)
        cursor += cols * size + spacing

title_text = "BUG BASH"
tag_text = "HACK-BREAK-BUILD"

# Title baseline positions
text_size = int(BASE_SIZE * 0.035)
text_width = (
    sum((len(FONT.get(ch.upper(), FONT[" "])[0]) * text_size + text_size) for ch in title_text)
    - text_size
)
start_x = (BASE_SIZE - text_width) // 2
start_y = int(BASE_SIZE * 0.88)
draw_text(title_text, start_x, start_y, text_size, DARK, spacing=int(text_size * 0.3))

sub_size = int(BASE_SIZE * 0.022)
sub_width = (
    sum((len(FONT.get(ch.upper(), FONT[" "])[0]) * sub_size + sub_size) for ch in tag_text)
    - sub_size
)
sub_x = (BASE_SIZE - sub_width) // 2
sub_y = int(BASE_SIZE * 0.95)
draw_text(tag_text, sub_x, sub_y, sub_size, DARK, spacing=int(sub_size * 0.4))


# Encode PNG
def write_png(path, buf, size):
    w = h = size
    if size != BASE_SIZE:
        scaled = bytearray((size * 4 + 1) * size)
        for y in range(size):
            scaled[y * (size * 4 + 1)] = 0
            src_y = int(y * BASE_SIZE / size)
            for x in range(size):
                src_x = int(x * BASE_SIZE / size)
                src_idx = src_y * ROW_STRIDE + 1 + src_x * 4
                dst_idx = y * (size * 4 + 1) + 1 + x * 4
                scaled[dst_idx:dst_idx+4] = buf[src_idx:src_idx+4]
        raw = bytes(scaled)
        stride = size * 4 + 1
    else:
        raw = bytes(buf)
        stride = ROW_STRIDE

    compressor = zlib.compressobj()
    compressed = compressor.compress(raw) + compressor.flush()
    png = bytearray()
    png.extend(b"\x89PNG\r\n\x1a\n")
    def chunk(tag, data):
        png.extend(struct.pack('>I', len(data)))
        png.extend(tag)
        png.extend(data)
        crc = zlib.crc32(tag)
        crc = zlib.crc32(data, crc) & 0xffffffff
        png.extend(struct.pack('>I', crc))
    ihdr = struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0)
    chunk(b'IHDR', ihdr)
    chunk(b'IDAT', compressed)
    chunk(b'IEND', b'')
    Path(path).write_bytes(png)

for dest, size in OUTPUTS:
    write_png(dest, pixels, size)

print("Generated logo assets.")
