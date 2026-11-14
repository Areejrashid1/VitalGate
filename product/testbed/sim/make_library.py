"""Builds a small library of synthetic DICOM images at image-build time (no DICOM Python library).
Smooth 'phantom' images (ellipses, gradients, texture) written as 8-bit BMP, converted with DCMTK img2dcm, then
stored in three encodings: raw (uncompressed), jl (JPEG lossless), jb (JPEG baseline, lossy).
Training data used random-noise 16-bit uncompressed images only, so sizes and byte patterns differ on purpose."""
import math, os, random, struct, subprocess, sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "/library"
SPEC = {"CT": [(512, 512)], "MR": [(256, 256), (384, 384)], "CR": [(1536, 1536)], "DX": [(2048, 1664)],
        "US": [(640, 480)]}
PER = 6
random.seed(7)


def bmp8(path, w, h, px):
    row = (w + 3) & ~3
    pal = b"".join(bytes((i, i, i, 0)) for i in range(256))
    off = 14 + 40 + len(pal); size = off + row * h
    with open(path, "wb") as f:
        f.write(b"BM" + struct.pack("<IHHI", size, 0, 0, off))
        f.write(struct.pack("<IiiHHIIiiII", 40, w, h, 1, 8, 0, row * h, 2835, 2835, 256, 0))
        f.write(pal)
        pad = b"\x00" * (row - w)
        for y in range(h - 1, -1, -1):
            f.write(bytes(px[y * w:(y + 1) * w]) + pad)


def phantom(w, h):
    s = max(1, w // 512)                                    # compute on a coarse grid, then upsample (build speed)
    cw, ch = (w + s - 1) // s, (h + s - 1) // s
    blobs = [(random.uniform(.2, .8) * cw, random.uniform(.2, .8) * ch, random.uniform(.05, .35) * cw,
              random.uniform(.05, .35) * ch, random.uniform(40, 200)) for _ in range(random.randint(3, 7))]
    fx, fy = random.uniform(.01, .08) * s, random.uniform(.01, .08) * s
    small = []
    for y in range(ch):
        for x in range(cw):
            v = 20 + 30 * (y / ch)
            for cx, cy, rx, ry, a in blobs:
                d = ((x - cx) / rx) ** 2 + ((y - cy) / ry) ** 2
                if d < 1: v += a * (1 - d) ** 0.5
            small.append(v + 6 * math.sin(fx * x) * math.cos(fy * y))
    px = bytearray(w * h)
    rnd = [random.randint(-4, 4) for _ in range(4096)]
    for y in range(h):
        base = (y // s) * cw
        for x in range(w):
            px[y * w + x] = max(0, min(255, int(small[base + x // s]) + rnd[(x * 31 + y * 17) & 4095]))
    return px


def run(cmd):
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


for enc in ("raw", "jl", "jb"):
    os.makedirs(os.path.join(OUT, enc), exist_ok=True)
for mod, sizes in SPEC.items():
    for i in range(PER):
        w, h = random.choice(sizes)
        bmp = f"/tmp/{mod}{i}.bmp"; bmp8(bmp, w, h, phantom(w, h))
        raw = os.path.join(OUT, "raw", f"{mod}_{i}.dcm")
        run(["img2dcm", "-i", "BMP", bmp, raw, "-k", f"Modality={mod}", "-k", "PatientName=TB^TEMPLATE",
             "-k", "PatientID=TB0", "-k", "StudyDescription=TESTBED " + mod])
        run(["dcmcjpeg", raw, os.path.join(OUT, "jl", f"{mod}_{i}.dcm")])            # default: lossless
        run(["dcmcjpeg", "+eb", raw, os.path.join(OUT, "jb", f"{mod}_{i}.dcm")])     # baseline (lossy)
        os.remove(bmp)
print("library:", sum(len(fs) for _, _, fs in os.walk(OUT)), "files in", OUT)
