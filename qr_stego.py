import qrcode
import numpy as np
from PIL import Image
import hashlib
import json
import base64
import io
import os
from datetime import date

# ─── Constants ────────────────────────────────────────────────────────────────
MARKER = b"\xDE\xAD\xBE\xEF"   # 4-byte magic header (file signature)
VERSION = 1

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _img_to_bits(img: Image.Image) -> np.ndarray:
    """Convert grayscale QR to flat bit array (0/1 per module pixel)."""
    arr = np.array(img.convert("1"))   # boolean array
    return arr.flatten().astype(np.uint8)

def _bits_to_img(bits: np.ndarray, size: tuple) -> Image.Image:
    arr = bits.reshape(size).astype(np.uint8) * 255
    return Image.fromarray(arr, mode="L")

def _bytes_to_bits(data: bytes) -> np.ndarray:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return np.array(bits, dtype=np.uint8)

def _bits_to_bytes(bits: np.ndarray) -> bytes:
    bits = bits[:len(bits) - (len(bits) % 8)]
    result = []
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | int(b)
        result.append(byte)
    return bytes(result)

# ─── QR Generation ────────────────────────────────────────────────────────────

def generate_qr(payload: str, error_level=qrcode.constants.ERROR_CORRECT_H, box_size=10, border=4) -> Image.Image:
    """Generate a QR with the given error correction level."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=error_level,
        box_size=box_size,
        border=border,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("L")
    return img

# ─── Capacity estimation ──────────────────────────────────────────────────────

def estimate_capacity(img: Image.Image) -> int:
    """Estimate how many secret bytes can be hidden (conservative: 10% of modules)."""
    bits = _img_to_bits(img)

    # Count dark modules (1-bits are white in PIL "1" mode)
    total_modules = len(bits)

    # LSB of every 8th pixel cluster is used
    usable_bits = total_modules // 8

    overhead = len(MARKER) + 1 + 4 + 32  # marker(4) + version(1) + msg_length(4) + sha256(32)
    
    return max(0, usable_bits - overhead)

# ─── Embed ────────────────────────────────────────────────────────────────────

def embed_message(cover_img: Image.Image, secret: str) -> Image.Image:
    """
    Hide `secret` inside `cover_img` using LSB steganography on QR modules.
    
    Payload structure (bytes):
      MARKER (4) | VERSION (1) | MSG_LEN (4, big-endian) | SHA256(secret) (32) | MSG
    """
    secret_bytes = secret.encode("utf-8")
    sha = hashlib.sha256(secret_bytes).digest()
    
    payload = (
        MARKER
        + bytes([VERSION])
        + len(secret_bytes).to_bytes(4, "big")
        + sha
        + secret_bytes
    )
    
    payload_bits = _bytes_to_bits(payload)
    
    arr = np.array(cover_img, dtype=np.uint8)
    flat = arr.flatten()
    
    if len(payload_bits) > len(flat):
        raise ValueError(
            f"Secret too long! Need {len(payload_bits)} bits, image has {len(flat)} pixels."
        )
    
    # Modify LSB of each pixel
    for i, bit in enumerate(payload_bits):
        flat[i] = (flat[i] & 0xFE) | bit
    
    stego = flat.reshape(arr.shape)
    
    return Image.fromarray(stego, mode="L")

# ─── Extract ──────────────────────────────────────────────────────────────────

def extract_message(stego_img: Image.Image) -> str:
    """Extract hidden message from a stego QR."""
    arr = np.array(stego_img, dtype=np.uint8)
    flat = arr.flatten()
    
    # Pull LSBs
    lsbs = (flat & 1).astype(np.uint8)
    raw = _bits_to_bytes(lsbs)
    
    # Verify marker
    if raw[:4] != MARKER:
        raise ValueError("No steganographic payload found (marker mismatch).")
    
    version = raw[4]
    if version != VERSION:
        raise ValueError(f"Unknown payload version: {version}")
    
    msg_len = int.from_bytes(raw[5:9], "big")
    stored_sha = raw[9:41]
    msg_bytes = raw[41:41 + msg_len]
    
    # Integrity check
    actual_sha = hashlib.sha256(msg_bytes).digest()
    if actual_sha != stored_sha:
        raise ValueError("Integrity check failed - message may be corrupted or tampered.")
    
    return msg_bytes.decode("utf-8")

# ─── Analysis ─────────────────────────────────────────────────────────────────

def analyze_image(img: Image.Image) -> dict:
    """Return forensic stats about an image."""
    arr = np.array(img, dtype=np.uint8)
    flat = arr.flatten()
    lsbs = flat & 1
    
    # Chi-square test for LSB randomness (basic steganalysis)
    ones = int(np.sum(lsbs))
    zeros = int(len(lsbs) - ones)
    expected = len(lsbs) / 2
    chi2 = ((ones - expected)**2 + (zeros - expected)**2) / expected
    
    return {
        "pixels": len(flat),
        "lsb_ones": ones,
        "lsb_zeros": zeros,
        "lsb_ratio": round(ones / len(lsbs), 4),
        "chi2_statistic": round(chi2, 4),
        "anomaly_detected": chi2 > 3.84,  # p=0.05 threshold
        "capacity_bytes": len(flat) // 8,
    }

# ─── Save / Load ──────────────────────────────────────────────────────────────

def save_png(img: Image.Image, path: str):
    img.save(path, format="PNG")

def load_png(path: str) -> Image.Image:
    return Image.open(path).convert("L")

# ─── CLI Demo ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":s
    OUT = os.path.dirname(os.path.abspath(__file__))  # save QRs next to this script

    PUBLIC_MSG = "https://www.elfak.ni.ac.rs/"
    SECRET_MSG = f"CLASSIFIED: Steganography research payload - embedded {date.today()}"
    
    print("=" * 60)
    print("  Digital forensics demo - QR code steganography")
    print("=" * 60)
     
    # Generate QR
    print(f"\n[1] Generating QR with message:\n    '{PUBLIC_MSG}'")
    cover = generate_qr(PUBLIC_MSG, error_level=qrcode.constants.ERROR_CORRECT_H) # HIGH error correction gives most redundancy
    save_png(cover, os.path.join(OUT, "qr_with_no_secret_error_correction-H.png"))
    cap = estimate_capacity(cover)
    print(f"    Image size: {cover.size}, estimated capacity: ~{cap} bytes")
    
    # Embed secret
    print(f"\n[2] Embedding secret:\n    '{SECRET_MSG}'")
    stego = embed_message(cover, SECRET_MSG)
    save_png(stego, os.path.join(OUT, "qr_with_embedded_secret_via_lsb.png"))
    print("    Stego image saved → qr_with_embedded_secret_via_lsb.png")
    
    # Analyse both
    print("\n[3] Forensic Analysis")
    cover_stats = analyze_image(cover)
    stego_stats = analyze_image(stego)
    print(f"    Cover  - LSB ratio: {cover_stats['lsb_ratio']}, χ²: {cover_stats['chi2_statistic']}, anomaly: {cover_stats['anomaly_detected']}")
    print(f"    Stego  - LSB ratio: {stego_stats['lsb_ratio']}, χ²: {stego_stats['chi2_statistic']}, anomaly: {stego_stats['anomaly_detected']}")
    
    # Extract
    print("\n[4] Extracting hidden message …")
    recovered = extract_message(stego)
    print(f"    Recovered: '{recovered}'")
    print(f"    Match: {recovered == SECRET_MSG}")
    
    print("\n[5] Visual diff (pixel delta)")
    diff = np.abs(np.array(cover, dtype=int) - np.array(stego, dtype=int))
    diff_img = Image.fromarray((diff * 40).clip(0, 255).astype(np.uint8), mode="L")
    save_png(diff_img, os.path.join(OUT, "qr_diff_lsb_changes_amplified_40x.png"))
    print(f"    Changed pixels: {int(np.sum(diff > 0))} / {diff.size}")
    print("    Diff image saved → qr_diff.png")
    
    print("\nDone.")
