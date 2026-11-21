def decode_watermark(leaked_text: str) -> str:
    """Extracts zero-width Unicode characters (\u200b, \u200c) to recover the User ID."""
    bits = []
    for char in leaked_text:
        if char == "\u200b":
            bits.append("1")
        elif char == "\u200c":
            bits.append("0")

    if not bits:
        return "No watermark found."

    binary_str = "".join(bits)
    # Convert 8-bit chunks back to ASCII characters
    chars = [
        chr(int(binary_str[i:i + 8], 2))
        for i in range(0, len(binary_str), 8)
        if len(binary_str[i:i + 8]) == 8
    ]
    return "".join(chars)

if __name__ == "__main__":
    # Example test with a watermarked string from CTR-8821
    sample_leak = (
        "Base Alpha perimeter fence is 4m high."
        "\u200c\u200b\u200c\u200c\u200c\u200c\u200b\u200b"  # 'C'
        "\u200c\u200b\u200c\u200b\u200c\u200b\u200c\u200c"  # 'T'
        "\u200c\u200b\u200c\u200b\u200c\u200c\u200b\u200c"  # 'R'
        "\u200c\u200c\u200b\u200c\u200b\u200b\u200c\u200b"  # '-'
        "\u200c\u200c\u200b\u200b\u200b\u200c\u200c\u200c"  # '8'
        "\u200c\u200c\u200b\u200b\u200b\u200c\u200c\u200c"  # '8'
        "\u200c\u200c\u200b\u200b\u200c\u200c\u200b\u200c"  # '2'
        "\u200c\u200c\u200b\u200b\u200c\u200c\u200c\u200b"  # '1'
    )
    recovered_id = decode_watermark(sample_leak)
    print(f"[FORENSIC TRACE] Recovered User ID: {recovered_id}")
