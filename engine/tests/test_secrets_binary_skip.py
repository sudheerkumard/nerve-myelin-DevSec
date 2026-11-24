from pathlib import Path

from myelin_engine import secrets


def test_binary_image_formats_are_not_scanned(tmp_path: Path):
    # Random bytes in compressed images can look like "admin Pa$$w0rd1"; image files are never read.
    img = tmp_path / "shot.webp"
    img.write_bytes(b"RIFF\x00\x00WEBP admin Xy7#abcdEF9 \n")
    assert ".webp" in secrets.SKIP_EXT
    for ext in (".webp", ".avif", ".ttf", ".docx"):
        assert ext in secrets.SKIP_EXT
