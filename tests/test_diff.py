from __future__ import annotations

from envshield.core.diff_engine import compute_in_memory_diff, render_diff
from envshield.core.vault import seal_file


def test_in_memory_diff(tmp_path):
    file_a = tmp_path / "a.env"
    file_b = tmp_path / "b.env"

    file_a.write_text("HOST=127.0.0.1\nPORT=5000\n", encoding="utf-8")
    file_b.write_text("HOST=127.0.0.1\nPORT=8000\nDEBUG=True\n", encoding="utf-8")

    enc_a = tmp_path / "a.env.enc"
    enc_b = tmp_path / "b.env.enc"

    seal_file(file_a, enc_a, "test_pass")
    seal_file(file_b, enc_b, "test_pass")

    diff = compute_in_memory_diff(enc_a, enc_b, password_a="test_pass")
    assert any("-PORT=5000" in line for line in diff)
    assert any("+PORT=8000" in line for line in diff)
    assert any("+DEBUG=True" in line for line in diff)

    # Render without errors
    render_diff(diff)
    render_diff([])
