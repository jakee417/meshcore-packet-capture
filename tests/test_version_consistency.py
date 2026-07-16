"""Keep release-facing version declarations synchronized."""
from __future__ import annotations

import re
from pathlib import Path

from meshcore_packet_capture import __version__


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_release_versions_match_package_version() -> None:
    nix_text = (REPO_ROOT / "nix" / "packages.nix").read_text()
    powershell_text = (REPO_ROOT / "install.ps1").read_text()

    nix_version = re.search(
        r'pname = "meshcore-packet-capture";\s+version = "([^"]+)";',
        nix_text,
    )
    powershell_version = re.search(r'\$ScriptVersion = "([^"]+)"', powershell_text)

    assert nix_version is not None
    assert powershell_version is not None
    assert nix_version.group(1) == __version__
    assert powershell_version.group(1) == __version__
