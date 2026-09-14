"""Vulnerability instance model for the MONK exploit-hunter.

Mirrors the CyberGym convention: each instance is a real-world C/C++ project
with two pinned refs (pre-patch / vulnerable and post-patch / fixed), a target
binary built inside containerized images, and sanitizer metadata plus a
reference PoC used only for evaluation (never shown to the agent).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass
class VulnerabilityInstance:
    """A single exploit-hunting target.

    Attributes:
        instance_id: Stable identifier (e.g. ``sunblaze-ucb/cybergym:proj-123``).
        repo_url: Clone URL of the upstream OSS project.
        pre_patch_ref: Git ref (commit/tag/branch) of the VULNERABLE build.
        post_patch_ref: Git ref of the FIXED build.
        target_binary: Path (inside the container) of the binary to invoke
            with the submitted PoC.
        sanitizer: Sanitizer used by the build (``address``, ``undefined``,
            ``memory``, ...). Drives crash detection in the harness.
        reference_poc_path: Local path to the reference PoC. Used ONLY for
            scoring/verification, never handed to the agent.
        build_dir: Optional path to the build context (Dockerfile + sources)
            for pre/post images. STUBBED: the real CyberGym provides images.
        description: Free-text note about the vulnerability class.
        metadata: Arbitrary extra fields (CVE id, harness args, etc.).
    """

    repo_url: str
    pre_patch_ref: str
    post_patch_ref: str
    target_binary: str
    sanitizer: str = "address"
    reference_poc_path: Optional[str] = None
    build_dir: Optional[str] = None
    instance_id: Optional[str] = None
    description: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ #
    # (De)serialization
    # ------------------------------------------------------------------ #
    @classmethod
    def from_json(cls, path: str | Path) -> "VulnerabilityInstance":
        """Load an instance description from a JSON file.

        The JSON keys map 1:1 onto the dataclass fields. ``reference_poc_path``
        and ``build_dir`` may be relative; they are resolved against the JSON
        file's directory so instances are portable.
        """
        path = Path(path)
        raw = json.loads(path.read_text())
        # Resolve relative auxiliary paths against the instance file location.
        for key in ("reference_poc_path", "build_dir"):
            val = raw.get(key)
            if val and not Path(val).is_absolute():
                raw[key] = str((path.parent / val).resolve())
        return cls(**raw)

    def to_json(self, path: str | Path) -> None:
        """Persist the instance to a JSON file."""
        Path(path).write_text(json.dumps(asdict(self), indent=2))

    # ------------------------------------------------------------------ #
    # Convenience
    # ------------------------------------------------------------------ #
    @property
    def id(self) -> str:
        """A non-empty identifier for tagging images / logs."""
        return self.instance_id or f"{self.repo_url}@{self.pre_patch_ref}"

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return (
            f"VulnerabilityInstance(id={self.id!r}, "
            f"sanitizer={self.sanitizer!r}, "
            f"target={self.target_binary!r})"
        )
