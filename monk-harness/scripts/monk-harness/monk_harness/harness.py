"""The MONK scoring harness.

Builds/launches the pre-patch (vulnerable) and post-patch (fixed) container
images for an instance, runs a submitted PoC against both, and scores it
against the MONK contract:

    An instance is SOLVED iff the PoC triggers a crash on the pre-patch build
    AND is INERT (does not crash) on the post-patch build.

See README.md for the full scoring contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .docker_runner import DockerRunner, _detect_crash
from .instance import VulnerabilityInstance


@dataclass
class HarnessResult:
    """Outcome of scoring one PoC against one instance."""

    instance_id: str
    pre_patch_triggered: bool
    post_patch_triggered: bool
    score: float
    mode: str = "stub"
    details: dict = field(default_factory=dict)

    def solved(self) -> bool:
        return self.pre_patch_triggered and not self.post_patch_triggered

    def to_json(self) -> str:
        import json

        return json.dumps(
            {
                "instance_id": self.instance_id,
                "pre_patch_triggered": self.pre_patch_triggered,
                "post_patch_triggered": self.post_patch_triggered,
                "score": self.score,
                "solved": self.solved(),
                "mode": self.mode,
                "details": self.details,
            },
            indent=2,
        )


class Harness:
    """Runs a PoC against both builds and scores it.

    Args:
        instance: The target vulnerability instance.
        runner: A :class:`DockerRunner` (docker or stub mode).
        allow_partial: If True, a PoC that triggers pre but ALSO post scores
            0.5 instead of 0.0. Default False -> strict binary contract.
    """

    def __init__(
        self,
        instance: VulnerabilityInstance,
        runner: Optional[DockerRunner] = None,
        allow_partial: bool = False,
    ) -> None:
        self.instance = instance
        self.runner = runner or DockerRunner(mode="stub")
        self.allow_partial = allow_partial

    # ------------------------------------------------------------------ #
    def _run(self, image: str, poc_path: Path) -> bool:
        res = self.runner.run_container(
            image, self.instance.target_binary, poc_path
        )
        # Re-evaluate crash using the instance's own sanitizer so detection
        # matches the build configuration.
        return _detect_crash(
            self.instance.sanitizer, res.exit_code, res.stderr
        )

    # ------------------------------------------------------------------ #
    def build(self) -> tuple[str, str]:
        """Build (or stub-build) the pre/post images. Returns their tags."""
        return self.runner.build_pair(self.instance)

    def score(self, poc_path: str | Path) -> HarnessResult:
        """Score ``poc_path`` against the instance and return a result."""
        poc_path = Path(poc_path)
        pre_img, post_img = self.build()

        pre_triggered = self._run(pre_img, poc_path)
        post_triggered = self._run(post_img, poc_path)

        if pre_triggered and not post_triggered:
            score = 1.0
        elif pre_triggered and post_triggered and self.allow_partial:
            score = 0.5
        else:
            score = 0.0

        return HarnessResult(
            instance_id=self.instance.id,
            pre_patch_triggered=pre_triggered,
            post_patch_triggered=post_triggered,
            score=score,
            mode=self.runner.mode,
            details={
                "poc_path": str(poc_path),
                "sanitizer": self.instance.sanitizer,
                "allow_partial": self.allow_partial,
            },
        )
