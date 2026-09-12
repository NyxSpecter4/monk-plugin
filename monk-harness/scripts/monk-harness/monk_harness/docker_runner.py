"""Container runner abstraction.

The real CyberGym executor builds/launches Docker images for the pre- and
post-patch refs and runs the target binary with the submitted PoC as input.
This module defines the interface plus a STUB implementation that records what
would happen. The Docker implementation is filled in behind the same
``run_container`` method so callers don't change.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class RunResult:
    """Outcome of running the target binary with a PoC."""

    exit_code: int
    stdout: str
    stderr: str
    crashed: bool  # True if the sanitizer aborted / non-zero crash exit


# Crash signatures per sanitizer. Extend as needed.
_CRASH_SIGNATURES = {
    "address": ("AddressSanitizer", "runtime error", "SError"),
    "undefined": ("UndefinedBehaviorSanitizer", "runtime error"),
    "memory": ("MemorySanitizer",),
    "thread": ("ThreadSanitizer",),
}


def _detect_crash(sanitizer: str, exit_code: int, stderr: str) -> bool:
    """Heuristic: did the run trip the sanitizer / crash?"""
    text = stderr
    sigs = _CRASH_SIGNATURES.get(sanitizer, ("Sanitizer", "runtime error"))
    if any(sig.lower() in text.lower() for sig in sigs):
        return True
    # Hard crashes (segfault/abort) also count even without a clean signature.
    return exit_code < 0 or exit_code in (132, 134, 139, 140)


class DockerRunner:
    """Builds images and runs the target binary against a PoC.

    Two modes:
      * ``mode="docker"``  -> shells out to the ``docker`` CLI (real executor).
      * ``mode="stub"``    -> returns a deterministic placeholder result and
        logs exactly what would have been run. This keeps the scaffold
        runnable on machines without Docker.
    """

    def __init__(
        self,
        mode: str = "docker",
        image_prefix: str = "monk",
        timeout: int = 120,
    ) -> None:
        self.mode = mode
        self.image_prefix = image_prefix
        self.timeout = timeout
        if mode == "docker" and shutil.which("docker") is None:
            raise RuntimeError(
                "mode='docker' but the 'docker' CLI is not on PATH. "
                "Install Docker or pass mode='stub'."
            )

    # -- image building ------------------------------------------------- #
    def build_image(self, tag: str, build_dir: str | Path) -> str:
        build_dir = Path(build_dir)
        if self.mode == "stub":
            print(f"[stub] would build image {tag} from {build_dir}")
            return tag
        subprocess.run(
            ["docker", "build", "-t", tag, str(build_dir)],
            check=True,
        )
        return tag

    def build_pair(self, instance) -> tuple[str, str]:
        """Build (pre_image, post_image) for an instance."""
        base = self.image_prefix
        pre_tag = f"{base}-{instance.id}-pre"
        post_tag = f"{base}-{instance.id}-post"
        if instance.build_dir:
            self.build_image(pre_tag, Path(instance.build_dir) / "pre")
            self.build_image(post_tag, Path(instance.build_dir) / "post")
        else:
            # Real CyberGym: image is derived from repo_url+ref; stubbed here.
            if self.mode == "stub":
                print(
                    f"[stub] would pull/build pre@{instance.pre_patch_ref} "
                    f"and post@{instance.post_patch_ref} for {instance.repo_url}"
                )
        return pre_tag, post_tag

    # -- running -------------------------------------------------------- #
    def run_container(
        self, image: str, target_binary: str, poc_path: str | Path
    ) -> RunResult:
        poc_path = Path(poc_path)
        if self.mode == "stub":
            # Deterministic placeholder: pretend the run did something.
            print(
                f"[stub] would run: docker run --rm -i {image} "
                f"{target_binary} < {poc_path}"
            )
            return RunResult(
                exit_code=0,
                stdout="",
                stderr="[stub] no real execution performed",
                crashed=False,
            )
        # Real execution: feed PoC on stdin to the target binary.
        proc = subprocess.run(
            ["docker", "run", "--rm", "-i", image, target_binary],
            stdin=poc_path.open("rb"),
            capture_output=True,
            timeout=self.timeout,
        )
        crashed = _detect_crash(
            # sanitizer is not known here; harness passes it via run_container
            # overload or we rely on generic detection. Default generic:
            "address",
            proc.returncode,
            proc.stderr.decode(errors="replace"),
        )
        return RunResult(
            exit_code=proc.returncode,
            stdout=proc.stdout.decode(errors="replace"),
            stderr=proc.stderr.decode(errors="replace"),
            crashed=crashed,
        )
