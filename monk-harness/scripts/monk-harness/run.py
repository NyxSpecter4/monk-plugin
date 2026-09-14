#!/usr/bin/env python3
"""MONK exploit-hunter CLI.

Usage:
    python scripts/monk-harness/run.py --instance <path> --agent <name>

Example (runs the scaffold end-to-end without Docker):
    python scripts/monk-harness/run.py \
        --instance scripts/monk-harness/example_instance.json \
        --agent stub --mode stub

The CLI:
  1. loads a VulnerabilityInstance from JSON,
  2. instantiates the chosen agent,
  3. lets the agent emit a PoC file,
  4. scores that PoC with the Harness (docker or stub mode),
  5. prints the JSON result and exits non-zero if unsolved (CI friendly).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from monk_harness.agent import get_agent
from monk_harness.harness import Harness
from monk_harness.instance import VulnerabilityInstance
from monk_harness.docker_runner import DockerRunner


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="monk-harness",
        description="MONK exploit-hunter PoC scoring harness (scaffold).",
    )
    p.add_argument(
        "--instance",
        required=True,
        help="Path to a VulnerabilityInstance JSON file.",
    )
    p.add_argument(
        "--agent",
        required=True,
        help="Agent name (registered in monk_harness.agent.AGENT_REGISTRY).",
    )
    p.add_argument(
        "--mode",
        choices=["docker", "stub"],
        default="stub",
        help="Execution backend. 'stub' avoids Docker (default).",
    )
    p.add_argument(
        "--client",
        default="dummy",
        help="AgentClient backend name (see monk_harness.clients).",
    )
    p.add_argument(
        "--allow-partial",
        action="store_true",
        help="Score 0.5 when PoC triggers pre AND post (else strict 0.0).",
    )
    p.add_argument(
        "--out",
        default=None,
        help="Optional path to write the JSON result.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    instance = VulnerabilityInstance.from_json(args.instance)
    print(f"[monk] loaded {instance}", file=sys.stderr)

    agent = get_agent(args.agent, client_name=args.client)
    print(f"[monk] agent={agent.name} client={agent.client.name}", file=sys.stderr)

    poc_path = agent.generate_poc(instance)
    print(f"[monk] agent wrote PoC -> {poc_path}", file=sys.stderr)

    try:
        runner = DockerRunner(mode=args.mode)
    except RuntimeError as exc:
        print(f"[monk] {exc}", file=sys.stderr)
        return 2

    harness = Harness(instance, runner=runner, allow_partial=args.allow_partial)
    result = harness.score(poc_path)

    print(result.to_json())
    if args.out:
        Path(args.out).write_text(result.to_json())
        print(f"[monk] wrote result -> {args.out}", file=sys.stderr)

    return 0 if result.solved() else 1


if __name__ == "__main__":
    raise SystemExit(main())
