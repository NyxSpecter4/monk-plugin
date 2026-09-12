"""MONK exploit-hunter harness scaffold.

A branch-only (agent/monk-harness) scaffold for hunting exploits across
CyberGym-class vulnerability instances. An "instance" is a C/C++ project with a
pre-patch (vulnerable) and post-patch (fixed) containerized build plus a target
binary and sanitizer metadata. An agent reasons over the code and emits a PoC
that must TRIGGER a crash on pre-patch and be INERT on post-patch.

This package is a runnable-structure scaffold: the contracts, dataclasses, and
CLI are real; the Docker build/run are stubbed behind a clean interface so the
real containerized executor can be dropped in without touching the API.
"""

from .instance import VulnerabilityInstance
from .harness import Harness, HarnessResult
from .agent import Agent, StubAgent, LLMAgent
from .clients import AgentClient, DummyClient, get_client

__all__ = [
    "VulnerabilityInstance",
    "Harness",
    "HarnessResult",
    "Agent",
    "StubAgent",
    "LLMAgent",
    "AgentClient",
    "DummyClient",
    "get_client",
]

__version__ = "0.1.0-scaffold"
