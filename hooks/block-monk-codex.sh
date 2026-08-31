#!/usr/bin/env sh
# Codex-only wrapper around block-monk.sh that hardcodes `--format codex`.
#
# Codex's hook-command tokenizer may not preserve a quoted, multi-word
# argument (needed to pass `--format codex` directly), while a single
# unquoted path is unambiguous under any reasonable tokenizer. See
# monk-diagnostics-codex.sh for the same pattern on the PostToolUse side.
#
# Codex drops output with any unknown top-level key, so the deny JSON must
# use Codex's documented PreToolUse fields, not the Claude-specific
# hookSpecificOutput wrapper.

set -eu
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec "$script_dir/block-monk.sh" --format codex
