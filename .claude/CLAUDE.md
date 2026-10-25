# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository. The rules every agent follows are in [AGENTS.md](../AGENTS.md), imported below.

@../AGENTS.md

## Claude Code

- `.claude/settings.json` sets `attribution.commit` and `attribution.pr` to `""`. Do not reintroduce Claude attribution in any other way.
- `.claude/settings.json` enforces part of the guardrails in [AGENTS.md](../AGENTS.md#guardrails) with `PreToolUse` hooks on `Bash`, `Read` and `Grep`, and with deny rules. A denial is a repo policy decision, not an obstacle to route around. Do not use other tools to achieve the result instead. Report the block to the contributor and let them decide.
- `kubectl exec`, `run`, `debug`, `attach`, `cp` and `delete`, and `task dev:build`, `dev:test`, `dev:destroy` and `release:bump` prompt on every invocation, with no exception for auto mode.
