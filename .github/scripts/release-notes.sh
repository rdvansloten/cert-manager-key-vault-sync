#!/usr/bin/env bash
set -euo pipefail

awk -v ver="$1" '
  index($0, "## [" ver "] - ") == 1 { found = 1; date = substr($0, length("## [" ver "] - ") + 1); next }
  found && /^## \[/ { exit }
  found { lines[++n] = $0 }
  END {
    if (!found) { print "No CHANGELOG.md section for " ver > "/dev/stderr"; exit 1 }
    first = 1; while (first <= n && lines[first] ~ /^[ \t]*$/) first++
    last = n; while (last >= first && lines[last] ~ /^[ \t]*$/) last--
    print "# " date
    print ""
    for (i = first; i <= last; i++) print lines[i]
  }
' CHANGELOG.md
