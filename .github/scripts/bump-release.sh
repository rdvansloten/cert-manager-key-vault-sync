#!/usr/bin/env bash
# Bumps the app and chart patch version for Renovate PRs that change the image.
# Usage: bash .github/scripts/bump-release.sh [base-branch]
set -euo pipefail

base="${1:-main}"
chart_dir="charts/cert-manager-key-vault-sync-chart"

ref=""
for candidate in "origin/$base" "$base" HEAD; do
  if git rev-parse -q --verify "$candidate^{commit}" >/dev/null; then
    ref="$candidate"
    break
  fi
done

read_field() {
  git show "$ref:$chart_dir/Chart.yaml" | awk -v key="$1:" '$1 == key { print $2 }'
}

bump_patch() {
  local major minor patch
  IFS=. read -r major minor patch <<<"${1#v}"
  echo "v$major.$minor.$((patch + 1))"
}

# Portable in-place edit (GNU and BSD sed differ on -i)
edit() {
  local file="$1"
  shift
  sed "$@" "$file" >"$file.tmp" && mv "$file.tmp" "$file"
}

old_app="$(read_field appVersion)"
old_chart="$(read_field version)"
new_app="$(bump_patch "$old_app")"
new_chart="$(bump_patch "$old_chart")"

edit "$chart_dir/Chart.yaml" \
  -e "s/^version: .*/version: $new_chart/" \
  -e "s/^appVersion: .*/appVersion: $new_app/"

edit "$chart_dir/values.yaml" \
  -e "s/^  tag: .*/  tag: $new_app/"

edit app/main.py \
  -e "s/^current_version = .*/current_version = \"$new_app\"/"

edit README.md \
  -e "s/^\(| Helm Chart  | \)v[0-9.]*/\1$new_chart/" \
  -e "s/^\(| Application | \)v[0-9.]*/\1$new_app/" \
  -e "s/--version v[0-9.]*/--version $new_chart/g"

# One line per changed dependency: "`new` from `old`", digests shortened
ENTRIES="$(git diff --no-color -U0 "$ref" -- Dockerfile app/requirements.txt app/build-constraints.txt | awk '
  function clean(line) {
    sub(/^[ \t]+/, "", line)
    sub(/ *\\$/, "", line)
    sub(/ *;.*/, "", line)
    if (line ~ /^FROM /) {
      sub(/^FROM /, "", line)
      sub(/ [Aa][Ss] .*/, "", line)
      i = index(line, "@sha256:")
      if (i) line = substr(line, 1, i + 19)
      return line
    }
    if (line ~ /^[A-Za-z0-9][A-Za-z0-9._-]*==?[^ =]+$/) return line
    return ""
  }
  function key(line) { split(line, parts, /[=<>~!:@ ]/); return parts[1] }
  /^(---|\+\+\+)/ { next }
  /^-/ { line = clean(substr($0, 2)); if (line != "") old[key(line)] = line; next }
  /^\+/ {
    line = clean(substr($0, 2))
    if (line == "" || seen[line]++) next
    order[++n] = line
  }
  END {
    for (i = 1; i <= n; i++) {
      k = key(order[i])
      if (k in old && old[k] != order[i]) printf "- `%s` from `%s`\n", order[i], old[k]
      else if (!(k in old)) printf "- `%s`\n", order[i]
    }
  }
')"
[ -n "$ENTRIES" ] || ENTRIES="- Dependency updates by Renovate"
export ENTRIES

# Replace this version's section if it exists, otherwise add it above the latest release
awk -v ver="$new_app" -v date="$(date -u +%F)" '
  /^## \[/ {
    if (index($0, "## [" ver "]") == 1) { skip = 1; next }
    skip = 0
    if (!done) {
      print "## [" ver "] - " date "\n\n### Updated\n\n" ENVIRON["ENTRIES"] "\n"
      done = 1
    }
  }
  skip { next }
  { print }
' CHANGELOG.md >CHANGELOG.md.tmp && mv CHANGELOG.md.tmp CHANGELOG.md

echo "Bumped application $old_app -> $new_app and Helm chart $old_chart -> $new_chart"
