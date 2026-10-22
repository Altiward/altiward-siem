#!/bin/bash
# Prints one release's section of CHANGELOG.md, the notes published with the release.
# Fails if the section is missing, still undated, or has no "### Changes".
#
#   scripts/release-notes.sh 0.1.0
set -euo pipefail

VERSION="${1:?version, e.g. 0.1.0}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version must be X.Y.Z, got $VERSION" >&2; exit 1; }
cd "$(dirname "$0")/.."

# The section runs from its heading to the next release heading.
SECTION="$(awk -v head="## $VERSION - " '
  index($0, head) == 1 { found = 1; print; next }
  found && /^## / { exit }
  found { print }
' CHANGELOG.md)"

if [ -z "$SECTION" ]; then
  echo "CHANGELOG.md has no \"## $VERSION - <date>\" section" >&2
  exit 1
fi
DATE="$(head -1 <<<"$SECTION" | sed "s/^## $VERSION - //")"
if ! [[ "$DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
  echo "CHANGELOG.md: $VERSION is dated \"$DATE\"; put the release date (YYYY-MM-DD) before releasing" >&2
  exit 1
fi
grep -qx "### Changes" <<<"$SECTION" || { echo "CHANGELOG.md: $VERSION has no \"### Changes\"" >&2; exit 1; }
printf '%s\n' "$SECTION"
