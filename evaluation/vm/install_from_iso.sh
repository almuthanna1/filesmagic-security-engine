#!/usr/bin/env bash
# Install an evaluation transfer ISO inside the offline VM. Run it FROM the mounted, read-only ISO:
#
#     bash /mnt/fm-eval-iso/install_from_iso.sh
#
# It changes nothing outside these paths and never resets, merges or deletes existing work:
#   ~/filesmagic-security-engine   gets the commit as a new ref (refs/remotes/iso/...), then a
#                                  detached checkout of it; refuses if the tree has local changes
#   ~/fm-eval/samples/<set>        the benign samples and their manifest (new directory, read-only)
#   ~/fm-eval/samples/<set>-tools  the verified Didier Stevens tools (new directory, read-only)
# Those are the paths the enforcing AppArmor profile filesmagic-eval-python lets the evaluation
# interpreter read; results go to ~/fm-eval/results, the only place it may write.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$HOME/filesmagic-security-engine}"
COMMIT="$(cat "$SRC/COMMIT.txt")"
BRANCH="$(cat "$SRC/BRANCH.txt")"
SET="eicar-didier-${COMMIT:0:7}"
SAMPLES="$HOME/fm-eval/samples/$SET"
TOOLS="$HOME/fm-eval/samples/$SET-tools"

fail() { echo "STOPPED: $*" >&2; exit 1; }
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || fail "COMMIT.txt does not hold a commit id"

echo "1/6 Verifying every file on the medium against SHA256SUMS"
(cd "$SRC" && sha256sum --quiet --strict -c SHA256SUMS) || fail "the medium does not match SHA256SUMS"
if find "$SRC" -iname '*eicar*' -print -quit | grep -q .; then fail "EICAR material on the medium: not part of this transfer"; fi

echo "2/6 Checking the repository at $REPO"
[ -d "$REPO/.git" ] || fail "no repository at $REPO (set REPO=... to its path)"
[ -z "$(git -C "$REPO" status --porcelain)" ] || fail "the repository has local changes or untracked files; commit or move them first"
git -C "$REPO" bundle verify "$SRC/filesmagic.bundle" >/dev/null

echo "3/6 Fetching $BRANCH at $COMMIT from the bundle (into a separate ref; nothing is reset or merged)"
git -C "$REPO" fetch --quiet "$SRC/filesmagic.bundle" "refs/heads/$BRANCH:refs/remotes/iso/$BRANCH"
[ "$(git -C "$REPO" rev-parse "refs/remotes/iso/$BRANCH")" = "$COMMIT" ] || fail "the bundle's branch is not $COMMIT"
git -C "$REPO" checkout --quiet --detach "$COMMIT"
[ "$(git -C "$REPO" rev-parse HEAD)" = "$COMMIT" ] && [ -z "$(git -C "$REPO" status --porcelain)" ] \
    || fail "checkout did not produce a clean tree at $COMMIT"

echo "4/6 Copying samples to $SAMPLES and tools to $TOOLS"
[ ! -e "$SAMPLES" ] && [ ! -e "$TOOLS" ] || fail "$SAMPLES or $TOOLS already exists; this script never overwrites"
mkdir -p "$HOME/fm-eval/samples" "$HOME/fm-eval/results"
cp -r "$SRC/samples" "$SAMPLES"
cp -r "$SRC/acquired" "$TOOLS"

echo "5/6 Re-verifying the copies"
grep '  samples/' "$SRC/SHA256SUMS" | sed "s|  samples/|  $SAMPLES/|" | sha256sum --quiet --strict -c - || fail "a copied sample differs"
grep '  acquired/' "$SRC/SHA256SUMS" | sed "s|  acquired/|  $TOOLS/|" | sha256sum --quiet --strict -c - || fail "a copied tool differs"
chmod -R a-w "$SAMPLES" "$TOOLS"

echo "6/6 Done."
echo "  commit   $COMMIT (detached HEAD in $REPO; your previous branch is untouched)"
echo "  samples  $SAMPLES ($(tail -n +2 "$SAMPLES/manifest.csv" | wc -l) samples, read-only)"
echo "  tools    $TOOLS (read-only)"
echo "Now unmount the ISO (sudo umount <mount point>), shut down, and detach it on the host."
