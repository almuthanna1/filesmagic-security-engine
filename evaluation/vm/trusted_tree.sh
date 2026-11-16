#!/usr/bin/env bash
# Is <root> a trusted tree? Every entry is owned by <owner>; no file or directory is group- or
# other-writable; every symbolic link resolves to an existing path inside <root>. Read-only.
#
#     bash trusted_tree.sh <root> <owner>        (guest_checks.sh: /opt/filesmagic root)
#
# A symlink's own mode is always 777 on Linux and is never used: who may replace a link is decided
# by its directory, which is checked like any other. So a link is judged by its owner and by
# where it leads, never by its mode. Dangling and looping links are rejected, and so is any link
# whose resolved target (readlink -f, every component followed) lies outside <root>.
# Prints one line per problem (the first 20) and a SUMMARY line; exits 0 only if there is none.
set -uo pipefail
usage="usage: trusted_tree.sh <root> <owner>"
root=$(readlink -f -- "${1:?$usage}") || root=""
owner=${2:?$usage}
if [ -z "$root" ] || [ -L "$1" ] || [ ! -d "$root" ]; then echo "PROBLEM $1 is not a directory (or is a link)"; echo "SUMMARY 1 problem(s)"; exit 1; fi

problems=0
problem() { problems=$((problems + 1)); [ "$problems" -le 20 ] && echo "PROBLEM $*"; }
while IFS= read -r -d '' p; do problem "not owned by $owner: $p"; done < <(find "$root" ! -user "$owner" -print0)
while IFS= read -r -d '' p; do problem "group- or other-writable: $p"; done < <(find "$root" ! -type l -perm /022 -print0)
links=0
while IFS= read -r -d '' link; do
    links=$((links + 1))
    if ! target=$(readlink -f -- "$link") || [ ! -e "$target" ]; then
        problem "dangling or looping link: $link"
        continue
    fi
    case "$target/" in
        "$root"/*) ;;
        *) problem "link leaves $root: $link -> $target" ;;
    esac
done < <(find "$root" -type l -print0)

echo "SUMMARY $problems problem(s); $(find "$root" ! -type l | wc -l) files and directories, $links symlinks resolved"
[ "$problems" -eq 0 ]
