#!/usr/bin/env bash
# Read-only isolation checks inside the offline VM, before anything is scanned. No root needed;
# changes nothing. Prints PASS or STOP per control and exits 1 if any control is missing:
#
#     bash ~/filesmagic-security-engine/evaluation/vm/guest_checks.sh | tee ~/fm-eval/results/phase6-guest-checks.txt
#
# Host-side settings (adapters, clipboard, drag and drop, shared folders, USB) are checked on the
# host with VBoxManage showvminfo; this checks what the guest itself sees. The worker's own
# controls (namespaces, capability drop, rlimits, audit hook) are verified by the strict preflight
# of evaluation.offline_validation, which refuses to scan if any is missing.
set -uo pipefail

PY=/opt/filesmagic/venv/bin/python
INTERP=/opt/filesmagic/python/cpython-3.11.18-linux-x86_64-gnu/bin/python3.11
PROFILE=/etc/apparmor.d/filesmagic-eval-python
PROFILE_SHA256=6a94078413be722c955cea9f63c8eefe9e3bd0c4f7530d381424fce81681aa20  # docs/offline-vm-validation-c9-2.md, Section 3
stops=0
check() {  # check <name> <ok: 0/1> <detail>
    if [ "$2" = 0 ]; then echo "PASS  $1: $3"; else echo "STOP  $1: $3"; stops=$((stops + 1)); fi
}

echo "date_utc $(date -u +%FT%TZ)  kernel $(uname -r)"
links=$(ip -br link | awk '{print $1}' | tr '\n' ' ')
[ "$links" = "lo " ]; check "interfaces" $? "${links}(only lo expected)"
r4=$(ip route show table all 2>/dev/null | grep -v -E '^(local|broadcast) ' | grep -c .)
r6=$(ip -6 route show table all 2>/dev/null | grep -v -E '^(local|multicast|anycast) ' | grep -c .)
[ "$r4" = 0 ] && [ "$r6" = 0 ]; check "routes" $? "IPv4 $r4, IPv6 $r6 non-local routes (0 expected)"
ip route get 192.0.2.1 >/dev/null 2>&1; [ $? -ne 0 ]; check "IPv4 unreachable" $? "route lookup to 192.0.2.1 fails"
ip -6 route get 2001:db8::1 >/dev/null 2>&1; [ $? -ne 0 ]; check "IPv6 unreachable" $? "route lookup to 2001:db8::1 fails"
shared=$(grep -c -E ' (vboxsf|9p|virtiofs|cifs|nfs4?|fuse\.sshfs) ' /proc/mounts)
[ "$shared" = 0 ]; check "shared folders" $? "$shared shared or network file systems mounted (0 expected)"
optical=$(grep -c -E '^/dev/sr[0-9]' /proc/mounts)
echo "INFO  optical medium mounted: $optical (unmount it before scanning)"

owner=$(stat -c '%U:%G' "$INTERP" 2>/dev/null)
[ "$owner" = "root:root" ]; check "interpreter" $? "$INTERP owned by ${owner:-missing}"
# Owners, write permissions, and where every symlink resolves (trusted_tree.sh): a link's own
# mode is always 777 and says nothing, so it is judged by its target, never its mode.
tree=$(bash "$(dirname "${BASH_SOURCE[0]}")/trusted_tree.sh" /opt/filesmagic root 2>&1); ok=$?
check "interpreter tree" $ok "$(printf '%s\n' "$tree" | tail -n 1)"
[ "$ok" = 0 ] || printf '%s\n' "$tree" | grep '^PROBLEM' | sed 's/^/      /'
target=$(readlink -f "$PY")
[ "$target" = "$INTERP" ]; check "venv interpreter" $? "$PY -> $target"

sum=$(sha256sum "$PROFILE" 2>/dev/null | cut -d' ' -f1)
[ "$sum" = "$PROFILE_SHA256" ]; check "AppArmor profile file" $? "$PROFILE sha256 ${sum:-missing}"
label=$("$PY" -B -c 'print(open("/proc/self/attr/apparmor/current").read().strip())' 2>&1)
[ "$label" = "filesmagic-eval-python (enforce)" ]; check "AppArmor confinement" $? "evaluation interpreter runs as '$label'"
sys_label=$(python3 -c 'print(open("/proc/self/attr/apparmor/current").read().strip())' 2>&1)
echo "INFO  system python3 runs as '$sys_label' (unconfined expected; it is not used for scanning)"
restrict=$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)
[ "$restrict" = 1 ]; check "userns restriction" $? "kernel.apparmor_restrict_unprivileged_userns=$restrict (1: unchanged)"

if [ "$stops" -eq 0 ]; then echo "RESULT all controls present"; else echo "RESULT STOPPED: $stops control(s) missing; do not scan"; fi
[ "$stops" -eq 0 ]
