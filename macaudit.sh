#!/bin/bash
# 1
# 2
# 3

set -u
export LC_ALL=C
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

VERSION="1.1"
EXTRA_HOSTS="$*"
START_EPOCH=$(date +%s)

[ "$(uname -s)" = "Darwin" ] || { echo "macOS only."; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Run it as:   sudo bash $0"; exit 1; }

REALUSER="${SUDO_USER:-}"
if [ -z "$REALUSER" ] || [ "$REALUSER" = "root" ]; then
  REALUSER=$(stat -f %Su /dev/console 2>/dev/null)
fi
[ -n "$REALUSER" ] || { echo "Cannot determine the logged-in user."; exit 1; }
REALUID=$(id -u "$REALUSER")
REALHOME=$(dscl . -read "/Users/$REALUSER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
[ -d "${REALHOME:-}" ] || REALHOME="/Users/$REALUSER"

HOSTSHORT=$(hostname -s 2>/dev/null || echo mac)
STAMP=$(date +%Y%m%d_%H%M%S)
OUT="$REALHOME/macaudit_${HOSTSHORT}_${STAMP}"
mkdir -p "$OUT/certs" || { echo "Cannot create $OUT"; exit 1; }
FLAGFILE="$OUT/.flags"
: > "$FLAGFILE"
SUMMARY="$OUT/00_SUMMARY.txt"
SETUP_MARK=/var/db/.AppleSetupDone

GW=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}')
DEFIF=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
RESOLVERS=$(scutil --dns 2>/dev/null | awk '/nameserver\[/{print $3}' | sort -u | tr '\n' ' ')

if sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" 'SELECT count(*) FROM access;' >/dev/null 2>&1; then FDA=yes; else FDA=no; fi

HOMES=()
while read -r u uid; do
  case "$uid" in ''|*[!0-9]*) continue;; esac
  [ "$uid" -ge 500 ] || continue
  hd=$(dscl . -read "/Users/$u" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
  [ -d "${hd:-}" ] && HOMES+=("$hd")
done < <(dscl . -list /Users UniqueID 2>/dev/null)
for d in /Users/*; do
  [ -d "$d" ] || continue
  [ "$d" = "/Users/Shared" ] && continue
  seen=0
  for e in "${HOMES[@]:-}"; do [ "$e" = "$d" ] && seen=1; done
  [ "$seen" -eq 0 ] && HOMES+=("$d")
done
HOMES+=("/var/root")

STEP=0; TOTAL=23; CURRENT_FILE=""; SECSTART=0; LAST_START=0

section() {
  if [ -n "$CURRENT_FILE" ]; then printf ' done (%ss)\n' "$(( $(date +%s) - SECSTART ))"; fi
  STEP=$((STEP + 1)); SECSTART=$(date +%s)
  CURRENT_FILE="$OUT/$1"
  printf 'macaudit %s | %s | %s | host=%s user=%s\n' "$VERSION" "$1" "$(date)" "$HOSTSHORT" "$REALUSER" > "$CURRENT_FILE"
  printf '[%2d/%d] %-28s' "$STEP" "$TOTAL" "$1"
}
section_done() { printf ' done (%ss)\n' "$(( $(date +%s) - SECSTART ))"; }
descendants() { local k; for k in $(pgrep -P "$1" 2>/dev/null); do printf '%s ' "$k"; descendants "$k"; done; }

run() {
  local secs="$1" label="$2" cmd="$3" cpid wpid rc
  LAST_START=$(wc -l < "$CURRENT_FILE" | tr -d ' ')
  printf '.'
  {
    printf '\n############ %s\n$ %s\n' "$label" "$cmd"
    ( eval "$cmd" ) &
    cpid=$!
    ( sleep "$secs"; if kill -0 "$cpid" 2>/dev/null; then touch "$OUT/.timeout.$cpid"; kids=$(descendants "$cpid"); kill -TERM "$cpid" 2>/dev/null; [ -n "$kids" ] && kill -TERM $kids 2>/dev/null; fi ) &
    wpid=$!
    wait "$cpid"; rc=$?
    kill "$wpid" 2>/dev/null
    if [ -e "$OUT/.timeout.$cpid" ]; then
      rm -f "$OUT/.timeout.$cpid"
      printf '\n[TIMED OUT after %ss - output above is partial]\n' "$secs"
    elif [ "$rc" -ne 0 ]; then
      printf '[exit %s]\n' "$rc"
    fi
    printf '\n'
  } >> "$CURRENT_FILE" 2>&1
}
lastout() { tail -n +"$((LAST_START + 4))" "$CURRENT_FILE"; }
hit() { lastout | grep -qE "$@"; }
blockout() { awk -v lab="$2" '$0 == "############ " lab {p=1; next} /^############ /{p=0} p' "$1"; }
flag() { printf 'FLAG  [%s]  %s\n' "${CURRENT_FILE##*/}" "$*" >> "$FLAGFILE"; }
note() { printf 'note  [%s]  %s\n' "${CURRENT_FILE##*/}" "$*" >> "$FLAGFILE"; }
asuser() { launchctl asuser "$REALUID" sudo -H -u "$REALUSER" "$@"; }
pids_of_path() { ps -axo pid=,comm= 2>/dev/null | awk -v p="$1" '{ pid=$1; sub(/^ *[0-9]+ /, ""); if ($0 == p) print pid }'; }

sigcheck() {
  local f="$1" out
  if [ ! -e "$f" ]; then printf 'FLAG: 217  %s\n' "$f"; return; fi
  out=$(codesign -dv --verbose=2 "$f" 2>&1)
  printf '%s\n' "$out" | grep -E '^(Identifier|TeamIdentifier|Authority|Signature|Format|CodeDirectory)' | sed 's/^/    /'
  if printf '%s\n' "$out" | grep -q 'not signed'; then
    printf 'FLAG: 218  %s\n' "$f"
  elif printf '%s\n' "$out" | grep -q 'Signature=adhoc'; then
    printf 'FLAG: 219  %s\n' "$f"
  elif printf '%s\n' "$out" | grep -qE '^Authority=(Software Signing|Apple Mac OS Application Signing|Apple iPhone OS Application Signing)'; then
    printf '    [220]\n'
  elif printf '%s\n' "$out" | grep -q '^Authority=Developer ID Application'; then
    printf '    [221] %s\n' "$(printf '%s\n' "$out" | grep '^TeamIdentifier')"
  elif printf '%s\n' "$out" | grep -qiE 'bundle format unrecognized|invalid|does not seem to be'; then
    printf 'FLAG: 222  %s\n' "$f"
  else
    printf 'FLAG: 223  %s\n' "$f"
  fi
}

plist_programs() {
  local d="$1" p prog
  [ -d "$d" ] || { printf '(224 %s)\n' "$d"; return; }
  ls -laO "$d" 2>&1
  for p in "$d"/*.plist; do
    [ -e "$p" ] || continue
    printf '\n=== %s\n' "$p"
    plutil -p "$p" 2>&1
    prog=$(plutil -extract Program raw -o - "$p" 2>/dev/null)
    [ -n "$prog" ] || prog=$(plutil -extract ProgramArguments.0 raw -o - "$p" 2>/dev/null)
    if [ -n "$prog" ]; then
      printf -- '--- program: %s\n' "$prog"
      sigcheck "$prog"
    else
      printf 'FLAG: 225  %s\n' "$p"
    fi
  done
}

dump_certs() {
  local kc="$1" pre="$2" n=0 f
  security find-certificate -a -p "$kc" 2>/dev/null | awk -v out="$OUT/certs/$pre" 'BEGIN{file="/dev/null"} /BEGIN CERTIFICATE/{n++; file=out "_" n ".pem"} {print > file}'
  for f in "$OUT/certs/${pre}"_*.pem; do
    [ -e "$f" ] || continue
    n=$((n + 1))
    printf '\n-- %s\n' "$f"
    openssl x509 -in "$f" -noout -subject -issuer -dates -fingerprint -sha256 2>&1
    openssl x509 -in "$f" -noout -text 2>/dev/null | grep -A1 'Basic Constraints' | tr -s ' ' | tr '\n' ' '; echo
  done
  printf '\n(226 %s %s)\n' "$n" "$kc"
}

SQL_TCC="SELECT service, client, client_type, auth_value, auth_reason, datetime(last_modified,'unixepoch') FROM access ORDER BY service, client;"
SQL_TCC_FALLBACK="SELECT * FROM access;"
SQL_QUARANTINE="SELECT datetime(LSQuarantineTimeStamp+978307200,'unixepoch') AS t, LSQuarantineAgentName, LSQuarantineDataURLString, LSQuarantineOriginURLString, LSQuarantineSenderAddress FROM LSQuarantineEvent ORDER BY t DESC;"
SQL_ACCOUNTS="SELECT a.ZACCOUNTDESCRIPTION, a.ZUSERNAME, t.ZACCOUNTTYPEDESCRIPTION, t.ZIDENTIFIER, a.ZACTIVE FROM ZACCOUNT a LEFT JOIN ZACCOUNTTYPE t ON a.ZACCOUNTTYPE = t.Z_PK;"
SQL_ACCOUNTS_FALLBACK="SELECT ZACCOUNTDESCRIPTION, ZUSERNAME FROM ZACCOUNT;"
SQL_SHORTCUTS="SELECT ZNAME, datetime(ZCREATIONDATE+978307200,'unixepoch'), datetime(ZMODIFICATIONDATE+978307200,'unixepoch') FROM ZSHORTCUT;"
PRED_AUTH='(process == "sshd") OR (process == "screensharingd") OR (process == "ARDAgent") OR (process == "remotedesktopd") OR (process == "sudo") OR (process == "loginwindow" AND (eventMessage CONTAINS[c] "login" OR eventMessage CONTAINS[c] "user")) OR (process == "mdmclient") OR (subsystem == "com.apple.ManagedClient") OR (process == "sysextd") OR (process == "kernelmanagerd") OR (process == "tccd" AND eventMessage CONTAINS "Granted") OR (process == "opendirectoryd" AND eventMessage CONTAINS[c] "create")'
PRED_XPROTECT='subsystem == "com.apple.XProtectFramework.PluginAPI" AND category == "XPEvent.structured"'

printf 'macaudit %s | 227 %s\n' "$VERSION" "$OUT"
printf '228 %s\n' "$FDA"
[ "$FDA" = no ] && printf '229\n'
printf '230 %s\n\n' "${HOMES[*]}"

section 01.txt
run 20 "4" 'sw_vers; echo; uname -a; echo; sysctl -n hw.model machdep.cpu.brand_string hw.ncpu hw.memsize 2>/dev/null'
run 20 "5" 'scutil --get ComputerName 2>&1; scutil --get LocalHostName 2>&1; scutil --get HostName 2>&1; hostname'
run 30 "6" 'date; echo; uptime; echo; systemsetup -gettimezone 2>&1; systemsetup -getusingnetworktime 2>&1; systemsetup -getnetworktimeserver 2>&1'
run 20 "7" 'ls -la "$SETUP_MARK" 2>&1; stat -f "created %SB   modified %Sm" "$SETUP_MARK" 2>&1'
run 90 "8" 'system_profiler SPHardwareDataType 2>&1'
run 90 "9" 'system_profiler SPSoftwareDataType 2>&1'
run 20 "10" 'who -a 2>&1; echo; w 2>&1; echo; stat -f "console owner: %Su" /dev/console'

section 02.txt
run 20 "11" 'csrutil status 2>&1; csrutil authenticated-root status 2>&1'
hit 'System Integrity Protection status: disabled' && flag "12"
hit 'Authenticated Root status: disabled' && flag "13"
run 20 "14" 'spctl --status 2>&1'
hit 'assessments disabled' && flag "15"
run 90 "16" 'spctl --list 2>&1'
run 30 "17" 'fdesetup status 2>&1; echo; echo "FileVault-enabled users:"; fdesetup list 2>&1; echo; echo "personal recovery key: $(fdesetup haspersonalrecoverykey 2>&1)"; echo "institutional recovery key: $(fdesetup hasinstitutionalrecoverykey 2>&1)"'
hit 'FileVault is Off' && flag "18"
hit 'institutional recovery key: true' && flag "19"
run 20 "20" '/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate --getstealthmode --getblockall --getallowsigned --getallowsignedapp 2>&1; echo; /usr/libexec/ApplicationFirewall/socketfilterfw --listapps 2>&1'
hit 'Firewall is disabled' && note "21"
run 30 "22" 'if command -v bputil >/dev/null 2>&1; then bputil -d 2>&1; else echo "232"; fi'
hit -i 'Security Mode: *(Reduced|Permissive)' && flag "23"
run 20 "24" 'nvram boot-args 2>&1; echo; nvram -p 2>&1 | grep -iE "boot-args|csr-active|amfi|recovery-boot|efi-boot"'
hit '^boot-args[[:space:]]+[^[:space:]]' && flag "25 $(lastout | grep -E '^boot-args' | head -1)"
run 30 "26" 'echo "-- /Library/Preferences/com.apple.security.libraryvalidation.plist"; plutil -p /Library/Preferences/com.apple.security.libraryvalidation.plist 2>&1; echo; for h in "${HOMES[@]}"; do f="$h/Library/Preferences/com.apple.LaunchServices.plist"; [ -e "$f" ] && { echo "-- $f"; plutil -p "$f"; }; done'
hit '"DisableLibraryValidation" => (1|true)' && flag "27"
hit '"LSQuarantine" => (0|false)' && flag "28"
run 40 "29" 'plutil -p /Library/Preferences/com.apple.SoftwareUpdate.plist 2>&1; echo; softwareupdate --schedule 2>&1'
hit '"AutomaticCheckEnabled" => (0|false)' && note "30"
run 20 "31" 'plutil -p /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/version.plist 2>&1 | grep -E "CFBundleShortVersionString"; ls -la /Library/Apple/System/Library/CoreServices/ 2>&1 | grep -i xprotect'

section 03.txt
run 20 "32" 'dscl . -list /Users UniqueID 2>&1 | sort -k2 -n'
while read -r u uid; do
  case "$uid" in ''|*[!0-9]*) continue;; esac
  if [ "$uid" -eq 0 ] && [ "$u" != "root" ]; then flag "33 $u"; fi
  case "$u" in _*|root|daemon|nobody) continue;; esac
  [ "$uid" -lt 500 ] && flag "34 $u $uid"
done < <(dscl . -list /Users UniqueID 2>/dev/null)
run 60 "35" 'for u in $(dscl . -list /Users 2>/dev/null); do echo "== $u"; dscl . -read "/Users/$u" UniqueID PrimaryGroupID NFSHomeDirectory UserShell IsHidden AuthenticationAuthority AltSecurityIdentities 2>&1 | grep -v "No such key"; echo; done'
for u in $(dscl . -list /Users 2>/dev/null); do
  hidden=$(dscl . -read "/Users/$u" IsHidden 2>/dev/null | awk '{print $2}')
  [ "${hidden:-0}" = "1" ] && flag "36 $u"
done
run 20 "37" 'for g in admin wheel com.apple.access_ssh com.apple.access_screensharing com.apple.access_remote_ae com.apple.access_ftp com.apple.access_disabled staff; do echo "== $g"; dscl . -read "/Groups/$g" GroupMembership 2>&1 | grep -v "No such key"; dscl . -read "/Groups/$g" NestedGroups 2>&1 | grep -v "No such key"; done'
ADMINS=$(dscl . -read /Groups/admin GroupMembership 2>/dev/null | sed 's/^GroupMembership: //')
note "38 ${ADMINS:-?}"
run 20 "39" 'dscl . -read /Users/root AuthenticationAuthority 2>&1; dscl . -read /Users/root Password 2>&1; dscl . -read /Users/root UserShell 2>&1'
dscl . -read /Users/root AuthenticationAuthority 2>&1 | grep -q '^AuthenticationAuthority:' && flag "40"
run 20 "41" 'cat /etc/sudoers 2>&1; echo; ls -la /etc/sudoers.d 2>&1; for f in /etc/sudoers.d/*; do [ -e "$f" ] && { echo "== $f"; cat "$f"; }; done'
if grep -vE '^[[:space:]]*(#|$|Defaults|root[[:space:]]|%admin[[:space:]]|@include)' /etc/sudoers 2>/dev/null | grep -q .; then flag "42 $(grep -vE '^[[:space:]]*(#|$|Defaults|root[[:space:]]|%admin[[:space:]]|@include)' /etc/sudoers | tr '\n' ' ')"; fi
grep -qs NOPASSWD /etc/sudoers /etc/sudoers.d/* 2>/dev/null && flag "43"
if ls /etc/sudoers.d/* >/dev/null 2>&1; then note "44"; fi
run 20 "45" 'for f in /etc/pam.d/*; do echo "== $f"; cat "$f"; echo; done'
hit 'pam_permit' && flag "46"
run 20 "47" 'security authorizationdb read system.login.console 2>&1; echo; ls -la /Library/Security/SecurityAgentPlugins 2>&1; ls -la /System/Library/CoreServices/SecurityAgentPlugins 2>&1'
if [ -n "$(ls -A /Library/Security/SecurityAgentPlugins 2>/dev/null)" ]; then flag "48"; fi
mechs=$(security authorizationdb read system.login.console 2>/dev/null | awk '/<key>mechanisms<\/key>/{m=1;next} m&&/<\/array>/{exit} m&&/<string>/{gsub(/.*<string>|<\/string>.*/,""); print}')
odd=$(printf '%s\n' "$mechs" | grep -vE '^(builtin:|loginwindow:|PKINITMechanism:|HomeDirMechanism:|MCXMechanism:|CryptoTokenKit:|SecureTokenMechanism|TeamIdentityMechanism|AKSSecurityMechanism)' | grep -v '^$')
[ -n "$odd" ] && flag "49 $(printf '%s' "$odd" | tr '\n' ' ')"
run 20 "50" 'plutil -p /Library/Preferences/com.apple.loginwindow.plist 2>&1; echo; ls -la /etc/kcpassword 2>&1; echo; for h in "${HOMES[@]}"; do f="$h/Library/Preferences/com.apple.loginwindow.plist"; [ -e "$f" ] && { echo "-- $f"; plutil -p "$f"; }; done'
hit '"(LoginHook|LogoutHook)"' && flag "51"
[ -e /etc/kcpassword ] && flag "52"
hit '"autoLoginUser"' && flag "53"
run 60 "54" 'for u in $(dscl . -list /Users UniqueID | awk "\$2 >= 500 {print \$1}"); do sysadminctl -secureTokenStatus "$u" 2>&1; done'
run 30 "55" 'last -40 2>&1'

section 04.txt
run 30 "56" 'systemsetup -getremotelogin 2>&1; systemsetup -getremoteappleevents 2>&1; systemsetup -getwakeonnetworkaccess 2>&1'
hit 'Remote Login: On' && flag "57"
hit 'Remote Apple Events: On' && flag "58"
run 20 "59" 'plutil -p /private/var/db/com.apple.xpc.launchd/disabled.plist 2>&1; echo; plutil -p "/private/var/db/com.apple.xpc.launchd/disabled.$REALUID.plist" 2>&1'
hit '"com.apple.screensharing" => false' && flag "60"
hit '"com.apple.smbd" => false' && note "61"
hit '"com.apple.openssh.sshd" => false' && note "62"
run 30 "63" 'ps -axo pid,user,etime,comm 2>&1 | grep -iE "ARDAgent|screensharingd|remotedesktopd|AppleVNCServer|sshd|teamviewer|anydesk|splashtop|logmein|gotomypc|rustdesk|zoho|connectwise|screenconnect|jump desktop|nomachine|nxserver|realvnc|vncserver|parsec|bomgar|beyondtrust|atera|syncro|tailscale|zerotier|ngrok|cloudflared|remoting_|supremo|ultraviewer|dwagent|getscreen|rport|meshagent|pulseway|action1|ninjarmm|datto|kaseya|simplehelp|chrome remote" | grep -v grep'
hit -i 'ARDAgent|screensharingd|remotedesktopd|AppleVNCServer' && flag "64"
hit -i '[[:space:]]sshd' && note "65"
hit -i 'teamviewer|anydesk|splashtop|logmein|gotomypc|rustdesk|zoho|connectwise|screenconnect|jump desktop|nomachine|nxserver|realvnc|vncserver|parsec|bomgar|beyondtrust|atera|syncro|ngrok|cloudflared|remoting_|supremo|ultraviewer|dwagent|getscreen|rport|meshagent|pulseway|action1|ninjarmm|datto|kaseya|simplehelp|chrome remote' && flag "66"
hit -i 'tailscale|zerotier' && note "67"
run 30 "68" 'plutil -p /Library/Preferences/com.apple.RemoteManagement.plist 2>&1; echo; ls -la /private/var/db/RemoteManagement 2>&1; ls -la "/Library/Application Support/Apple/Remote Desktop" 2>&1; echo; plutil -p /Library/Preferences/com.apple.RemoteDesktop.plist 2>&1'
run 20 "69" 'sharing -l 2>&1; echo; plutil -p /Library/Preferences/SystemConfiguration/com.apple.smb.server.plist 2>&1'
run 30 "70" 'ls -la /etc/ssh 2>&1; echo; grep -vE "^[[:space:]]*#|^[[:space:]]*$" /etc/ssh/sshd_config 2>&1; echo; ls -la /etc/ssh/sshd_config.d 2>&1; for f in /etc/ssh/sshd_config.d/*; do [ -e "$f" ] && { echo "== $f"; cat "$f"; }; done; echo; for h in "${HOMES[@]}"; do d="$h/.ssh"; [ -d "$d" ] || continue; echo "== $d"; ls -la "$d"; for f in "$d/authorized_keys" "$d/authorized_keys2" "$d/config" "$d/rc" "$d/environment"; do [ -e "$f" ] && { echo "-- $f"; cat "$f"; }; done; done'
for h in "${HOMES[@]}"; do
  for f in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2" "$h/.ssh/rc" "$h/.ssh/environment"; do
    [ -s "$f" ] && flag "71 $f"
  done
done
run 180 "72" 'find /Applications /Library /Users /usr/local /opt /private/tmp /private/var/tmp /private/var/root /Users/Shared -maxdepth 6 \( -iname "*teamviewer*" -o -iname "*anydesk*" -o -iname "*splashtop*" -o -iname "*logmein*" -o -iname "*gotomypc*" -o -iname "*rustdesk*" -o -iname "*zoho*assist*" -o -iname "*connectwise*" -o -iname "*screenconnect*" -o -iname "*jump desktop*" -o -iname "*nomachine*" -o -iname "*realvnc*" -o -iname "*vnc*" -o -iname "*parsec*" -o -iname "*bomgar*" -o -iname "*beyondtrust*" -o -iname "*atera*" -o -iname "*syncro*" -o -iname "*tailscale*" -o -iname "*zerotier*" -o -iname "*ngrok*" -o -iname "*cloudflared*" -o -iname "*chrome remote desktop*" -o -iname "*remoting_me2me*" -o -iname "*supremo*" -o -iname "*ultraviewer*" -o -iname "*dwagent*" -o -iname "*getscreen*" -o -iname "*meshagent*" -o -iname "*pulseway*" -o -iname "*action1*" -o -iname "*ninjarmm*" -o -iname "*kaseya*" -o -iname "*simplehelp*" -o -iname "*wireguard*" -o -iname "*openvpn*" \) -not -path "*/Caches/*" 2>/dev/null | head -300'
hit '^/' && note "73"
run 30 "74" 'pfctl -s info 2>&1 | head -5; echo; pfctl -s rules 2>&1; echo; pfctl -s nat 2>&1; echo; grep -vE "^[[:space:]]*#|^[[:space:]]*$" /etc/pf.conf 2>&1; echo; ls -la /etc/pf.anchors 2>&1; for f in /etc/pf.anchors/*; do [ -e "$f" ] && { echo "== $f"; grep -vE "^[[:space:]]*#|^[[:space:]]*$" "$f"; }; done'
if ls /etc/pf.anchors 2>/dev/null | grep -vqE '^com\.apple'; then flag "75"; fi

section 05.txt
for d in /Library/LaunchDaemons /Library/LaunchAgents; do
  run 120 "76 $d" "plist_programs \"$d\""
done
for h in "${HOMES[@]}"; do
  d="$h/Library/LaunchAgents"
  [ -d "$d" ] && run 120 "76 $d" "plist_programs \"$d\""
done
n=$(ls /Library/LaunchDaemons/*.plist /Library/LaunchAgents/*.plist 2>/dev/null | wc -l | tr -d ' ')
note "77 $n"
for h in "${HOMES[@]}"; do
  n=$(ls "$h/Library/LaunchAgents"/*.plist 2>/dev/null | wc -l | tr -d ' ')
  [ "$n" -gt 0 ] && note "78 $h/Library/LaunchAgents $n"
done
run 60 "79" 'echo "-- system:"; launchctl list 2>&1 | grep -vE "[[:space:]]com\.apple\."; echo; echo "-- user $REALUSER:"; asuser launchctl list 2>&1 | grep -vE "[[:space:]]com\.apple\."'
run 90 "80" 'launchctl print system 2>&1'
run 90 "81" 'launchctl print "user/$REALUID" 2>&1; echo; echo "======== gui"; launchctl print "gui/$REALUID" 2>&1'
run 60 "82" 'echo "-- system domain:"; launchctl print system 2>/dev/null | grep -E "^[[:space:]]*path = " | grep -vE "/System/Library/|/Library/Apple/" | sort -u; echo "-- gui domain:"; launchctl print "gui/$REALUID" 2>/dev/null | grep -E "^[[:space:]]*path = " | grep -vE "/System/Library/|/Library/Apple/" | sort -u'
run 30 "83" 'echo "launchctl getenv DYLD_INSERT_LIBRARIES: [$(launchctl getenv DYLD_INSERT_LIBRARIES 2>/dev/null)]"; echo; echo "-- plists mentioning DYLD_:"; grep -rl "DYLD_" /Library/LaunchDaemons /Library/LaunchAgents /var/root/Library/LaunchAgents /Users/*/Library/LaunchAgents 2>/dev/null; echo; echo "-- launchd environment mentioning DYLD:"; launchctl print "gui/$REALUID" 2>/dev/null | grep -i dyld; launchctl print system 2>/dev/null | grep -i dyld; echo "-- /etc/launchd.conf:"; cat /etc/launchd.conf 2>&1'
hit 'DYLD_INSERT_LIBRARIES: \[.+\]' && flag "84"
if lastout | grep -q '^/.*\.plist$'; then flag "85 $(lastout | grep '^/.*\.plist$' | tr '\n' ' ')"; fi
run 60 "86" 'ls -laO /Library/PrivilegedHelperTools 2>&1; for f in /Library/PrivilegedHelperTools/*; do [ -e "$f" ] || continue; echo "== $f"; sigcheck "$f"; done'
run 20 "87" 'ls -laO /Library/StartupItems /System/Library/StartupItems /etc/emond.d /etc/emond.d/rules 2>&1; for f in /etc/emond.d/rules/*; do [ -e "$f" ] && { echo "== $f"; plutil -p "$f"; }; done; ls -la /etc/rc* /etc/launchd.conf 2>&1'
[ -n "$(ls -A /Library/StartupItems 2>/dev/null)" ] && flag "88"

section 06.txt
run 120 "89" 'if command -v sfltool >/dev/null 2>&1; then sfltool dumpbtm 2>&1; else echo "233"; fi'
n=$(lastout | grep -ciE 'Team Identifier')
note "90 $n"
run 20 "91" 'for h in "${HOMES[@]}"; do d="$h/Library/Application Support/com.apple.backgroundtaskmanagement"; [ -d "$d" ] && { echo "== $d"; ls -la "$d"; }; done; ls -la /private/var/db/com.apple.backgroundtaskmanagement 2>&1'

section 07.txt
run 30 "92" 'for u in $(dscl . -list /Users 2>/dev/null); do c=$(crontab -u "$u" -l 2>/dev/null); [ -n "$c" ] && { echo "== crontab for $u"; echo "$c"; echo; }; done; echo "-- /usr/lib/cron/tabs:"; ls -la /usr/lib/cron/tabs 2>&1; for f in /usr/lib/cron/tabs/*; do [ -e "$f" ] && { echo "== $f"; cat "$f"; }; done; echo; echo "-- /etc/crontab:"; cat /etc/crontab 2>&1; echo "-- at jobs:"; atq 2>&1; ls -la /private/var/at/jobs 2>&1'
hit '^== crontab for|^== /usr/lib/cron/tabs/' && flag "93"
run 30 "94" 'cat /etc/periodic.conf /etc/periodic.conf.local 2>&1; ls -laR /etc/periodic 2>&1; ls -la /usr/local/etc/periodic 2>&1; echo "-- periodic scripts newer than the setup marker:"; find /etc/periodic /usr/local/etc/periodic -type f -newer "$SETUP_MARK" 2>/dev/null'
run 60 "95" 'for h in "${HOMES[@]}"; do for f in .zshrc .zprofile .zshenv .zlogin .zlogout .bash_profile .bashrc .bash_login .bash_logout .profile .inputrc .hushlogin .config/fish/config.fish .zsh_history .bash_history; do p="$h/$f"; [ -e "$p" ] || continue; case "$f" in *_history) echo "== $p ($(wc -l < "$p" | tr -d " ") lines), last 60:"; tail -60 "$p";; *) echo "== $p"; ls -laO "$p"; cat "$p";; esac; echo; done; done'
run 30 "96" 'for f in /etc/zshrc /etc/zprofile /etc/zshenv /etc/zlogin /etc/zlogout /etc/profile /etc/bashrc /etc/bashrc_Apple_Terminal /etc/zshrc_Apple_Terminal /etc/csh.cshrc /etc/csh.login /etc/csh.logout /etc/shells /etc/paths /etc/paths.d/* /etc/manpaths.d/*; do [ -e "$f" ] || continue; echo "== $f"; ls -laO "$f"; cat "$f"; echo; done'
run 30 "97" 'for h in "${HOMES[@]}"; do f="$h/Library/Preferences/com.apple.Terminal.plist"; [ -e "$f" ] && { echo "== $f"; plutil -p "$f" | grep -iE "CommandString|RunCommandAsShell|\"Shell\"|Default Window Settings|Startup Window Settings"; }; done'
hit 'CommandString' && note "98"
run 30 "99" 'ls -la "/Library/Scripts/Folder Action Scripts" 2>&1; for h in "${HOMES[@]}"; do ls -la "$h/Library/Scripts/Folder Action Scripts" 2>/dev/null; f="$h/Library/Preferences/com.apple.FolderActionsDispatcher.plist"; [ -e "$f" ] && { echo "== $f"; plutil -p "$f"; }; d="$h/Library/Shortcuts"; [ -d "$d" ] && { echo "== $d"; ls -la "$d"; sqlite3 "$d/Shortcuts.sqlite" "$SQL_SHORTCUTS" 2>&1 || sqlite3 "$d/Shortcuts.sqlite" ".tables" 2>&1; }; done'

section 08.txt
run 60 "100" 'kmutil showloaded --list-only 2>&1 || kextstat 2>&1'
if lastout | grep -vE 'com\.apple\.|^Index|^Executing|^No variant|^\s*$|^\[' | grep -q .; then flag "101"; fi
run 60 "102" 'systemextensionsctl list 2>&1; echo; ls -la /Library/SystemExtensions 2>&1; ls -la /Library/SystemExtensions/*/ 2>&1'
if lastout | grep -q '\[activated'; then flag "103"; fi
run 30 "104" 'ls -laO /Library/Extensions 2>&1; echo; echo "/System/Library/Extensions count: $(ls /System/Library/Extensions 2>/dev/null | wc -l | tr -d " ")"'

section 09.txt
run 60 "105" 'profiles status -type enrollment 2>&1'
hit 'MDM enrollment: Yes' && flag "106"
hit 'Enrolled via DEP: Yes' && flag "107"
run 60 "108" 'profiles list 2>&1; echo ======; profiles show 2>&1; echo ======; profiles show -type enrollment 2>&1; echo ======; profiles list -user "$REALUSER" 2>&1; echo ======; profiles show -user "$REALUSER" 2>&1'
if lastout | grep -qiE 'profileIdentifier'; then flag "109"; fi
run 120 "110" 'system_profiler SPConfigurationProfileDataType SPManagedClientDataType 2>&1'
run 30 "111" 'ls -laR "/Library/Managed Preferences" 2>&1; for f in "/Library/Managed Preferences"/*.plist "/Library/Managed Preferences"/*/*.plist; do [ -e "$f" ] && { echo "== $f"; plutil -p "$f"; }; done; echo; ls -la /var/db/ConfigurationProfiles /var/db/ConfigurationProfiles/Store 2>&1'
if find "/Library/Managed Preferences" -name '*.plist' 2>/dev/null | grep -q .; then flag "112"; fi

section 10.txt
run 60 "113" 'dump_certs /Library/Keychains/System.keychain system'
n=$(lastout | grep -c '^-- ')
note "114 $n"
lastout | grep -q 'CA:TRUE' && flag "115"
for h in "${HOMES[@]}"; do
  kc="$h/Library/Keychains/login.keychain-db"
  [ -e "$kc" ] || continue
  run 60 "116 $kc" "dump_certs \"$kc\" login_$(basename "$h")"
  lastout | grep -q 'CA:TRUE' && note "117 $kc"
done
run 30 "118" 'echo "-- admin:"; security dump-trust-settings -d 2>&1; echo; echo "-- user ($REALUSER):"; asuser security dump-trust-settings 2>&1'
lastout | grep -q 'Number of trusted certs = [1-9]' && flag "119"
run 30 "120" 'asuser security find-identity -v 2>&1; echo; asuser security list-keychains 2>&1; echo; security list-keychains -d system 2>&1'

section 11.txt
run 90 "121" 'networksetup -listallhardwareports 2>&1; echo; networksetup -listnetworkserviceorder 2>&1; echo; networksetup -listallnetworkservices 2>&1 | tail -n +2 | while IFS= read -r s; do s="${s#\*}"; echo "=================== [$s]"; networksetup -getinfo "$s" 2>&1; echo "-- DNS:"; networksetup -getdnsservers "$s" 2>&1; echo "-- search domains:"; networksetup -getsearchdomains "$s" 2>&1; echo "-- web proxy:"; networksetup -getwebproxy "$s" 2>&1; echo "-- secure web proxy:"; networksetup -getsecurewebproxy "$s" 2>&1; echo "-- socks proxy:"; networksetup -getsocksfirewallproxy "$s" 2>&1; echo "-- auto proxy url:"; networksetup -getautoproxyurl "$s" 2>&1; echo "-- proxy autodiscovery:"; networksetup -getproxyautodiscovery "$s" 2>&1; echo "-- bypass:"; networksetup -getproxybypassdomains "$s" 2>&1; done'
if lastout | awk '/^-- (web|secure web|socks) proxy:/{p=1;next} /^--/{p=0} p && /^Enabled: Yes/' | grep -q .; then flag "122"; fi
if lastout | awk '/^-- auto proxy url/{p=1;next} /^--/{p=0} p && /^Enabled: Yes/' | grep -q .; then flag "123"; fi
if lastout | awk '/^-- proxy autodiscovery/{p=1;next} /^--/{p=0} p && /On/' | grep -q .; then note "124"; fi
if lastout | awk '/^-- DNS:/{p=1;next} /^--/{p=0} p' | grep -vqE "^There aren't any DNS Servers|^$"; then note "125 $(lastout | awk '/^-- DNS:/{p=1;next} /^--/{p=0} p' | grep -vE "There aren|^$" | tr '\n' ' ')"; fi
run 30 "126" 'scutil --dns 2>&1; echo ====; scutil --proxy 2>&1; echo ==== VPN configurations; scutil --nc list 2>&1; echo ====; scutil --nwi 2>&1'
if lastout | awk '/VPN configurations/{p=1;next} /^====/{p=0} p' | grep -qE '^\*? *\('; then flag "127"; fi
run 20 "128" 'echo "-- /etc/hosts:"; cat /etc/hosts 2>&1; echo; echo "-- /etc/resolv.conf:"; cat /etc/resolv.conf 2>&1; echo; ls -la /etc/resolver 2>&1'
if grep -vE '^[[:space:]]*#|^[[:space:]]*$|^127\.0\.0\.1[[:space:]]+localhost|^255\.255\.255\.255[[:space:]]+broadcasthost|^::1[[:space:]]+localhost' /etc/hosts 2>/dev/null | grep -q .; then flag "129"; fi
[ -d /etc/resolver ] && note "130"
run 60 "131" 'plutil -p /Library/Preferences/SystemConfiguration/preferences.plist 2>&1; echo =====; plutil -p /Library/Preferences/SystemConfiguration/NetworkInterfaces.plist 2>&1; echo "===== Internet Sharing:"; plutil -p /Library/Preferences/SystemConfiguration/com.apple.nat.plist 2>&1'
if lastout | awk '/Internet Sharing/{p=1} p' | grep -qE '"Enabled" => (1|true)'; then flag "132"; fi
run 90 "133" 'wifi_if=$(networksetup -listallhardwareports 2>/dev/null | awk "/Wi-Fi|AirPort/{getline; print \$2}" | head -1); echo "wifi interface: $wifi_if"; [ -n "$wifi_if" ] && networksetup -listpreferredwirelessnetworks "$wifi_if" 2>&1; echo; wdutil info 2>&1; echo; system_profiler SPAirPortDataType 2>&1'
run 60 "134" 'ifconfig -a 2>&1; echo "====== routes"; netstat -rn 2>&1; echo "====== default route"; route -n get default 2>&1; for i in $(ifconfig -l); do case "$i" in en*|bridge*) ;; *) continue;; esac; echo "====== DHCP packet on $i:"; ipconfig getpacket "$i" 2>&1; echo "====== summary $i:"; ipconfig getsummary "$i" 2>&1; done'
if [ -n "$DEFIF" ]; then case "$DEFIF" in en*|bridge*) ;; *) flag "135 $DEFIF";; esac; fi
hit -i 'option_252|wpad' && flag "136"

section 12.txt
run 60 "137" 'lsof -nP -i 2>&1'
run 60 "138" 'lsof -nP -iTCP -sTCP:LISTEN 2>&1; echo; lsof -nP -iUDP 2>&1'
run 120 "139" 'lsof -nP -iTCP -sTCP:LISTEN -F pcn 2>/dev/null | awk "/^p/{pid=substr(\$0,2)} /^c/{cmd=substr(\$0,2)} /^n/{print pid, cmd, substr(\$0,2)}" | sort -u | while read -r pid cmd addr; do path=$(ps -o comm= -p "$pid" 2>/dev/null); echo "== pid $pid  $addr  [$path]"; [ -n "$path" ] && sigcheck "$path"; done'
run 30 "140" 'netstat -anv -p tcp 2>&1; echo; netstat -anv -p udp 2>&1'
run 40 "141" 'nettop -P -l 1 -n 2>&1'
run 20 "142" 'arp -an 2>&1; echo; ndp -an 2>&1'
dups=$(arp -an 2>/dev/null | awk '{print $4}' | grep -E '^([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}$' | sort | uniq -d | tr '\n' ' ')
[ -n "$dups" ] && note "143 $dups"

section 13.txt
run 20 "144" 'echo "default gateway: $GW via $DEFIF"; echo "resolvers in use: $RESOLVERS"; echo; echo "-- ARP entry for the gateway:"; arp -an 2>/dev/null | grep -F "($GW)"; gwmac=$(arp -an 2>/dev/null | grep -F "($GW)" | awk "{print \$4}" | head -1); echo "gateway MAC: $gwmac"; echo "-- other IPs with the same MAC:"; [ -n "$gwmac" ] && arp -an | grep -F "$gwmac" | grep -vF "($GW)"'
run 90 "145" 'for r in $RESOLVERS $GW; do echo "== resolver $r"; printf "  www.apple.com -> "; dig +short +time=3 +tries=1 www.apple.com @"$r" 2>&1 | tr "\n" " "; echo; printf "  bogus name -> "; dig +short +time=3 +tries=1 "nx-test-$RANDOM$RANDOM.com" @"$r" 2>&1 | tr "\n" " "; echo; done; echo "== reference 1.1.1.1 / 8.8.8.8:"; dig +short +time=3 +tries=1 www.apple.com @1.1.1.1 2>&1 | tr "\n" " "; echo; dig +short +time=3 +tries=1 www.apple.com @8.8.8.8 2>&1 | tr "\n" " "; echo'
if lastout | grep -E 'bogus name -> [0-9]' | grep -q .; then flag "146"; fi
run 90 "147" 'printf "system-resolver egress (TXT o-o.myaddr.l.google.com): "; egress=$(dig +short +time=4 +tries=1 TXT o-o.myaddr.l.google.com 2>&1 | tr -d "\"" | head -1); echo "$egress"; [ -n "$egress" ] && { echo "-- owner of resolver egress $egress:"; whois -h whois.cymru.com " -v $egress" 2>&1; }; echo; printf "public IP (opendns): "; ip=$(dig +short +time=4 +tries=1 myip.opendns.com @resolver1.opendns.com 2>&1 | head -1); echo "$ip"; printf "public IP (https): "; curl -fsS --max-time 10 https://api.ipify.org 2>&1; echo; [ -n "$ip" ] && { echo "-- owner of $ip:"; whois -h whois.cymru.com " -v $ip" 2>&1; }'
run 120 "148" 'for host in www.apple.com appleid.apple.com www.icloud.com accounts.google.com login.microsoftonline.com outlook.office.com github.com $EXTRA_HOSTS; do echo "== $host"; nc -z -G 4 "$host" 443 2>/dev/null || { echo "  (port 443 unreachable)"; continue; }; echo | openssl s_client -connect "$host:443" -servername "$host" 2>/dev/null | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256 2>&1 | sed "s/^/  /"; curl -sS --max-time 10 -o /dev/null -w "  curl verify=%{ssl_verify_result} http=%{http_code}\n" "https://$host/" 2>&1; done'
if lastout | grep -E 'curl verify=[1-9]' | grep -q .; then flag "149"; fi
lastout | grep -E '^\s*issuer=' | sed -E 's/.*CN *= *//; s#[/,].*##' | sort -u | while read -r cn; do
  [ -n "$cn" ] || continue
  if blockout "$OUT/10.txt" "118" | grep -qF "$cn"; then flag "150 $cn"; fi
done
run 60 "151" 'if [ -z "$GW" ]; then echo "235"; exit 0; fi; for p in 21 22 23 53 80 443 445 1900 5000 7547 8080 8443 8291 9000; do nc -z -G 2 "$GW" "$p" >/dev/null 2>&1 && echo "open: $p"; done; echo; curl -sS --max-time 5 -I "http://$GW/" 2>&1 | head -12; echo; echo | openssl s_client -connect "$GW:443" 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>&1'
hit '^open: (23|7547)$' && note "152"

section 14.txt
run 30 "153" 'ps -axo pid,ppid,user,lstart,etime,%cpu,%mem,comm -ww 2>&1'
run 30 "154" 'ps -axo pid,user,args -ww 2>&1'
run 300 "155" 'ps -axo comm= 2>/dev/null | grep "^/" | sort -u | while IFS= read -r p; do echo "== $p"; sigcheck "$p"; done'
n=$(lastout | grep -c '^FLAG:')
[ "$n" -gt 0 ] && flag "156 $n"
FLAGGED=$(lastout | grep '^FLAG:' | awk -F'  ' '{print $2}' | head -10)
run 30 "157" 'ps -axo pid,user,comm -ww 2>/dev/null | grep -E "/(private/)?tmp/|/var/tmp/|/private/var/folders/|/Users/Shared/|/\.[^/]" '
hit '.' && flag "158"
run 30 "159" 'ps -axo pid,user,comm -ww 2>/dev/null | grep -E "/Users/[^/]+/(Library|Downloads|Documents|Public|Desktop)/|/Library/Application Support/" '
hit '.' && note "160"
if [ -n "$FLAGGED" ]; then
  run 120 "161" 'printf "%s\n" "$FLAGGED" | while IFS= read -r p; do [ -n "$p" ] || continue; for pid in $(pids_of_path "$p"); do echo "== $p (pid $pid)"; lsof -nP -p "$pid" 2>&1 | head -80; done; done'
fi

section 15.txt
run 10 "162" 'echo "231"'
run 30 "163" 'db="/Library/Application Support/com.apple.TCC/TCC.db"; sqlite3 "$db" "$SQL_TCC" 2>&1 || sqlite3 "$db" "$SQL_TCC_FALLBACK" 2>&1'
if lastout | grep -qiE 'unable to open|authorization denied|not a database|Operation not permitted'; then
  flag "164"
else
  lastout | grep -E '^kTCCService(ScreenCapture|Accessibility|PostEvent|ListenEvent|SystemPolicyAllFiles|AppleEvents|Microphone|Camera|SystemPolicySysAdminFiles|DeveloperTool|RemoteDesktop)\|' | grep -vE '\|com\.apple\.' | awk -F'|' '$4=="2"' | while IFS='|' read -r svc cli rest; do flag "165 $cli $svc"; done
fi
for h in "${HOMES[@]}"; do
  db="$h/Library/Application Support/com.apple.TCC/TCC.db"
  [ -e "$db" ] || continue
  run 30 "166 $db" 'sqlite3 "$db" "$SQL_TCC" 2>&1 || sqlite3 "$db" "$SQL_TCC_FALLBACK" 2>&1'
  if lastout | grep -qiE 'unable to open|authorization denied|not a database|Operation not permitted'; then
    flag "167 $h"
  else
    lastout | grep -E '^kTCCService(ScreenCapture|Accessibility|PostEvent|ListenEvent|SystemPolicyAllFiles|AppleEvents|Microphone|Camera|SystemPolicySysAdminFiles|DeveloperTool|RemoteDesktop)\|' | grep -vE '\|com\.apple\.' | awk -F'|' '$4=="2"' | while IFS='|' read -r svc cli rest; do flag "168 $h $cli $svc"; done
  fi
done

section 16.txt
run 300 "169" 'system_profiler SPApplicationsDataType 2>&1'
run 120 "170" 'system_profiler SPInstallHistoryDataType 2>&1'
run 120 "171" 'for p in $(pkgutil --pkgs 2>/dev/null | grep -v "^com\.apple\."); do echo "== $p"; info=$(pkgutil --pkg-info "$p" 2>&1); echo "$info" | grep -E "location|version"; t=$(echo "$info" | awk "/install-time/{print \$2}"); [ -n "$t" ] && echo "installed: $(date -r "$t" 2>/dev/null)"; done'
run 60 "172" 'ls -laO /Applications 2>&1; echo; ls -laO /Applications/Utilities 2>&1; for h in "${HOMES[@]}"; do [ -d "$h/Applications" ] && { echo "== $h/Applications"; ls -laO "$h/Applications"; }; done; echo "== /Users/Shared"; ls -laO /Users/Shared 2>&1'
hit '^[^ ]+[ ]+[^ ]+[ ]+[^ ]+[ ]+[^ ]+[ ]+[^ ]*hidden' && flag "173"
run 300 "174" 'find /Users /Library /usr/local /opt /private/tmp /private/var/tmp /private/var/root /Users/Shared /private/var/folders -maxdepth 7 -name "*.app" -type d -not -path "*/.Trash/*" -not -path "*/Caches/*" -not -path "/Library/Apple/*" -not -path "*/Contents/*" 2>/dev/null | head -250 | while IFS= read -r a; do echo "== $a"; ls -ldO "$a"; sigcheck "$a"; done'
run 60 "175" 'for a in /Applications/*.app /Applications/*/*.app; do [ -d "$a" ] || continue; q=$(xattr -p com.apple.quarantine "$a" 2>/dev/null); echo "$(basename "$a"): ${q:-234}"; done'
run 60 "176" 'for a in /Applications/*.app /Applications/*/*.app "$REALHOME"/Applications/*.app; do [ -d "$a" ] || continue; ui=$(plutil -extract LSUIElement raw -o - "$a/Contents/Info.plist" 2>/dev/null); bg=$(plutil -extract LSBackgroundOnly raw -o - "$a/Contents/Info.plist" 2>/dev/null); case "$ui$bg" in *1*|*true*) echo "$a  (LSUIElement=$ui LSBackgroundOnly=$bg)";; esac; done'
run 60 "177" 'for d in /Library/ScriptingAdditions /Library/InputManagers "/Library/Input Methods" /Library/Spotlight /Library/QuickLook "/Library/Internet Plug-Ins" /Library/PreferencePanes "/Library/Audio/Plug-Ins/HAL" "/Library/Screen Savers" /Library/Frameworks "/Library/Application Support" "/Library/Mail/Bundles" /Library/Google /Library/Python; do [ -d "$d" ] && { echo "== $d"; ls -laO "$d"; }; done; for h in "${HOMES[@]}"; do for s in ScriptingAdditions InputManagers "Input Methods" Spotlight QuickLook "Internet Plug-Ins" PreferencePanes Frameworks "Screen Savers" "Application Support" Containers "Group Containers" "Mail/Bundles"; do d="$h/Library/$s"; [ -d "$d" ] && { echo "== $d"; ls -laO "$d"; }; done; done'
for d in /Library/ScriptingAdditions /Library/InputManagers "/Library/Mail/Bundles"; do [ -n "$(ls -A "$d" 2>/dev/null)" ] && flag "178 $d"; done

section 17.txt
for h in "${HOMES[@]}"; do
  db="$h/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
  [ -e "$db" ] || continue
  run 30 "179 $h" 'sqlite3 -header "$db" "$SQL_QUARANTINE" 2>&1'
  n=$(lastout | grep -c '^20')
  note "180 $h $n"
  run 30 "181 $h/Downloads" 'ls -laO@ "$h/Downloads" 2>&1 | head -200'
done

section 18.txt
for h in "${HOMES[@]}"; do
  run 20 "182 $h" 'plutil -p "$h/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist" 2>&1'
  run 60 "183 $h" 'ls -la "$h/Library/Safari" 2>&1 | head -60; echo; ls -la "$h/Library/Containers/com.apple.Safari/Data/Library/Safari" 2>&1 | head -40; echo "-- Safari prefs of interest:"; for f in "$h/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari.plist" "$h/Library/Preferences/com.apple.Safari.plist"; do [ -e "$f" ] && plutil -p "$f" 2>/dev/null | grep -iE "HomePage|SearchProvider|ExtensionsEnabled|ManagedPayload|Proxy"; done; echo "-- Safari extensions store:"; plutil -p "$h/Library/Safari/Extensions/Extensions.plist" 2>&1 | head -80'
  run 60 "184 $h" 'for base in "$h/Library/Application Support/Google/Chrome" "$h/Library/Application Support/Microsoft Edge" "$h/Library/Application Support/BraveSoftware/Brave-Browser" "$h/Library/Application Support/Vivaldi" "$h/Library/Application Support/Arc/User Data"; do [ -d "$base" ] || continue; echo "========= $base"; for m in "$base"/*/Extensions/*/*/manifest.json; do [ -e "$m" ] || continue; echo "-- $m"; grep -E "\"(name|version|update_url)\"" "$m" | head -4; done; [ -d "$base/External Extensions" ] && { echo "!! External Extensions dir present: $base/External Extensions"; ls -la "$base/External Extensions"; }; done; for ee in "/Library/Application Support/Google/Chrome/External Extensions" "/Library/Application Support/Google/Chrome/NativeMessagingHosts" "$h/Library/Application Support/Google/Chrome/NativeMessagingHosts" "/Library/Google/Chrome/NativeMessagingHosts" "$h/Library/Application Support/Mozilla/NativeMessagingHosts" "/Library/Application Support/Mozilla/NativeMessagingHosts" "$h/Library/Application Support/Microsoft Edge/NativeMessagingHosts"; do [ -d "$ee" ] && { echo "!! present: $ee"; ls -la "$ee"; for f in "$ee"/*.json; do [ -e "$f" ] && { echo "-- $f"; cat "$f"; echo; }; done; }; done; echo "-- browser policy plists:"; for f in "$h/Library/Preferences/com.google.Chrome.plist" "$h/Library/Preferences/com.microsoft.Edge.plist" "$h/Library/Preferences/com.brave.Browser.plist" /Library/Preferences/com.google.Chrome.plist /Library/Preferences/com.microsoft.Edge.plist; do [ -e "$f" ] && { echo "== $f"; plutil -p "$f"; }; done'
  hit 'External Extensions dir present' && flag "185 $h"
  hit 'ExtensionInstallForcelist' && flag "186 $h"
  hit '^!! present: .*NativeMessagingHosts' && note "187 $h"
  run 60 "188 $h" 'for p in "$h/Library/Application Support/Firefox/Profiles"/*; do [ -d "$p" ] || continue; echo "== profile $p"; [ -e "$p/extensions.json" ] && grep -oE "\"(name|id|sourceURI|version)\":\"[^\"]*\"" "$p/extensions.json" | head -80; [ -e "$p/user.js" ] && { echo "!! user.js present:"; cat "$p/user.js"; }; done; for f in "/Applications/Firefox.app/Contents/Resources/distribution/policies.json"; do [ -e "$f" ] && { echo "== $f"; cat "$f" | head -100; }; done; f="$h/Library/Preferences/org.mozilla.firefox.plist"; [ -e "$f" ] && { echo "== $f"; plutil -p "$f" | head -100; }'
  hit 'user.js present' && flag "189 $h"
done
run 60 "190 $REALUSER" 'asuser pluginkit -mvv 2>&1'
run 120 "191" '/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump 2>/dev/null | grep -iE "^[[:space:]]*(claimed schemes|bindings):" | sort | uniq -c | sort -rn | head -150'

section 19.txt
for h in "${HOMES[@]}"; do
  run 30 "192 $h" 'db="$h/Library/Accounts/Accounts4.sqlite"; [ -e "$db" ] || { echo "(none)"; exit 0; }; sqlite3 -header "$db" "$SQL_ACCOUNTS" 2>&1 || sqlite3 -header "$db" "$SQL_ACCOUNTS_FALLBACK" 2>&1'
  run 20 "193 $h" 'plutil -p "$h/Library/Preferences/MobileMeAccounts.plist" 2>&1 | grep -E "AccountID|AccountDescription|DisplayName|\"Name\"|Enabled|LoggedIn|ServiceID|primaryEmail"'
  run 60 "194 $h" 'for d in "$h/Library/Mail"/V*/MailData; do [ -d "$d" ] || continue; echo "== $d"; ls -la "$d" | grep -iE "rule|signature|accounts"; for f in SyncedRules.plist UnsyncedRules.plist RulesActiveState.plist; do [ -e "$d/$f" ] && { echo "-- $f"; plutil -p "$d/$f"; }; done; done; f="$h/Library/Containers/com.apple.mail/Data/Library/Preferences/com.apple.mail.plist"; [ -e "$f" ] && { echo "== $f (filtered)"; plutil -p "$f" | grep -iE "Account|SMTP|Hostname|Username|Redirect|Forward|Signature" | head -120; }'
  if lastout | grep -iqE 'ForwardTo|RedirectTo|"Forward"|"Redirect'; then flag "195 $h"; fi
done

section 20.txt
run 60 "196" 'for d in /private/tmp /private/var/tmp /Users/Shared /usr/local /usr/local/bin /usr/local/sbin /usr/local/lib /opt /opt/homebrew/bin /opt/local/bin /private/var/root /private/var/root/Library "/Library/WebServer/Documents" /private/etc/paths.d; do [ -d "$d" ] && { echo "== $d"; ls -laO "$d" | head -100; }; done'
run 60 "197" 'for h in "${HOMES[@]}"; do echo "== $h"; ls -laO "$h"; echo "-- $h/Library:"; ls -laO "$h/Library" 2>&1; done'
run 180 "198" 'find /Library /Users /usr/local /opt /private/etc /private/var/root /private/tmp -xdev -flags +uchg,schg 2>/dev/null | head -200'
hit '^/' && flag "199"
run 300 "200" 'find /System/Volumes/Data -xdev -type f \( -perm -4000 -o -perm -2000 \) -not -path "/System/Volumes/Data/System/*" -not -path "/System/Volumes/Data/usr/bin/*" -not -path "/System/Volumes/Data/usr/sbin/*" -not -path "/System/Volumes/Data/usr/libexec/*" -not -path "/System/Volumes/Data/bin/*" -not -path "/System/Volumes/Data/sbin/*" -exec ls -lO {} \; 2>/dev/null | head -300'
hit '^-' && note "201"
run 600 "202" 'find /System/Volumes/Data -xdev -type f -perm -100 -newer "$SETUP_MARK" -not -path "/System/Volumes/Data/System/*" -not -path "/System/Volumes/Data/private/var/db/*" -not -path "/System/Volumes/Data/private/var/folders/*" -not -path "/System/Volumes/Data/private/var/log/*" -not -path "/System/Volumes/Data/usr/share/*" -not -path "*/Caches/*" -not -path "*/.Trash/*" -not -path "*/node_modules/*" 2>/dev/null | head -5000'
n=$(lastout | grep -c '^/')
note "203 $n"

section 21.txt
run 60 "204" 'diskutil list 2>&1; echo; mount 2>&1; echo; df -h 2>&1; echo; ls -la /Volumes 2>&1'
run 60 "205" 'diskutil apfs list 2>&1'
run 30 "206" 'diskutil apfs listUsers / 2>&1; echo; echo "-- fdesetup list:"; fdesetup list 2>&1'
run 30 "207" 'tmutil destinationinfo 2>&1; echo; plutil -p /Library/Preferences/com.apple.TimeMachine.plist 2>&1 | head -60'

section 22.txt
run 30 "208" 'ls -la /var/log 2>&1; echo; ls -lat /Library/Logs 2>&1 | head -40; echo; ls -lat /Library/Logs/DiagnosticReports 2>&1 | head -50; for h in "${HOMES[@]}"; do echo "== $h/Library/Logs/DiagnosticReports"; ls -lat "$h/Library/Logs/DiagnosticReports" 2>&1 | head -30; done'
run 60 "209" 'grep -E "Installed \"|installing|PackageKit: Install" /var/log/install.log 2>/dev/null | tail -300; echo "======= tail"; tail -150 /var/log/install.log 2>&1'
run 60 "210" 'tail -200 /var/log/system.log 2>&1; echo =====; ls /var/log/wifi* 2>/dev/null && tail -100 /var/log/wifi.log 2>&1'
run 600 "211" 'log show --last 3d --style compact --predicate "$PRED_AUTH" 2>&1 | tail -3000'
run 300 "212" 'log show --last 14d --style compact --predicate "$PRED_XPROTECT" 2>&1 | tail -400'
if lastout | grep -i 'status_message' | grep -viE 'no threats|not detected' | grep -q .; then note "213"; fi

section 23.txt
run 120 "214" 'system_profiler SPUSBDataType SPThunderboltDataType SPBluetoothDataType 2>&1'
run 30 "215" 'system_profiler SPBluetoothDataType 2>/dev/null | grep -iE "keyboard|mouse|trackpad|Minor Type|Connected|Paired"'
run 30 "216" 'ioreg -p IOUSB -l -w0 2>/dev/null | grep -E "\"USB Product Name\"|\"USB Vendor Name\"|\"idVendor\"|\"idProduct\"|\"USB Serial Number\""'

section_done
{
  echo "=================================================================="
  echo "macaudit $VERSION  |  host: $HOSTSHORT  |  user: $REALUSER  |  $(date)"
  echo "$(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null))  |  setup marker: $(stat -f %Sm "$SETUP_MARK" 2>/dev/null)"
  echo "242 $FDA | sha256 $(openssl dgst -sha256 "$0" 2>/dev/null | awk '{print $NF}')"
  echo "gateway: ${GW:-?} via ${DEFIF:-?}  |  resolvers: ${RESOLVERS:-?}"
  echo "elapsed: $(( $(date +%s) - START_EPOCH ))s"
  echo "=================================================================="
  echo
  echo "#### 236"
  if [ -s "$FLAGFILE" ]; then grep '^FLAG' "$FLAGFILE"; echo; grep '^note' "$FLAGFILE"; else echo "(none)"; fi
  echo
  echo "#### 237"
  sigs=$(grep -n 'FLAG:' "$OUT"/[0-9][0-9].txt 2>/dev/null | grep -vE ':[0-9]+:(#|\$ )' | sed "s|^$OUT/||")
  if [ -n "$sigs" ]; then printf '%s\n' "$sigs"; else echo "(none)"; fi
  echo
  echo "#### 238"
  echo "  239"
  echo "  240"
  echo "  241"
} > "$SUMMARY"
rm -f "$FLAGFILE"

ZIP="$OUT.zip"
( cd "$(dirname "$OUT")" && ditto -c -k --keepParent "$(basename "$OUT")" "$ZIP" )
chown -R "$REALUSER" "$OUT" "$ZIP" 2>/dev/null
HASH=$(openssl dgst -sha256 "$ZIP" 2>/dev/null | awk '{print $NF}')

printf '\n==== DONE in %ss ====\nfolder: %s\nzip:    %s\nzip sha256: %s\n\n' "$(( $(date +%s) - START_EPOCH ))" "$OUT" "$ZIP" "$HASH"
cat "$SUMMARY"
launchctl asuser "$REALUID" sudo -u "$REALUSER" open "$OUT" >/dev/null 2>&1
exit 0
