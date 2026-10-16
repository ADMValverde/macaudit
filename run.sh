#!/bin/sh
# 266
# 267
# 268
# 269

URL="https://raw.githubusercontent.com/ADMValverde/macaudit/main/macaudit.sh"
EXPECT="be34f8d0e2173e7fca7e2bbb9b07f6d1075f4907c48ef61d7d1a64ec1565cef6"
HOSTS=""
UPLOAD_URL="https://www.dropbox.com/request/mr0zkoez9ma1wy7za1mv"
CURL_UPLOAD_URL=""
F="$HOME/macaudit.sh"

upload_zip() {
  ZIP=$(ls -t "$HOME"/macaudit_*.zip 2>/dev/null | head -1)
  [ -n "$ZIP" ] || { echo "no macaudit zip found in $HOME"; return 1; }
  echo "zip:    $ZIP"
  echo "sha256: $(openssl dgst -sha256 "$ZIP" | awk '{print $NF}')"
  if [ -n "$CURL_UPLOAD_URL" ]; then
    echo "uploading to $CURL_UPLOAD_URL"
    if curl -fsS -F "file=@$ZIP" "$CURL_UPLOAD_URL"; then echo; echo "upload done"; else echo "upload FAILED"; fi
  fi
  if [ -n "$UPLOAD_URL" ]; then
    open -R "$ZIP"
    open "$UPLOAD_URL"
    echo "The upload page is open in the browser and the zip is selected in Finder."
    echo "Drag the zip onto the page, or: Add files > Files from computer > Cmd+Shift+G > type ~ > pick the zip. Enter any name. Upload."
  fi
  return 0
}

case "${1:-}" in
  upload)
    upload_zip
    exit $?
    ;;
  tools)
    cd "$HOME/Downloads" || exit 1
    for app in KnockKnock BlockBlock; do
      u=$(curl -fsSL "https://api.github.com/repos/objective-see/$app/releases/latest" | grep -o '"browser_download_url": *"[^"]*\.zip"' | head -1 | sed 's/.*"\(https[^"]*\)"/\1/')
      echo "== $app: ${u:-no .zip asset found; download by hand from https://objective-see.org}"
      [ -n "$u" ] || continue
      curl -fsSLo "$app.zip" "$u" || { echo "download failed"; continue; }
      sudo ditto -xk "$app.zip" /Applications || { echo "unpack failed"; continue; }
      codesign -dv --verbose=4 "/Applications/$app.app" 2>&1 | grep -E '^(Authority|TeamIdentifier)'
      spctl -a -vv "/Applications/$app.app" 2>&1
    done
    open -a KnockKnock
    exit 0
    ;;
esac

if [ -f "$HOME/Downloads/macaudit.sh" ]; then
  cp "$HOME/Downloads/macaudit.sh" "$F"
  echo "270"
else
  curl -fsSLo "$F" "$URL" || { echo "DOWNLOAD FAILED: $URL"; exit 1; }
fi

H=$(openssl dgst -sha256 "$F" | awk '{print $NF}')
echo "sha256 of macaudit.sh: $H"
if [ "$H" != "$EXPECT" ]; then
  echo "HASH MISMATCH. STOP. Do not run it."
  exit 1
fi
echo "hash OK"

if sudo sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" 'SELECT count(*) FROM access;' >/dev/null 2>&1; then
  sudo caffeinate -i bash "$F" $HOSTS
  upload_zip
else
  open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
  echo "NO FULL DISK ACCESS for Terminal."
  echo "In the Settings pane that just opened: turn Terminal ON."
  echo "If Terminal is not listed: click +, press Cmd+Shift+G, type  /System/Applications/Utilities/Terminal.app  then Open, then turn it ON."
  echo "Then Cmd+Q Terminal, reopen it, and run:   sh ~/run.sh"
  exit 2
fi
