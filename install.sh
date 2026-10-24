#!/bin/bash
# Installs what Hide Me needs and adds "Hide Me" to ~/Applications.
#   ./install.sh              install
#   ./install.sh --uninstall  remove the app and the login helper
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
app="$HOME/Applications/Hide Me.app"
agent_label="com.lillybaba1.hideme.restore"
agent="$HOME/Library/LaunchAgents/$agent_label.plist"

if [[ "${1:-}" == "--uninstall" ]]; then
  launchctl bootout "gui/$(id -u)" "$agent" 2>/dev/null || true
  rm -rf "$app" "$agent"
  echo "Removed Hide Me. (Tor stays installed; remove it with: brew uninstall tor)"
  exit 0
fi

if [[ "$(uname)" != "Darwin" ]]; then
  echo "Hide Me is for macOS." >&2
  exit 1
fi

# Homebrew isn't on PATH in every shell, so look in its usual places too.
for b in /opt/homebrew/bin/brew /usr/local/bin/brew; do
  if ! command -v brew >/dev/null 2>&1 && [[ -x "$b" ]]; then
    eval "$("$b" shellenv)"
  fi
done
if ! command -v brew >/dev/null 2>&1; then
  echo "Hide Me needs Homebrew. Install it from https://brew.sh, then run this again." >&2
  exit 1
fi

echo "Installing Tor and Python's window toolkit with Homebrew..."
brew install tor python-tk

python="$(brew --prefix)/bin/python3"
if ! "$python" -c "import tkinter" 2>/dev/null; then
  echo "Python at $python can't open windows (tkinter is missing)." >&2
  exit 1
fi

mkdir -p "$app/Contents/MacOS"
cat > "$app/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Hide Me</string>
  <key>CFBundleIdentifier</key><string>com.lillybaba1.hideme</string>
  <key>CFBundleExecutable</key><string>HideMe</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
</dict>
</plist>
EOF
{
  echo "#!/bin/bash"
  printf 'exec %q %q\n' "$python" "$here/hideme.py"
} > "$app/Contents/MacOS/HideMe"
chmod +x "$app/Contents/MacOS/HideMe"

# At every login, undo settings left behind if the Mac shut down while Hide Me was on.
# It does nothing (and asks for nothing) when Hide Me was switched off properly.
mkdir -p "$(dirname "$agent")"
cat > "$agent" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$agent_label</string>
  <key>ProgramArguments</key>
  <array>
    <string>$python</string>
    <string>$here/hideme.py</string>
    <string>--restore</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
EOF

echo
echo "Done. Open \"Hide Me\" from your Applications folder (or Spotlight)."
echo "Keep this folder where it is: the app runs the code from $here"
