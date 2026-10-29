#!/usr/bin/env bash
# Per-user desktop integration: .dlb file type, "Open with DLB", and right-click entries
# for Nautilus (GNOME/Files) and Dolphin (KDE). Not tested on every desktop; harmless to remove:
#   rm ~/.local/share/applications/dlb.desktop ~/.local/share/mime/packages/dlb-mime.xml \
#      ~/.local/share/nautilus/scripts/*DLB* ~/.local/share/kio/servicemenus/dlb.desktop
# Usage: integration/linux/install.sh /path/to/dlb /path/to/app-bundle-dir
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI="${1:?path to the dlb CLI binary}"
APP="${2:-}"
install -Dm755 "$CLI" "$HOME/.local/bin/dlb"
install -Dm644 "$HERE/dlb-mime.xml" "$HOME/.local/share/mime/packages/dlb-mime.xml"
update-mime-database "$HOME/.local/share/mime" 2>/dev/null || true
ICON="$HERE/../../app/dlb_app/branding"
if [ -d "$ICON" ]; then
  install -Dm644 "$ICON/linux/dlb.png" "$HOME/.local/share/icons/hicolor/256x256/apps/dlb.png"
  for s in 16 32 48 64 128; do
    install -Dm644 "$ICON/png/icon-$s.png" "$HOME/.local/share/icons/hicolor/${s}x${s}/apps/dlb.png"
  done
  install -Dm644 "$ICON/dlb.svg" "$HOME/.local/share/icons/hicolor/scalable/apps/dlb.svg"
  gtk-update-icon-cache -q "$HOME/.local/share/icons/hicolor" 2>/dev/null || true
fi
if [ -n "$APP" ]; then
  sed "s|^Exec=dlb_app|Exec=$APP/dlb_app|" "$HERE/dlb.desktop" > /tmp/dlb.desktop.$$
  install -Dm644 /tmp/dlb.desktop.$$ "$HOME/.local/share/applications/dlb.desktop"
  rm -f /tmp/dlb.desktop.$$
  update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
fi
# Nautilus: right click > Scripts
mkdir -p "$HOME/.local/share/nautilus/scripts"
cat > "$HOME/.local/share/nautilus/scripts/Compress with DLB" <<'SCRIPT'
#!/usr/bin/env bash
cd "$(dirname "$1")" || exit 1
out=$("$HOME/.local/bin/dlb" c -q "$@" 2>&1) && msg="Done" || msg="Failed"
notify-send "DLB" "$msg: $out" 2>/dev/null || echo "$out"
SCRIPT
chmod +x "$HOME/.local/share/nautilus/scripts/Compress with DLB"
# Dolphin: service menu
install -d "$HOME/.local/share/kio/servicemenus"
cat > "$HOME/.local/share/kio/servicemenus/dlb.desktop" <<'MENU'
[Desktop Entry]
Type=Service
MimeType=all/allfiles;inode/directory;
Actions=compress;extract;
X-KDE-Submenu=DLB

[Desktop Action compress]
Name=Compress with DLB
Exec=sh -c 'cd "$(dirname "$1")" && "$HOME/.local/bin/dlb" c "$1"' _ %f

[Desktop Action extract]
Name=Extract here (DLB)
Exec=sh -c 'cd "$(dirname "$1")" && "$HOME/.local/bin/dlb" x "$1"' _ %f
MENU
echo "Installed. Make sure ~/.local/bin is in your PATH."
