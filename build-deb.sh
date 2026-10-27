#!/usr/bin/env bash
# Собирает singbox-panel_<версия>_all.deb
#   ./build-deb.sh [версия]        (по умолчанию 1.0.0)
#   MAINTAINER="Имя <почта>" ./build-deb.sh
# Нужен только dpkg-deb (dpkg >= 1.19). Права root не требуются.
set -euo pipefail
cd "$(dirname "$0")"
VERSION="${1:-1.0.0}"
MAINTAINER="${MAINTAINER:-singbox-panel <root@localhost>}"
PKG=singbox-panel
OUT="${PKG}_${VERSION}_all.deb"
EPOCH="${SOURCE_DATE_EPOCH:-$(date +%s)}"

command -v dpkg-deb >/dev/null || { echo "нужен dpkg-deb"; exit 1; }
# синтаксис должен подходить для Python 3.7 (Debian 10): без := , позиционных-только параметров и f"{x=}"
python3 -I -c "import ast;ast.parse(open('app.py',encoding='utf-8').read(), feature_version=(3, 7))"

S="$(mktemp -d)"; trap 'rm -rf "$S"' EXIT
R="$S/root"
install -d -m755 "$R/DEBIAN" "$R/usr/bin" "$R/usr/lib/singbox-panel" "$R/lib/systemd/system" \
                "$R/etc/default" "$R/etc/pam.d" "$R/usr/share/doc/$PKG"
sed "s|^APP_VERSION = \"dev\"|APP_VERSION = \"$VERSION\"|" app.py > "$R/usr/lib/singbox-panel/app.py"
sed "s|<meta name=\"panel-version\" content=\"dev\">|<meta name=\"panel-version\" content=\"$VERSION\">|" index.html > "$R/usr/lib/singbox-panel/index.html"
install -m644 CHANGELOG.md "$R/usr/lib/singbox-panel/CHANGELOG.md"
chmod 644 "$R/usr/lib/singbox-panel/app.py" "$R/usr/lib/singbox-panel/index.html"
grep -q "APP_VERSION = \"$VERSION\"" "$R/usr/lib/singbox-panel/app.py" && grep -q "content=\"$VERSION\"" "$R/usr/lib/singbox-panel/index.html" || { echo "не удалось проставить версию"; exit 1; }
install -m755 deb/singbox-panel "$R/usr/bin/singbox-panel"
install -m644 singbox-panel.service "$R/lib/systemd/system/"
install -m644 deb/default "$R/etc/default/singbox-panel"
install -m644 deb/pam-singbox-panel "$R/etc/pam.d/singbox-panel"
install -m644 deb/copyright deb/README.Debian "$R/usr/share/doc/$PKG/"
{
  echo "$PKG ($VERSION) stable; urgency=medium"
  echo
  echo "  * Сервер на стандартной библиотеке Python, вход через libpam; вкладка «Сеть»: шлюз, SOCKS5/HTTP-прокси в sing-box, запрет доступа из LAN."
  echo
  echo " -- $MAINTAINER  $(LC_ALL=C date -u -d "@$EPOCH" '+%a, %d %b %Y %H:%M:%S +0000')"
} | gzip -9n > "$R/usr/share/doc/$PKG/changelog.Debian.gz"
chmod 644 "$R/usr/share/doc/$PKG/changelog.Debian.gz"

install -m755 deb/postinst deb/prerm deb/postrm "$R/DEBIAN/"
printf "%s\n" /etc/default/singbox-panel /etc/pam.d/singbox-panel > "$R/DEBIAN/conffiles"
SIZE=$(du -sk --exclude=DEBIAN "$R" | cut -f1)
sed -e "s|@VERSION@|$VERSION|" -e "s|@MAINTAINER@|$MAINTAINER|" -e "s|@SIZE@|$SIZE|" \
    deb/control > "$R/DEBIAN/control"

find "$R" -exec touch -h -d "@$EPOCH" {} +
( cd "$R" && find . -path ./DEBIAN -prune -o -type f -print | sed 's|^\./||' | sort | xargs md5sum > DEBIAN/md5sums )
chmod 644 "$R/DEBIAN/md5sums"

dpkg-deb --root-owner-group -Zxz --build "$R" "$OUT" >/dev/null
echo "Готово: $OUT ($(du -h "$OUT" | cut -f1))"
SUM=$(sha256sum "$OUT" | cut -d' ' -f1)
python3 - "$VERSION" "$(basename "$OUT")" "$SUM" <<'PY'
import json, re, sys
ver, fn, sha = sys.argv[1:4]
log, cur = [], None
for line in open("CHANGELOG.md", encoding="utf-8"):
    m = re.match(r"^##\s+(\S+)", line)
    if m:
        cur = {"version": m.group(1), "changes": []}
        log.append(cur)
    elif cur is not None and line.startswith("- "):
        cur["changes"].append(line[2:].strip())
if not any(x["version"] == ver and x["changes"] for x in log):
    print("ВНИМАНИЕ: в CHANGELOG.md нет записи для версии " + ver, file=sys.stderr)
json.dump({"version": ver, "file": fn, "sha256": sha, "changelog": log[:20]}, open("latest.json", "w", encoding="utf-8"), ensure_ascii=False, indent=2)
open("latest.json", "a").write("\n")
PY
echo "latest.json: $VERSION, sha256 $SUM"
