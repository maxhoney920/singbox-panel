#!/usr/bin/env bash
# Собирает один самодостаточный файл singbox-panel-installer.sh
# (внутри app.py + index.html + install.sh). Его достаточно скопировать на сервер
# и запустить: sudo bash singbox-panel-installer.sh [опции install.sh]
set -euo pipefail
cd "$(dirname "$0")"
OUT=singbox-panel-installer.sh

cat > "$OUT" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
sed '1,/^__PAYLOAD__$/d' "$0" | base64 -d | tar xz -C "$T"
bash "$T/install.sh" "$@"
exit 0
__PAYLOAD__
STUB

VERSION="${1:-$(python3 -c 'import json;print(json.load(open("latest.json"))["version"])' 2>/dev/null || true)}"
[ -n "$VERSION" ] || { echo "укажите версию: ./make-bundle.sh X.Y.Z (или сначала ./build-deb.sh)"; exit 1; }
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
sed "s|^APP_VERSION = \"dev\"|APP_VERSION = \"$VERSION\"|" app.py > "$W/app.py"
sed "s|<meta name=\"panel-version\" content=\"dev\">|<meta name=\"panel-version\" content=\"$VERSION\">|" index.html > "$W/index.html"
cp install.sh "$W/install.sh"
cp CHANGELOG.md "$W/CHANGELOG.md"
grep -q "APP_VERSION = \"$VERSION\"" "$W/app.py" && grep -q "content=\"$VERSION\"" "$W/index.html" || { echo "не удалось проставить версию"; exit 1; }
tar czf - -C "$W" app.py index.html install.sh CHANGELOG.md | base64 >> "$OUT"
chmod +x "$OUT"
echo "Готово: $OUT ($(du -h "$OUT" | cut -f1))"
