# GUI responsive layout validation

SeaVault Fast uses a browser-based local GUI. The result and progress panel stays on the right side of the screen on desktop-sized layouts and automatically moves above the main forms on narrower screens where a right-hand panel would cause horizontal scrolling.

## Layout rules

- Desktop and wide laptop viewports use a two-column grid: main content on the left and `Result and progress` on the right.
- Tablet and narrow laptop viewports collapse to a single column at 1180 px and place the result panel before the forms so status remains visible.
- Phone-width viewports use single-column action buttons, full-width inputs, and horizontally scrollable tables.
- All inputs, selects, file pickers, buttons, and tables use `box-sizing: border-box` and `min-width: 0` to prevent the form controls from overflowing their panels.
- Tables are wrapped in `.table-wrap` containers so long paths and action columns do not break the page layout.
- The page avoids relying only on `Canvas` and `color-mix()` system colours. It uses CSS variables with light and dark fallbacks and a small `@supports` fallback for focus outlines.

## Browser behaviour

The GUI checks for required browser APIs at runtime:

- Fetch API
- FormData
- AbortController
- folder upload support where available

If a browser does not support folder selection, the Upload panel instructs the user to use local path ingest instead. Browser folder upload is best supported by Chromium, Edge, and Safari. Firefox users can still upload selected files and can use local path ingest for whole folders.

## Validation commands

Run from the repository root:

```bash
go test ./internal/webui
go test ./...
go vet ./...
go build -o bin/seavault ./cmd/seavault
node --check /tmp/page.js
```

To create `/tmp/page.js`, run the GUI locally, fetch the rendered page, and extract the inline script block:

```bash
./bin/seavault gui --addr 127.0.0.1:8899 --no-open
curl -fsS http://127.0.0.1:8899/ > /tmp/page.html
python3 - <<'PY'
from pathlib import Path
html = Path('/tmp/page.html').read_text()
start = html.index('<script>') + len('<script>')
end = html.index('</script>', start)
Path('/tmp/page.js').write_text(html[start:end])
PY
node --check /tmp/page.js
```
