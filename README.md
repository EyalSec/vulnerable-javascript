# vulnerable-javascript

A deliberately vulnerable single page web application, built as a live
demonstration target for **[es-chromium](https://github.com/EyalSec/es-chromium)**,
the taint tracking browser from **[EyalSec](https://eyalsec.com)**.

It is not a list of labelled XSS labs. It is a plausible product: *Northwind
Retail Analytics*, a retail dashboard with saved views, a search box, a custom
metric formula, a saved theme, an embedded partner widget and an export
preview. Every one of those features has an independent reason to exist, and 21
of them carry real DOM-XSS.

**Live:** https://eyalsec.github.io/vulnerable-javascript/
**Catalogue:** https://eyalsec.github.io/vulnerable-javascript/catalog.html

> ### Warning: this application is deliberately insecure
> Every screen runs attacker controlled input into a dangerous DOM operation on
> purpose. It is static, has no backend, stores nothing and has nothing to
> steal, so the only achievable outcome is self-XSS on a page that says so at
> the top of every screen. Do not copy code out of it, and do not host it on a
> domain you care about: it is published on `github.io` precisely because that
> domain is on the Public Suffix List, so a payload here cannot set cookies for
> anything above it.

---

## The point in one picture

The app does not import, detect, or know anything about EyalSec. It is
byte for byte identical between the two runs below. Only the browser changes.

| Open it in | What happens |
|---|---|
| **stock Chrome** | The dashboard works. The payload executes. Nothing is recorded and nobody finds out. |
| **es-chromium** | Every flow from an attacker controlled source to a DOM sink is reported, with the source, the sink and the exact characters that were tainted. Zero changes to the page. |

A scanner guesses at whether a sink is reachable. This reports a flow that
actually happened, in a real page, in a real browser, with the widget loaded.

---

## Quickstart

### Against the hosted app

```bash
git clone https://github.com/EyalSec/vulnerable-javascript
cd vulnerable-javascript

# drive every catalogued flow against the live site
./run-eschromium.sh /path/to/es-chromium https://eyalsec.github.io/vulnerable-javascript/
```

### Against a local checkout

```bash
./serve.py                       # http://127.0.0.1:8000/
./run-eschromium.sh /path/to/es-chromium http://127.0.0.1:8000/
```

Serve it over HTTP rather than opening `index.html` from disk. A `file://` page
has no fragment to deep link with, and `document.cookie`, `document.referrer`
and both web storages are empty on it, which silently disables more than half
of the catalogue.

### By hand

```bash
ES2_CHROMIUM_TEST_SINK=1 timeout 20 ./es-chromium \
  'https://eyalsec.github.io/vulnerable-javascript/index.html#view=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E'
```

```
ESEVENT where=Element.innerHTML origin=location.hash repr=<img src=x onerror=alert(1)>
```

`ES2_CHROMIUM_TEST_SINK=1` prints detections to the console and needs no
dashboard and no token. Three things will trip you up if you drive it by hand:
the browser stays open like a browser and never exits on its own, so bound
every run with `timeout` and expect a non-zero exit; `content_shell` folds
renderer output into stdout, so capture both streams; and the `repr` wraps the
attacker controlled span in two invisible characters (`U+E000` and `U+E001`) so
you can see exactly which characters were tainted, which means a grep for a
payload that straddles that boundary will not match as plain text.

`es-chromium` itself is delivered through the EyalSec dashboard. See
[EyalSec/es-chromium](https://github.com/EyalSec/es-chromium).

---

## What it demonstrates

21 flows across 8 taint sources and 18 distinct sinks. Every row was observed
firing against the build published 2026-08-04; nothing is claimed here that was
not watched happening.

| Feature | Source | Sink |
|---|---|---|
| Deep linked saved view | `location.hash` | `Element.innerHTML` |
| Search results header | `location.search` | `insertAdjacentHTML` |
| Custom computed metric | `location.hash` | `eval` |
| Auto refresh interval | `location.hash` | `setTimeout` (string) |
| Custom tick handler | `location.hash` | `new Function` |
| Embedded report widget | `postMessage` | `Element.innerHTML` |
| Partner analytics tag | `location.hash` | `HTMLScriptElement.src` |
| Staging API override | `location.hash` | `fetch` |
| Staging API override, legacy | `location.hash` | `XMLHttpRequest.open` |
| Live updates endpoint | `location.hash` | `WebSocket` |
| Live updates fallback | `location.hash` | `EventSource` |
| Saved dashboard theme | `localStorage` | `CSSStyleDeclaration.cssText` |
| User avatar | `location.hash` | `Element.setAttribute` |
| Continue where you left off | `document.cookie` | `Element.innerHTML` |
| Continue where you left off, write | `location.hash` | `document.cookie` |
| Share dialog handoff | `window.name` | `Element.innerHTML` |
| Draft comment restore | `sessionStorage` | `Element.outerHTML` |
| Export preview | `location.hash` | `DOMParser.parseFromString` |
| Export preview, print frame | `location.hash` | `document.write` |
| Charting web component | `location.hash` | `ShadowRoot.innerHTML` |
| Back to where you came from | `document.referrer` | `location.assign` |

The full map, with a one click trigger URL and the expected detector id for
each row, is at [`catalog.html`](https://eyalsec.github.io/vulnerable-javascript/catalog.html).
That page and `run-eschromium.sh` read the same file, `catalog.js`, so the
demo script and the harness cannot drift apart.

### Safe twins

Most vulnerable features have a neighbour that does the same job correctly:
the view label is rendered with `innerHTML` while the view description beside
it uses `textContent`; the search header interpolates the term while the result
rows below it do not; the widget body is trusted as markup while the widget
title from the same message is set as text.

These are load bearing, not decoration. A demo where the tool lights up on
everything proves nothing. Measured on a clean load with no payload, the app
produces **one** flow, and it is a real one: the widget genuinely passes data
into `innerHTML` even when the content is benign. Every safe twin is silent.

---

## Known non-detections

The shipped build does not report everything in this app, and the three
features below are catalogued as gaps rather than quietly left out. They are
exactly as exploitable as the rows above.

| Feature | What happens | Observed |
|---|---|---|
| Region filter label | The region code is upper cased before display | Not reported. Taint does not survive `toUpperCase()` or `toLowerCase()`. |
| Saved layout string | A layout is passed base64 encoded and decoded with `atob` | Not reported. `atob` rebuilds the string and the taint does not come with it. |
| Label slug pass | The label is taken apart per character and rejoined | Not reported. `split("")` to characters and `join("")` loses the taint. Splitting on a real separator keeps it. |

All three were measured on the 2026-08-04 build. `run-eschromium.sh` marks them
as expected gaps and re-checks them on every run, so a future build that closes
one is reported as **gap closed** rather than passing unnoticed.

Two further limits are worth stating because they change how results should be
read, neither of them specific to this app:

- **es-chromium reports flows, not exploits.** The widget flow above fires on
  benign content because the data really does reach `innerHTML`. That is the
  correct threat model for DOM-XSS and it is also why a data heavy site is
  noisier than this one.
- **It is sanitizer blind.** Passing a value through a sanitizer before
  `innerHTML` still reports, because the taint survives the sanitizer.

---

## Files

```
index.html         the dashboard
app.js             application logic; the vulnerable features live here
components.js      the charting web component (ShadowRoot sink)
styles.css
widget.html        the embedded "partner" report widget (postMessage sender)
share.html         share dialog; parks a note in window.name and navigates back
depart.html        the previous page, so document.referrer is genuinely set
catalog.html       operator map: feature, source, sink, detector, trigger
catalog.js         the catalogue itself, read by both catalog.html and the harness
run-eschromium.sh  drives every trigger and reports what fired
serve.py           stdlib http.server, for local and offline runs
```

### A note on the widget

The embedded widget is same origin with its host, because a GitHub Pages site
has only one origin. A cross origin frame is the more realistic shape for a
third party report, but the flow being demonstrated, `postMessage` data
reaching `innerHTML` in the host page with no `event.origin` check, is
identical either way.

---

## License

MIT. See [LICENSE](LICENSE). The same terms as
[EyalSec/vulnerable-python](https://github.com/EyalSec/vulnerable-python), the
equivalent target for `es-python`.

Northwind Retail Analytics is not a real company, a real product, or a real
dataset. It exists to be attacked.
