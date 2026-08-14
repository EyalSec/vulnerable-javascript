// The catalogue of deliberate vulnerabilities in this app.
//
// This file is the single source of truth for three things: the operator map
// rendered by catalog.html, the demo script a human follows, and the machine
// readable input to run-eschromium.sh. A feature added to app.js without a row
// here shows up as a gap in the harness rather than quietly going untested.
//
// The array below is strict JSON so the shell harness can parse it without a
// JavaScript engine. Keep it that way: no comments, no trailing commas and no
// single quotes inside the brackets.
//
// Fields
//   id        stable slug, used by the harness and in the README
//   feature   the product feature the flaw lives inside
//   source    where the attacker controlled data enters the page
//   sink      the DOM or JS operation it reaches
//   detector  the es-chromium detector id expected to fire
//   where     the sink label es-chromium prints in "ESEVENT where=..."
//   trigger   URL, relative to the app root, that exercises the flow on load
//   safe      the neighbouring feature that does the same job correctly
//   note      anything an operator needs to know before reading the result

const CATALOG = [
  {
    "id": "saved-view",
    "feature": "Deep linked saved view",
    "source": "location.hash",
    "sink": "Element.innerHTML",
    "detector": "b.sink.element.innerhtml",
    "where": "Element.innerHTML",
    "marker": "alert(1)",
    "trigger": "index.html#view=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
    "safe": "The view description beside it is written with textContent.",
    "note": "The saved view label is rendered as markup so a team can bold a word in it."
  },
  {
    "id": "search-header",
    "feature": "Search results header",
    "source": "location.search",
    "sink": "Element.insertAdjacentHTML",
    "detector": "b.sink.element.insertadjacenthtml",
    "where": "Element.insertAdjacentHTML",
    "marker": "alert(2)",
    "trigger": "index.html?q=%3Cimg%20src%3Dx%20onerror%3Dalert(2)%3E",
    "safe": "Each result row below the header is built with textContent.",
    "note": "Reads the query string rather than the fragment, so it also proves the search source is separate."
  },
  {
    "id": "computed-metric",
    "feature": "Custom computed metric",
    "source": "location.hash",
    "sink": "eval",
    "detector": "b.sink.eval",
    "where": "eval",
    "marker": "revenue/orders",
    "trigger": "index.html#metric=revenue%2Forders",
    "safe": "The five built in metrics are looked up in a table, never evaluated.",
    "note": "A real formula is evaluated here, not a payload, because the point is that the feature is genuinely useful and still a sink."
  },
  {
    "id": "refresh-timer",
    "feature": "Auto refresh interval",
    "source": "location.hash",
    "sink": "setTimeout(string)",
    "detector": "b.sink.settimeout",
    "where": "setTimeout",
    "marker": "refreshTiles()",
    "trigger": "index.html#refresh=refreshTiles()",
    "safe": "The default refresh passes a function reference, not a string.",
    "note": "The string form of setTimeout is a compilation sink in the same way eval is."
  },
  {
    "id": "tick-callback",
    "feature": "Custom tick handler",
    "source": "location.hash",
    "sink": "new Function",
    "detector": "b.sink.function",
    "where": "Function",
    "marker": "console.log('tick')",
    "trigger": "index.html#tick=console.log('tick')",
    "safe": "The built in tick handler is an ordinary closure.",
    "note": "Same shape as the refresh timer but through the Function constructor."
  },
  {
    "id": "widget-message",
    "feature": "Embedded report widget",
    "source": "postMessage",
    "sink": "Element.innerHTML",
    "detector": "b.sink.element.innerhtml",
    "where": "Element.innerHTML",
    "marker": "alert(3)",
    "trigger": "index.html#widget=%3Cimg%20src%3Dx%20onerror%3Dalert(3)%3E",
    "safe": "The widget title, sent in the same message, is set with textContent.",
    "note": "The host page trusts the message body and never checks event.origin. The widget is same origin here; see the README for why."
  },
  {
    "id": "partner-tag",
    "feature": "Partner analytics tag loader",
    "source": "location.hash",
    "sink": "HTMLScriptElement.src",
    "detector": "b.sink.htmlscriptelement.src",
    "where": "HTMLScriptElement.src",
    "marker": "example.com/tag.js",
    "trigger": "index.html#partner=https%3A%2F%2Fexample.com%2Ftag.js",
    "safe": "The first party tag URL is a constant in the page.",
    "note": "Points at a URL that does not resolve. The detection is on the sink assignment, not on the fetch succeeding."
  },
  {
    "id": "api-base",
    "feature": "Staging API base override",
    "source": "location.hash",
    "sink": "fetch",
    "detector": "b.sink.fetch",
    "where": "fetch",
    "marker": "v1/summary.json",
    "trigger": "index.html#api=https%3A%2F%2Fexample.com%2Fv1%2F",
    "safe": "The production base URL is a constant and is not overridable.",
    "note": "Also exercises XMLHttpRequest.open with the same value; both are catalogued as one feature."
  },
  {
    "id": "api-base-xhr",
    "feature": "Staging API base override, legacy path",
    "source": "location.hash",
    "sink": "XMLHttpRequest.open",
    "detector": "b.sink.xhr.open",
    "where": "XMLHttpRequest.open",
    "marker": "v1/export.csv",
    "trigger": "index.html#api=https%3A%2F%2Fexample.com%2Fv1%2F",
    "safe": "The production base URL is a constant and is not overridable.",
    "note": "The older report export still uses XMLHttpRequest, so the same override reaches a second sink."
  },
  {
    "id": "live-socket",
    "feature": "Live updates endpoint",
    "source": "location.hash",
    "sink": "WebSocket",
    "detector": "b.sink.websocket",
    "where": "WebSocket",
    "marker": "wss://example.com/stream",
    "trigger": "index.html#live=wss%3A%2F%2Fexample.com%2Fstream",
    "safe": "The default endpoint is derived from location.host by the page itself.",
    "note": "The connection is expected to fail. The sink is the constructor argument."
  },
  {
    "id": "live-sse",
    "feature": "Live updates fallback",
    "source": "location.hash",
    "sink": "EventSource",
    "detector": "b.sink.eventsource",
    "where": "EventSource",
    "marker": "https://example.com/events",
    "trigger": "index.html#sse=https%3A%2F%2Fexample.com%2Fevents",
    "safe": "The default fallback endpoint is a same origin constant.",
    "note": "The EventSource fallback used when the socket cannot be opened."
  },
  {
    "id": "theme-css",
    "feature": "Saved dashboard theme",
    "source": "localStorage",
    "sink": "CSSStyleDeclaration.cssText",
    "detector": "b.sink.cssstyledeclaration.csstext",
    "where": "CSSStyleDeclaration.cssText",
    "marker": "background:#10222e",
    "trigger": "index.html#seed-theme=background%3A%2310222e",
    "safe": "The three shipped themes are applied by setting a class name.",
    "note": "Seeds localStorage and reloads, so the value genuinely arrives from storage on the second load rather than from the URL."
  },
  {
    "id": "avatar-attr",
    "feature": "User avatar",
    "source": "location.hash",
    "sink": "Element.setAttribute",
    "detector": "b.sink.element.setattribute",
    "where": "Element.setAttribute",
    "marker": "alert(4)",
    "trigger": "index.html#avatar=x%22%20onerror%3D%22alert(4)",
    "safe": "The fallback initials avatar sets no attributes from input.",
    "note": "setAttribute is the backstop that also covers event handler attributes, so this reaches onerror."
  },
  {
    "id": "resume-cookie",
    "feature": "Continue where you left off",
    "source": "document.cookie",
    "sink": "Element.innerHTML",
    "detector": "b.sink.element.innerhtml",
    "where": "Element.innerHTML",
    "marker": "alert(5)",
    "trigger": "index.html#seed-resume=%3Cimg%20src%3Dx%20onerror%3Dalert(5)%3E",
    "safe": "The timestamp shown next to it is formatted and written with textContent.",
    "note": "Seeds a cookie and reloads. The cookie write is itself a catalogued sink."
  },
  {
    "id": "resume-cookie-write",
    "feature": "Continue where you left off, the write side",
    "source": "location.hash",
    "sink": "document.cookie",
    "detector": "b.sink.document.cookie",
    "where": "document.cookie",
    "marker": "nw_resume=",
    "trigger": "index.html#seed-resume=%3Cimg%20src%3Dx%20onerror%3Dalert(5)%3E",
    "safe": "The session id cookie is generated by the page, not taken from input.",
    "note": "The same trigger as resume-cookie. Writing attacker data into a cookie is reported separately from reading it back."
  },
  {
    "id": "share-handoff",
    "feature": "Share dialog handoff",
    "source": "window.name",
    "sink": "Element.innerHTML",
    "detector": "b.sink.element.innerhtml",
    "where": "Element.innerHTML",
    "marker": "alert(6)",
    "trigger": "share.html#note=%3Cimg%20src%3Dx%20onerror%3Dalert(6)%3E",
    "safe": "The recipient list in the same dialog is rendered with textContent.",
    "note": "share.html parks the note in window.name and navigates to the dashboard, which reads it back. window.name survives same window navigation, which is exactly why it gets used as a handoff."
  },
  {
    "id": "draft-restore",
    "feature": "Draft comment restore",
    "source": "sessionStorage",
    "sink": "Element.outerHTML",
    "detector": "b.sink.element.outerhtml",
    "where": "Element.outerHTML",
    "marker": "alert(7)",
    "trigger": "index.html#seed-draft=%3Cimg%20src%3Dx%20onerror%3Dalert(7)%3E",
    "safe": "The saved draft count beside it is written with textContent.",
    "note": "Seeds sessionStorage and reloads. outerHTML replaces the placeholder node entirely, which is why the feature uses it."
  },
  {
    "id": "export-parse",
    "feature": "Export preview",
    "source": "location.hash",
    "sink": "DOMParser.parseFromString",
    "detector": "b.sink.domparser.parsefromstring",
    "where": "DOMParser.parseFromString",
    "marker": "alert(8)",
    "trigger": "index.html#print=%3Cimg%20src%3Dx%20onerror%3Dalert(8)%3E",
    "safe": "The export filename is escaped before it goes into the header.",
    "note": "The preview header is parsed so a report title can carry basic formatting."
  },
  {
    "id": "export-write",
    "feature": "Export preview, print frame",
    "source": "location.hash",
    "sink": "Document.write",
    "detector": "b.sink.document.write",
    "where": "document.write",
    "marker": "alert(8)",
    "trigger": "index.html#print=%3Cimg%20src%3Dx%20onerror%3Dalert(8)%3E",
    "safe": "The print stylesheet link written beside it is a constant.",
    "note": "Writes into the print iframe rather than the main document, which is what a real export preview does."
  },
  {
    "id": "chart-shadow",
    "feature": "Charting web component",
    "source": "location.hash",
    "sink": "ShadowRoot.innerHTML",
    "detector": "b.sink.shadowroot.innerhtml",
    "where": "ShadowRoot.innerHTML",
    "marker": "alert(9)",
    "trigger": "index.html#chart=%3Cimg%20src%3Dx%20onerror%3Dalert(9)%3E",
    "safe": "The axis labels inside the same shadow root are set with textContent.",
    "note": "A shadow root is a separate node tree. The flow crosses into it and is still reported."
  },
  {
    "id": "referrer-nav",
    "feature": "Back to where you came from",
    "source": "document.referrer",
    "sink": "Location.assign",
    "detector": "b.sink.location.assign",
    "where": "location.assign",
    "marker": "depart.html",
    "trigger": "depart.html",
    "safe": "The in app breadcrumb navigates to a route name from a fixed table.",
    "note": "depart.html links into the dashboard so there is a real referrer, and the dashboard navigates back to it. This one leaves the page, so run it last."
  },
  {
    "id": "region-uppercase",
    "feature": "Region filter label",
    "source": "location.hash",
    "sink": "Element.innerHTML",
    "detector": "b.sink.element.innerhtml",
    "where": "Element.innerHTML",
    "marker": "alert(10)",
    "expected": false,
    "trigger": "index.html#region=%3Cimg%20src%3Dx%20onerror%3Dalert(10)%3E",
    "safe": "None. This one is exploitable and is not reported.",
    "note": "KNOWN NON-DETECTION. The region code is upper-cased before display and case folding drops the taint, so the flow is real but unreported. Measured on the 2026-08-04 build."
  },
  {
    "id": "layout-base64",
    "feature": "Saved layout string",
    "source": "location.hash",
    "sink": "Element.innerHTML",
    "detector": "b.sink.element.innerhtml",
    "where": "Element.innerHTML",
    "marker": "alert(11)",
    "expected": false,
    "trigger": "index.html#layout=PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDExKT4%3D",
    "safe": "None. This one is exploitable and is not reported.",
    "note": "KNOWN NON-DETECTION. atob rebuilds the string from the encoded form and the taint does not survive. Measured on the 2026-08-04 build."
  },
  {
    "id": "slug-percharacter",
    "feature": "Label slug pass",
    "source": "location.hash",
    "sink": "Element.innerHTML",
    "detector": "b.sink.element.innerhtml",
    "where": "Element.innerHTML",
    "marker": "alert(12)",
    "expected": false,
    "trigger": "index.html#slug=%3Cimg%20src%3Dx%20onerror%3Dalert(12)%3E",
    "safe": "None. This one is exploitable and is not reported.",
    "note": "KNOWN NON-DETECTION. split(\"\") to characters and join back loses the taint. Splitting on a real separator keeps it. Measured on the 2026-08-04 build."
  }
];

if (typeof module !== "undefined" && module.exports) { module.exports = CATALOG; }
