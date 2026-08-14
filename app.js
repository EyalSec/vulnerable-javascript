/*
 * Northwind Retail Analytics: application logic.
 *
 * This file is deliberately vulnerable. Every flaw in it is listed in
 * catalog.js, and every flaw sits inside a feature that has an independent
 * reason to exist: a saved view you can deep link, a formula you can define, a
 * theme that persists, a widget from another team. None of them are named after
 * their sink, because real DOM-XSS is never labelled either.
 *
 * Beside most of them is a "safe twin": the neighbouring bit of the same
 * feature written correctly, with textContent or an escaped template. Those are
 * load bearing. A demo where the tool lights up on everything proves nothing.
 *
 * Do not copy anything out of this file.
 */
(function () {
  "use strict";

  /* ---------------------------------------------------------------- data -- */

  var STORES = [
    { name: "Bridgeport Central", region: "Northeast", revenue: 412900, orders: 5120 },
    { name: "Cedar Hills",        region: "Midwest",   revenue: 388400, orders: 4870 },
    { name: "Marlowe Street",     region: "Northeast", revenue: 351200, orders: 4402 },
    { name: "Halton Quay",        region: "South",     revenue: 297650, orders: 3980 },
    { name: "Ridgeway Park",      region: "West",      revenue: 265300, orders: 3411 }
  ];

  var FIGURES = { revenue: 4182900, orders: 51038, returns: 0.047, visits: 613480 };

  var BUILTIN_METRICS = {
    "Average order value": function (f) { return f.revenue / f.orders; },
    "Revenue per visit":   function (f) { return f.revenue / f.visits; },
    "Orders per visit":    function (f) { return f.orders / f.visits; },
    "Return rate":         function (f) { return f.returns; },
    "Revenue per store":   function (f) { return f.revenue / 5; }
  };

  var API_BASE = "https://api.northwind.example/v3/";
  var PARTNER_TAG = "https://tags.northwind.example/first-party.js";

  /* ------------------------------------------------------------- helpers -- */

  function el(id) { return document.getElementById(id); }

  // Parse the fragment into key/value pairs. The fragment is how this app deep
  // links a view, which is the honest reason it ends up in so many features.
  function hashParams() {
    var out = {};
    var raw = location.hash.slice(1);
    if (!raw) { return out; }
    raw.split("&").forEach(function (pair) {
      var i = pair.indexOf("=");
      if (i === -1) { out[pair] = ""; return; }
      out[pair.slice(0, i)] = decodeURIComponent(pair.slice(i + 1));
    });
    return out;
  }

  function queryParam(name) {
    var raw = location.search.slice(1);
    var found = null;
    raw.split("&").forEach(function (pair) {
      var i = pair.indexOf("=");
      if (i > 0 && pair.slice(0, i) === name) {
        found = decodeURIComponent(pair.slice(i + 1).replace(/\+/g, " "));
      }
    });
    return found;
  }

  function money(n) {
    return n.toLocaleString("en-US", { maximumFractionDigits: 0 });
  }

  function log(what) {
    if (window.console && console.info) { console.info("[northwind] " + what); }
  }

  var P = hashParams();

  /* --------------------------------------------------------------- seeds -- */
  /*
   * Three features take their input from browser storage rather than from the
   * URL: the saved theme, the resume strip and the draft note. To exercise
   * those from a single URL the app can seed the store and then reload, so that
   * on the second load the value genuinely arrives from storage.
   *
   * A fragment-only change does not re-run the page, so the reload is explicit.
   * The replace target is a constant: building it out of location.pathname
   * would put a second, uninteresting flow in every trace.
   */
  function seedAndReload(key) {
    if (P["seed-theme"] !== undefined && key === "theme") {
      localStorage.setItem("nw.theme", P["seed-theme"]);
      location.replace("index.html#theme");
      location.reload();
      return true;
    }
    if (P["seed-resume"] !== undefined && key === "resume") {
      // VULNERABLE (document.cookie sink): the resume marker is attacker
      // controlled and is written straight into a cookie.
      document.cookie = "nw_resume=" + encodeURIComponent(P["seed-resume"]) + "; path=/";
      // SAFE TWIN: the session id is generated here, not taken from input.
      document.cookie = "nw_sid=" + Math.floor(Math.random() * 1e9) + "; path=/";
      location.replace("index.html#resume");
      location.reload();
      return true;
    }
    if (P["seed-draft"] !== undefined && key === "draft") {
      sessionStorage.setItem("nw.draft", P["seed-draft"]);
      sessionStorage.setItem("nw.draftCount", "1");
      location.replace("index.html#draft");
      location.reload();
      return true;
    }
    return false;
  }

  if (seedAndReload("theme") || seedAndReload("resume") || seedAndReload("draft")) {
    return; // the reload takes it from here
  }

  /* ---------------------------------------------------------- base render -- */

  function renderStores() {
    var body = el("store-rows");
    body.textContent = "";
    STORES.forEach(function (s) {
      var tr = document.createElement("tr");
      [s.name, s.region, money(s.revenue), money(s.orders)].forEach(function (v) {
        var td = document.createElement("td");
        td.textContent = v;           // SAFE: store data is never markup
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
  }

  // Referenced by name from the auto refresh feature below, so it has to be a
  // global. That is also why a string handler is tempting there in the first
  // place.
  window.refreshTiles = function refreshTiles() {
    el("kpi-revenue").textContent = money(FIGURES.revenue);
    el("kpi-orders").textContent = money(FIGURES.orders);
    el("kpi-returns").textContent = (FIGURES.returns * 100).toFixed(1) + "%";
    log("tiles refreshed");
  };

  renderStores();
  window.refreshTiles();

  /* ---------------------------------------------- 1. deep linked saved view -- */

  (function savedView() {
    if (P.view === undefined) { return; }
    // VULNERABLE (Element.innerHTML): a saved view label is rendered as markup
    // so a team can emphasise a word in the name of a shared view.
    el("view-label").innerHTML = P.view;

    // SAFE TWIN: the description under it does the same job with textContent.
    el("view-note").textContent = "Saved view: " + P.view + ", rolling 28 days.";
    log("saved view applied");
  }());

  /* -------------------------------------------------- 2. search results head -- */

  (function search() {
    var q = queryParam("q");
    if (q === null) { return; }
    el("search-panel").hidden = false;

    // VULNERABLE (Element.insertAdjacentHTML): the header echoes the search
    // term with the matched part wrapped in <mark>.
    el("search-head").insertAdjacentHTML(
      "beforeend",
      "<h2>Results for <mark>" + q + "</mark></h2>"
    );

    // SAFE TWIN: the result rows are built from the same term with textContent.
    var list = el("search-results");
    STORES.slice(0, 3).forEach(function (s) {
      var li = document.createElement("li");
      li.textContent = s.name + ", matched on “" + q + "”";
      list.appendChild(li);
    });
    log("search rendered");
  }());

  /* --------------------------------------------- 3. custom computed metric -- */

  (function computedMetric() {
    if (P.metric === undefined) {
      // SAFE TWIN: the shipped metrics are looked up, never evaluated.
      var fn = BUILTIN_METRICS["Average order value"];
      el("computed-value").textContent = fn(FIGURES).toFixed(2);
      return;
    }
    var formula = P.metric;
    var revenue = FIGURES.revenue, orders = FIGURES.orders,
        returns = FIGURES.returns, visits = FIGURES.visits;
    var value;
    try {
      // VULNERABLE (eval): a custom metric is a formula over the figures above,
      // and the quickest way to support that is to evaluate it.
      value = eval(formula);
    } catch (e) {
      value = "error";
    }
    el("computed-label").textContent = "Custom metric";
    el("computed-formula").textContent = formula;
    el("computed-value").textContent =
      (typeof value === "number") ? value.toFixed(2) : String(value);
    log("custom metric evaluated");
  }());

  /* ------------------------------------------------- 4. auto refresh timer -- */

  (function autoRefresh() {
    if (P.refresh === undefined) {
      // SAFE TWIN: the default refresh passes the function itself.
      setTimeout(window.refreshTiles, 60000);
      return;
    }
    // VULNERABLE (setTimeout with a string): the saved view carries its own
    // refresh action, and it is scheduled as source text.
    setTimeout(P.refresh, 4000);
    el("refresh-note").textContent = "Auto refresh: " + P.refresh;
    log("refresh handler scheduled");
  }());

  /* -------------------------------------------------- 5. custom tick handler -- */

  (function tickHandler() {
    if (P.tick === undefined) { return; }
    try {
      // VULNERABLE (new Function): the same idea one layer down, compiling a
      // handler body instead of scheduling it.
      var handler = new Function(P.tick);
      handler();
    } catch (e) {
      log("tick handler failed");
    }
  }());

  /* --------------------------------------------- 6. embedded report widget -- */

  (function reportWidget() {
    var frame = el("widget-frame");
    var payload = (P.widget !== undefined) ? P.widget : "Regional summary is up to date.";

    // The widget is configured through its URL, the way an embedded third party
    // report normally is.
    frame.src = "widget.html#msg=" + encodeURIComponent(payload);

    window.addEventListener("message", function (e) {
      // No origin check, and the body is trusted as markup. This is the flaw:
      // the host page treats anything the widget says as its own HTML.
      var data = e.data;
      if (!data || typeof data !== "object") { return; }

      // VULNERABLE (Element.innerHTML from postMessage).
      el("widget-body").innerHTML = data.body;

      // SAFE TWIN: the title arrives in the same message and is set as text.
      el("widget-title").textContent = data.title || "Partner report";
      log("widget message rendered");
    });
  }());

  /* --------------------------------------------- 7. partner analytics tag -- */

  (function partnerTag() {
    // SAFE TWIN: the first party tag URL is a constant.
    var own = document.createElement("script");
    own.src = PARTNER_TAG;
    own.async = true;
    document.head.appendChild(own);

    if (P.partner === undefined) { return; }
    // VULNERABLE (HTMLScriptElement.src): a partner tag can be switched on per
    // view, and the URL comes with the link.
    var tag = document.createElement("script");
    tag.src = P.partner;
    tag.async = true;
    document.head.appendChild(tag);
    log("partner tag injected");
  }());

  /* ------------------------------------------------ 8. staging API override -- */

  (function apiOverride() {
    var base = (P.api !== undefined) ? P.api : API_BASE;

    // VULNERABLE when overridden (fetch): the base URL for the summary call.
    fetch(base + "summary.json", { mode: "cors" })
      .then(function () { log("summary loaded"); })
      .catch(function () { log("summary request failed, as expected offline"); });

    // VULNERABLE when overridden (XMLHttpRequest.open): the older export path
    // still uses XHR, so the same override reaches a second sink.
    try {
      var xhr = new XMLHttpRequest();
      xhr.open("GET", base + "export.csv", true);
      xhr.onerror = function () { log("export request failed, as expected offline"); };
      xhr.send();
    } catch (e) {
      log("xhr blocked");
    }

    if (P.api !== undefined) { log("api base overridden"); }
  }());

  /* --------------------------------------------------- 9. live updates feed -- */

  (function liveFeed() {
    if (P.live !== undefined) {
      try {
        // VULNERABLE (WebSocket): the live endpoint is taken from the link.
        var ws = new WebSocket(P.live);
        ws.onerror = function () { log("live socket failed, as expected offline"); };
        el("live-note").textContent = "Live updates: " + P.live;
      } catch (e) {
        log("socket rejected");
      }
    }
    if (P.sse !== undefined) {
      try {
        // VULNERABLE (EventSource): the fallback endpoint, same shape.
        var es = new EventSource(P.sse);
        es.onerror = function () { es.close(); };
        el("live-note").textContent = "Live updates (fallback): " + P.sse;
      } catch (e) {
        log("eventsource rejected");
      }
    }
  }());

  /* ------------------------------------------------- 10. saved theme (CSS) -- */

  (function savedTheme() {
    var theme = localStorage.getItem("nw.theme");
    if (!theme) { return; }
    // VULNERABLE (CSSStyleDeclaration.cssText): a saved theme is stored as a
    // declaration list and applied to the page header.
    document.querySelector(".topbar").style.cssText = theme;
    log("saved theme applied");
  }());

  /* -------------------------------------------------------- 11. user avatar -- */

  (function avatar() {
    if (P.avatar === undefined) { return; }
    // VULNERABLE (Element.setAttribute): the avatar URL comes from the link,
    // and setAttribute will happily set an event handler attribute too.
    el("avatar").setAttribute("src", P.avatar);
    el("avatar").setAttribute("alt", "Profile picture");
    log("avatar set");
  }());

  /* ---------------------------------------- 12. continue where you left off -- */

  (function resumeStrip() {
    var marker = null;
    document.cookie.split(";").forEach(function (part) {
      var kv = part.split("=");
      if (kv[0].trim() === "nw_resume") {
        marker = decodeURIComponent(kv.slice(1).join("="));
      }
    });
    if (marker === null) { return; }
    el("resume-strip").hidden = false;
    // VULNERABLE (Element.innerHTML from document.cookie).
    el("resume-body").innerHTML = marker;
    // SAFE TWIN: the timestamp beside it is formatted and set as text.
    el("resume-time").textContent = "saved earlier today";
    log("resume strip rendered");
  }());

  /* ------------------------------------------------- 13. share dialog handoff -- */

  (function shareHandoff() {
    el("btn-share").addEventListener("click", function () {
      location.href = "share.html";
    });
    if (P.share === undefined) { return; }
    var note = window.name;
    if (!note) { return; }
    var box = document.createElement("div");
    box.className = "share-note";
    document.querySelector(".content").insertBefore(
      box, document.querySelector(".page-head").nextSibling
    );
    // VULNERABLE (Element.innerHTML from window.name): the note parked by the
    // share dialog is rendered as markup.
    box.innerHTML = "Shared with a note: " + note;
    window.name = "";
    log("share note rendered");
  }());

  /* ------------------------------------------------ 14. draft comment restore -- */

  (function draftRestore() {
    var draft = sessionStorage.getItem("nw.draft");
    if (!draft) { return; }
    // SAFE TWIN: the count is read from the same store and set as text.
    el("draft-count").textContent =
      (sessionStorage.getItem("nw.draftCount") || "0") + " saved draft";
    // VULNERABLE (Element.outerHTML): the placeholder node is replaced wholesale
    // by the saved draft, which is why the feature reaches for outerHTML.
    el("draft-slot").outerHTML =
      '<div class="draft-slot" id="draft-slot">' + draft + "</div>";
    log("draft restored");
  }());

  /* ---------------------------------------------------- 15. export preview -- */

  (function exportPreview() {
    el("btn-export").addEventListener("click", function () {
      location.href = "index.html#print=Quarterly%20summary";
      location.reload();
    });
    if (P.print === undefined) { return; }
    el("export-panel").hidden = false;

    var header = "<h1>" + P.print + "</h1><p>Northwind Retail Analytics</p>";

    // VULNERABLE (DOMParser.parseFromString): the report header is parsed so a
    // title can carry basic formatting.
    var doc = new DOMParser().parseFromString(header, "text/html");
    el("export-head").appendChild(doc.body.firstChild.cloneNode(true));

    // VULNERABLE (Document.write): the print frame is composed by writing into
    // it, which is what an export preview normally does.
    var frame = el("print-frame");
    var fdoc = frame.contentDocument || frame.contentWindow.document;
    fdoc.open();
    fdoc.write("<!doctype html><html><head>");
    // SAFE TWIN: the print stylesheet beside it is a constant.
    fdoc.write('<link rel="stylesheet" href="styles.css">');
    fdoc.write("</head><body>" + header + "</body></html>");
    fdoc.close();
    log("export preview built");
  }());

  /* -------------------------------------------------- 16. charting component -- */

  (function chartTitle() {
    var chart = el("chart");
    if (!chart || !chart.setTitle) { return; }
    if (P.chart !== undefined) {
      // VULNERABLE (ShadowRoot.innerHTML): see components.js. The chart caption
      // is rendered as markup inside the component's shadow root.
      chart.setTitle(P.chart);
      log("chart caption set");
    } else {
      chart.setTitle(null);
    }
  }());

  /* ---------------------------------------------- known non-detections ------ */
  /*
   * The three features below are just as exploitable as everything above, and
   * the shipped es-chromium build does NOT report them. They are here on
   * purpose. A demo that only shows what a tool catches is marketing; the
   * catalogue marks these as expected non-detections so the harness re-checks
   * them on every future build and says so if one starts firing.
   *
   * What they have in common: each rebuilds the string character by character
   * or through an encoder, and the taint does not survive the rebuild.
   */

  (function regionFilter() {
    if (P.region === undefined) { return; }
    // Region codes are upper-cased before display. Case folding drops the
    // taint, so this reaches innerHTML unreported.
    var region = P.region.toUpperCase();
    var box = document.createElement("div");
    box.className = "strip";
    document.querySelector(".content").insertBefore(
      box, document.querySelector(".tiles")
    );
    box.innerHTML = "Filtered to region " + region;
    log("region filter applied");
  }());

  (function savedLayout() {
    if (P.layout === undefined) { return; }
    // Saved layouts are passed around base64 encoded. atob rebuilds the string
    // from scratch and the taint does not come with it.
    var decoded;
    try { decoded = atob(P.layout); } catch (e) { return; }
    var box = document.createElement("div");
    box.className = "strip";
    document.querySelector(".content").insertBefore(
      box, document.querySelector(".tiles")
    );
    box.innerHTML = "Layout: " + decoded;
    log("saved layout applied");
  }());

  (function labelSlug() {
    if (P.slug === undefined) { return; }
    // A per character pass, the shape a hand rolled sanitiser usually takes.
    // Splitting to characters and joining back loses the taint. Note that
    // splitting on a real separator does not.
    var slug = P.slug.split("").map(function (c) { return c; }).join("");
    var box = document.createElement("div");
    box.className = "strip";
    document.querySelector(".content").insertBefore(
      box, document.querySelector(".tiles")
    );
    box.innerHTML = "Label: " + slug;
    log("label slug applied");
  }());

  /* ------------------------------------------ 17. back to where you came from -- */

  (function backLink() {
    if (P.back === undefined) { return; }
    var ref = document.referrer;
    if (!ref) { log("no referrer to go back to"); return; }
    log("navigating back to the referrer");
    // VULNERABLE (Location.assign from document.referrer): the app sends the
    // user back to whatever page linked here, with no check on where that is.
    location.assign(ref);
  }());

}());
