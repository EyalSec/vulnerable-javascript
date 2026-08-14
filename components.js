/*
 * The Northwind charting component.
 *
 * A shadow root is a separate node tree, which is exactly why it is worth
 * demonstrating: the flow crosses out of the main document and into the
 * component, and is still reported.
 *
 * Deliberately vulnerable. See catalog.js, row "chart-shadow".
 */
(function () {
  "use strict";

  var BARS = [62, 74, 58, 81, 69, 88, 76, 94];

  function svg(bars) {
    var w = 40, gap = 14, h = 120;
    var parts = bars.map(function (v, i) {
      var x = i * (w + gap);
      var bh = Math.round(h * v / 100);
      return '<rect x="' + x + '" y="' + (h - bh) + '" width="' + w +
             '" height="' + bh + '" rx="3"></rect>';
    });
    return '<svg viewBox="0 0 ' + (bars.length * (w + gap)) + ' ' + h +
           '" preserveAspectRatio="none" role="img" aria-label="Revenue by week">' +
           parts.join("") + "</svg>";
  }

  var STYLE =
    ":host{display:block}" +
    ".wrap{padding:4px 2px 0}" +
    "svg{width:100%;height:150px}" +
    "rect{fill:#1d6b70}" +
    ".caption{margin:10px 2px 0;font:500 13px/1.4 system-ui,sans-serif;color:#3c4a52}" +
    ".axis{display:flex;justify-content:space-between;margin-top:6px;" +
    "font:400 11px/1 system-ui,sans-serif;color:#7b8792}";

  function NwChart() { return Reflect.construct(HTMLElement, [], NwChart); }
  NwChart.prototype = Object.create(HTMLElement.prototype);
  NwChart.prototype.constructor = NwChart;
  Object.setPrototypeOf(NwChart, HTMLElement);

  NwChart.prototype.connectedCallback = function () {
    if (this.shadowRoot) { return; }
    var root = this.attachShadow({ mode: "open" });
    root.innerHTML =
      "<style>" + STYLE + "</style>" +
      '<div class="wrap">' + svg(BARS) +
      '<div class="axis"></div>' +
      '<div class="caption" id="cap"></div></div>';

    // SAFE TWIN: the week labels along the axis are set with textContent.
    var axis = root.querySelector(".axis");
    ["W1", "W2", "W3", "W4", "W5", "W6", "W7", "W8"].forEach(function (label) {
      var span = document.createElement("span");
      span.textContent = label;
      axis.appendChild(span);
    });
    this._render();
  };

  NwChart.prototype.setTitle = function (title) {
    this._title = title;
    this._render();
  };

  NwChart.prototype._render = function () {
    var root = this.shadowRoot;
    if (!root) { return; }
    var cap = root.getElementById("cap");
    if (!cap) { return; }
    if (this._title === undefined || this._title === null) {
      // SAFE TWIN: the default caption is set as text.
      cap.textContent = "Revenue by week, all regions.";
      return;
    }
    // VULNERABLE (ShadowRoot.innerHTML): the whole component is re-rendered so
    // a saved chart can carry a formatted caption.
    root.innerHTML =
      "<style>" + STYLE + "</style>" +
      '<div class="wrap">' + svg(BARS) +
      '<div class="axis"><span>W1</span><span>W8</span></div>' +
      '<div class="caption" id="cap">' + this._title + "</div></div>";
  };

  if (!window.customElements.get("nw-chart")) {
    window.customElements.define("nw-chart", NwChart);
  }
}());
