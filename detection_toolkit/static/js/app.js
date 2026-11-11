/* Detection Toolkit v0.1: small progressive enhancements. Every view works without JavaScript.
   No inline handlers are used, so the Content-Security-Policy can stay at script-src 'self'. */
(function () {
  "use strict";
  document.documentElement.classList.add("js");

  // Collapsible navigation on narrow screens.
  var toggle = document.querySelector(".nav-toggle");
  var nav = document.getElementById("primary-nav");
  if (toggle && nav) {
    toggle.addEventListener("click", function () {
      var open = toggle.getAttribute("aria-expanded") === "true";
      toggle.setAttribute("aria-expanded", String(!open));
      nav.classList.toggle("is-open", !open);
    });
  }

  // Copy buttons: <button data-copy-target="element-id" data-copy-status="status-id">.
  function fallbackCopy(text) {
    var area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.className = "copy-buffer";
    document.body.appendChild(area);
    area.select();
    var copied = false;
    try {
      copied = document.execCommand("copy");
    } catch (err) {
      copied = false;
    }
    document.body.removeChild(area);
    return copied;
  }

  function announce(button, message) {
    var statusId = button.getAttribute("data-copy-status");
    var status = statusId ? document.getElementById(statusId) : null;
    if (status) {
      status.textContent = message;
    }
  }

  var COPIED = "Copied to the clipboard.";
  var FAILED = "Copy failed. Select the text and press Ctrl+C.";

  document.addEventListener("click", function (event) {
    var button = event.target.closest ? event.target.closest("[data-copy-target]") : null;
    if (!button) {
      return;
    }
    var target = document.getElementById(button.getAttribute("data-copy-target"));
    if (!target) {
      return;
    }
    var text = target.textContent || "";
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(
        function () { announce(button, COPIED); },
        function () { announce(button, fallbackCopy(text) ? COPIED : FAILED); }
      );
    } else {
      announce(button, fallbackCopy(text) ? COPIED : FAILED);
    }
  });
})();
