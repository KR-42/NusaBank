/* NusaBank — shared vanilla JS (lab build) */
(function () {
  "use strict";

  // Mobile navigation
  document.querySelectorAll("[data-nav-toggle]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var nav = document.getElementById("main-nav");
      if (!nav) return;
      var open = nav.classList.toggle("is-open");
      btn.setAttribute("aria-expanded", open ? "true" : "false");
    });
  });

  // Auto-dismiss flash messages
  document.querySelectorAll(".flash").forEach(function (el, i) {
    window.setTimeout(function () {
      el.style.transition = "opacity .4s ease";
      el.style.opacity = "0";
      window.setTimeout(function () { el.remove(); }, 400);
    }, 8000 + i * 300);
  });

  // Confirm dialogs
  document.querySelectorAll("[data-confirm]").forEach(function (el) {
    el.addEventListener("click", function (e) {
      if (!window.confirm(el.getAttribute("data-confirm"))) e.preventDefault();
    });
  });

  // Copy buttons used by the walkthrough snippets
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var text = btn.getAttribute("data-copy");
      if (navigator.clipboard) navigator.clipboard.writeText(text);
      var old = btn.textContent;
      btn.textContent = "Tersalin";
      window.setTimeout(function () { btn.textContent = old; }, 1500);
    });
  });

  // Print buttons (receipt view)
  document.querySelectorAll("[data-print]").forEach(function (btn) {
    btn.addEventListener("click", function () { window.print(); });
  });

  // ---------------------------------------------------------------------
  // DOM-based XSS sink.
  // VULN: xss_dom — the fragment is written into the DOM with innerHTML.
  //   Try: /#<img src=x onerror=alert(document.cookie)>
  // FIX: textContent + length limit (applied when lab level is `patched`).
  // ---------------------------------------------------------------------
  function domGreeting() {
    var target = document.getElementById("dom-greeting");
    if (!target) return;
    var raw;
    try {
      raw = decodeURIComponent(window.location.hash.replace(/^#/, ""));
    } catch (err) {
      return;
    }
    if (!raw) return;
    // Ordinary in-page anchors (#produk, #faq …) must keep working.
    if (document.getElementById(raw)) return;
    var level = (document.body && document.body.dataset.labLevel) || "easy";
    if (level === "patched") {
      target.textContent = raw.slice(0, 40);
    } else {
      target.innerHTML = raw;
    }
  }

  document.addEventListener("DOMContentLoaded", domGreeting);

  // ---------------------------------------------------------------------
  // FAQ filter (public /faq). Client-side only; the page ships every entry.
  // ---------------------------------------------------------------------
  function faqFilter() {
    var search = document.querySelector("[data-faq-search]");
    var list = document.querySelector("[data-faq-list]");
    if (!search || !list) return;
    var counter = document.querySelector("[data-faq-count]");
    var items = Array.prototype.slice.call(list.querySelectorAll(".faq-item"));

    function apply() {
      var needle = search.value.trim().toLowerCase();
      var shown = 0;
      items.forEach(function (item) {
        var match = !needle || item.textContent.toLowerCase().indexOf(needle) !== -1;
        item.classList.toggle("hidden", !match);
        if (match) {
          shown += 1;
          if (needle) item.setAttribute("open", "");
        } else {
          item.removeAttribute("open");
        }
      });
      if (counter) {
        counter.textContent = needle
          ? shown + " dari " + items.length + " pertanyaan cocok"
          : "";
      }
    }

    search.addEventListener("input", apply);
  }

  document.addEventListener("DOMContentLoaded", faqFilter);
})();
