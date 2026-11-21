/* NextDNS Sentinel: the dashboard's own controls.
 *
 * Everything here enhances markup that already works without JavaScript:
 *
 * - a native <select data-ui="select"> becomes a listbox drawn in the
 *   dashboard's ink; the native select stays in the form, holds the value
 *   and still fires "change", so filters and htmx work unchanged;
 * - every table.sortable gets sorting buttons in its headings;
 * - htmx confirmations open the dashboard's own dialog instead of the
 *   browser's;
 * - on a finding's page, J and K move to the next and previous open finding.
 *
 * Text only ever comes from the page itself and is written with textContent.
 */
(() => {
  "use strict";

  // Controls that only matter without scripts (the Filter button) step aside.
  document.documentElement.classList.add("has-js");

  const SVG = "http://www.w3.org/2000/svg";
  let serial = 0;
  const uid = (prefix) => `${prefix}-${++serial}`;

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  /* A small drawn icon: one stroke weight, drawn in the current colour. */
  function icon(name) {
    const svg = document.createElementNS(SVG, "svg");
    svg.setAttribute("class", `icon icon-${name}`);
    svg.setAttribute("viewBox", "0 0 12 12");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
    const paths = {
      chevron: ["M3 4.5 6 7.5 9 4.5"],
      check: ["M2.5 6.2 5 8.6 9.5 3.6"],
      sort: ["M3.5 4.8 6 2.3 8.5 4.8", "M3.5 7.2 6 9.7 8.5 7.2"],
    }[name];
    for (const d of paths) {
      const path = document.createElementNS(SVG, "path");
      path.setAttribute("d", d);
      path.setAttribute("class", `icon-path icon-path-${paths.indexOf(d)}`);
      svg.append(path);
    }
    return svg;
  }

  // --- select ------------------------------------------------------------------

  function enhanceSelect(native) {
    if (native.dataset.enhanced) return;
    native.dataset.enhanced = "true";
    const field = native.closest("label");
    const caption = field ? field.querySelector(".field-label") : null;
    if (caption && !caption.id) caption.id = uid("field");

    const box = el("div", "select");
    const button = el("button", "select-button");
    button.type = "button";
    button.id = uid("select");
    button.setAttribute("aria-haspopup", "listbox");
    button.setAttribute("aria-expanded", "false");
    const value = el("span", "select-value");
    value.id = uid("value");
    button.append(value, icon("chevron"));
    button.setAttribute("aria-labelledby", caption ? `${caption.id} ${value.id}` : value.id);

    const list = el("ul", "select-list");
    list.id = uid("list");
    list.setAttribute("role", "listbox");
    list.tabIndex = -1;
    list.hidden = true;
    if (caption) list.setAttribute("aria-labelledby", caption.id);
    button.setAttribute("aria-controls", list.id);

    const options = Array.from(native.options).map((option) => {
      const item = el("li", "select-option");
      item.id = uid("option");
      item.setAttribute("role", "option");
      item.dataset.value = option.value;
      item.append(el("span", "select-option-text", option.textContent), icon("check"));
      list.append(item);
      return item;
    });

    let active = -1;

    function sync() {
      const index = native.selectedIndex;
      value.textContent = index >= 0 ? native.options[index].textContent : "";
      options.forEach((item, i) => item.setAttribute("aria-selected", String(i === index)));
    }

    function setActive(index) {
      if (!options.length) return;
      active = Math.max(0, Math.min(options.length - 1, index));
      options.forEach((item, i) => item.classList.toggle("is-active", i === active));
      list.setAttribute("aria-activedescendant", options[active].id);
      options[active].scrollIntoView({ block: "nearest" });
    }

    function open() {
      if (!list.hidden) return;
      list.hidden = false;
      box.classList.add("is-open");
      button.setAttribute("aria-expanded", "true");
      // Opens upwards when there is no room below.
      const room = window.innerHeight - button.getBoundingClientRect().bottom;
      box.classList.toggle("opens-up", room < Math.min(280, list.scrollHeight + 12));
      setActive(native.selectedIndex);
      list.focus({ preventScroll: true });
    }

    function close(focusButton = true) {
      if (list.hidden) return;
      list.hidden = true;
      box.classList.remove("is-open");
      button.setAttribute("aria-expanded", "false");
      list.removeAttribute("aria-activedescendant");
      if (focusButton) button.focus({ preventScroll: true });
    }

    function choose(index) {
      if (index < 0 || index >= options.length) return;
      const changed = native.selectedIndex !== index;
      native.selectedIndex = index;
      sync();
      close();
      if (changed) native.dispatchEvent(new Event("change", { bubbles: true }));
    }

    let typed = "";
    let typedAt = 0;
    function typeahead(key) {
      const now = Date.now();
      typed = now - typedAt > 700 ? key : typed + key;
      typedAt = now;
      const start = list.hidden ? native.selectedIndex : active;
      const order = [...options.keys()].map((n) => (n + start + 1) % options.length);
      const hit = order.find((n) => native.options[n].textContent.trim().toLowerCase().startsWith(typed));
      if (hit === undefined) return;
      if (list.hidden) choose(hit);
      else setActive(hit);
    }

    button.addEventListener("click", () => (list.hidden ? open() : close()));
    button.addEventListener("keydown", (event) => {
      if (["ArrowDown", "ArrowUp", "Enter", " "].includes(event.key)) {
        event.preventDefault();
        open();
      } else if (event.key.length === 1 && /\S/.test(event.key) && !event.ctrlKey && !event.metaKey && !event.altKey) {
        typeahead(event.key.toLowerCase());
      }
    });
    list.addEventListener("keydown", (event) => {
      const moves = { ArrowDown: active + 1, ArrowUp: active - 1, Home: 0, End: options.length - 1, PageDown: active + 6, PageUp: active - 6 };
      if (event.key in moves) {
        event.preventDefault();
        setActive(moves[event.key]);
      } else if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        choose(active);
      } else if (event.key === "Escape") {
        event.preventDefault();
        close();
      } else if (event.key === "Tab") {
        close(false);
      } else if (event.key.length === 1 && /\S/.test(event.key)) {
        typeahead(event.key.toLowerCase());
      }
    });
    list.addEventListener("mousemove", (event) => {
      const item = event.target.closest(".select-option");
      if (item) setActive(options.indexOf(item));
    });
    list.addEventListener("click", (event) => {
      const item = event.target.closest(".select-option");
      if (item) choose(options.indexOf(item));
    });
    document.addEventListener("pointerdown", (event) => {
      if (!box.contains(event.target)) close(false);
    });
    native.addEventListener("change", sync);
    // A form reset or a history restore changes the native value silently.
    native.form?.addEventListener("reset", () => setTimeout(sync, 0));

    native.classList.add("select-native");
    native.tabIndex = -1;
    native.setAttribute("aria-hidden", "true");
    native.after(box);
    box.append(button, list);
    if (field) {
      // The label's own click would land on the hidden select.
      field.addEventListener("click", (event) => {
        if (event.target === field || event.target === caption) {
          event.preventDefault();
          button.focus();
        }
      });
    }
    sync();
  }

  // --- sortable tables -------------------------------------------------------------

  const NUMBER = /^[-+]?[\d,]*\.?\d+\s*%?$/;
  const remembered = new Map(); // table id -> [column, direction], across htmx swaps

  function cellValue(row, column) {
    const cell = row.cells[column];
    if (!cell) return "";
    return (cell.dataset.sort ?? cell.textContent).trim();
  }

  function sortTable(table, column, direction) {
    const body = table.tBodies[0];
    if (!body) return;
    const rows = Array.from(body.rows);
    const values = rows.map((row) => cellValue(row, column));
    const numeric = values.every((value) => value === "" || value === "–" || NUMBER.test(value));
    const key = (value) => {
      if (!numeric) return value.toLowerCase();
      const parsed = Number.parseFloat(value.replace(/[,%\s]/g, ""));
      return Number.isFinite(parsed) ? parsed : -Infinity;
    };
    const order = rows.map((row, index) => ({ row, index, key: key(values[index]) }));
    order.sort((a, b) => {
      let diff = 0;
      if (numeric) diff = a.key - b.key;
      else diff = a.key.localeCompare(b.key, undefined, { numeric: true, sensitivity: "base" });
      return (direction === "ascending" ? diff : -diff) || a.index - b.index;
    });
    body.append(...order.map((item) => item.row));
    table.querySelectorAll("thead th").forEach((th) => {
      const index = Number(th.dataset.column);
      if (Number.isInteger(index)) th.setAttribute("aria-sort", index === column ? direction : "none");
    });
    if (table.id) remembered.set(table.id, [column, direction]);
  }

  function enhanceTable(table) {
    if (table.dataset.enhanced || !table.tHead || !table.tBodies[0]) return;
    table.dataset.enhanced = "true";
    const headings = Array.from(table.tHead.rows[0]?.cells ?? []);
    let column = 0;
    for (const th of headings) {
      const index = column;
      column += th.colSpan || 1;
      if (th.dataset.sort === "none" || !th.textContent.trim()) continue;
      th.dataset.column = String(index);
      th.setAttribute("aria-sort", th.dataset.sorted || "none");
      const button = el("button", "sort");
      button.type = "button";
      button.append(...Array.from(th.childNodes), icon("sort"));
      th.append(button);
      button.addEventListener("click", () => {
        const current = th.getAttribute("aria-sort");
        // Figures, times and priorities read largest or newest first.
        const first = th.dataset.first || (th.classList.contains("num") ? "descending" : "ascending");
        const direction = current === "ascending" ? "descending" : current === "descending" ? "ascending" : first;
        sortTable(table, index, direction);
      });
    }
    const again = table.id && remembered.get(table.id);
    if (again) sortTable(table, again[0], again[1]);
  }

  // --- confirm dialog -------------------------------------------------------------

  let confirmDialog = null;
  function confirmBox() {
    if (confirmDialog) return confirmDialog;
    const dialog = el("dialog", "confirm");
    dialog.setAttribute("aria-labelledby", "confirm-title");
    const title = el("h2", "confirm-title", "Please confirm");
    title.id = "confirm-title";
    const question = el("p", "confirm-question");
    const bar = el("div", "confirm-actions");
    const cancel = el("button", "quiet", "Cancel");
    cancel.type = "button";
    cancel.value = "cancel";
    const go = el("button", "primary", "Confirm");
    go.type = "button";
    go.value = "go";
    bar.append(cancel, go);
    dialog.append(title, question, bar);
    document.body.append(dialog);
    cancel.addEventListener("click", () => dialog.close("cancel"));
    go.addEventListener("click", () => dialog.close("go"));
    confirmDialog = { dialog, title, question, go };
    return confirmDialog;
  }

  document.addEventListener("htmx:confirm", (event) => {
    const asked = event.detail && event.detail.question;
    if (!asked || typeof HTMLDialogElement !== "function") return;
    event.preventDefault();
    const { dialog, question, go } = confirmBox();
    const trigger = event.detail.elt;
    const submit = trigger && trigger.querySelector ? trigger.querySelector('button[type="submit"]') : null;
    question.textContent = asked;
    go.textContent = submit ? submit.textContent.trim() : "Confirm";
    dialog.returnValue = "";
    dialog.addEventListener(
      "close",
      () => {
        if (dialog.returnValue === "go") event.detail.issueRequest(true);
        else if (submit) submit.focus({ preventScroll: true });
      },
      { once: true },
    );
    dialog.showModal();
    go.focus();
  });

  // --- keys -----------------------------------------------------------------------

  document.addEventListener("keydown", (event) => {
    if (event.ctrlKey || event.metaKey || event.altKey || event.defaultPrevented) return;
    const target = event.target;
    if (target.closest && target.closest("input, textarea, select, [contenteditable], .select, dialog, [role=application]")) return;
    const key = event.key.toLowerCase();
    const link = key === "j" ? document.querySelector('[data-key="next"]') : key === "k" ? document.querySelector('[data-key="previous"]') : null;
    if (link && link.getAttribute("href")) {
      event.preventDefault();
      link.click();
    }
  });

  // --- wiring ---------------------------------------------------------------------

  function enhance(root) {
    root.querySelectorAll('select[data-ui="select"]').forEach(enhanceSelect);
    root.querySelectorAll("table.sortable").forEach(enhanceTable);
  }

  enhance(document);
  document.addEventListener("htmx:afterSettle", (event) => enhance(event.target || document));
})();
