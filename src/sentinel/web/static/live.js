/* NextDNS Sentinel: live updates for the dashboard.
 *
 * Listens to /live/stream (server-sent events) and keeps the page current:
 * the query feed, the live counters, the rail's status, and the decision
 * table (which htmx re-fetches when findings change).
 *
 * Every value from the server is untrusted text. It is only ever written
 * with textContent or setAttribute on known attributes; nothing is parsed
 * as HTML.
 */
(() => {
  "use strict";

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const live = (name, root = document) => $$(`[data-live="${name}"]`, root);

  const feeds = live("feed");
  const shown = new Set($$(".feed-row[data-id]").map((row) => row.dataset.id));
  const filters = { onlyBlocked: false, profile: "" };
  let paused = false;
  let buffer = [];
  const BUFFER_LIMIT = 500;

  // --- small helpers ---------------------------------------------------------

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function setText(name, value) {
    for (const node of live(name)) {
      const text = String(value);
      if (node.textContent !== text) {
        node.textContent = text;
        tick(node);
      }
    }
  }

  function tick(node) {
    node.classList.remove("ticked");
    void node.offsetWidth; // restart the animation
    node.classList.add("ticked");
  }

  function number(value) {
    return Number(value).toLocaleString("en-US");
  }

  // The status dot rings at most once every few seconds, and not while paused.
  const PING_MS = 4000;
  let lastPing = 0;

  function ping() {
    const now = Date.now();
    if (paused || now - lastPing < PING_MS) return;
    lastPing = now;
    for (const dot of live("dot")) {
      dot.classList.remove("ping");
      void dot.offsetWidth;
      dot.classList.add("ping");
    }
  }

  function connection(state, text) {
    document.documentElement.dataset.live = state;
    for (const node of live("connection")) node.textContent = text;
    for (const node of live("state")) node.textContent = state === "open" ? "Live" : text;
  }

  // --- the feed --------------------------------------------------------------

  function visible(item) {
    if (filters.onlyBlocked && item.status !== "blocked") return false;
    if (filters.profile && item.profile !== filters.profile) return false;
    return true;
  }

  function row(item) {
    const li = el("li", `feed-row status-${item.status === "blocked" ? "blocked" : "allowed"} is-new`);
    li.dataset.id = item.id;
    li.dataset.status = item.status;
    li.dataset.profile = item.profile;
    li.append(el("span", "feed-time", item.time));
    li.append(el("span", "feed-domain name", item.domain));
    const where = el("span", "feed-where", item.profile);
    if (item.device) {
      where.append(" · ");
      where.append(el("span", "device", item.device));
    }
    li.append(where);
    const status = el("span", "feed-status");
    if (item.status === "blocked") {
      const chip = el("span", "chip chip-blocked", "blocked");
      chip.title = item.reason || "Blocked by NextDNS";
      status.append(chip);
    }
    li.append(status);
    // Two animations run on a new row; it stays "new" until the longer one ends.
    li.addEventListener("animationend", function settled(event) {
      if (event.animationName !== "feed-appear" && event.animationName !== "feed-in-calm") return;
      li.classList.remove("is-new");
      li.removeEventListener("animationend", settled);
    });
    return li;
  }

  // Rows past the limit are removed once the new rows have opened, so the
  // list never shrinks while it is still growing.
  const SETTLE_MS = 600;

  function trim(feed, limit) {
    setTimeout(() => {
      while (feed.children.length > limit) feed.lastElementChild.remove();
    }, SETTLE_MS);
  }

  function render(items) {
    for (const feed of feeds) {
      const limit = Number(feed.dataset.limit) || 50;
      const filtered = "filterable" in feed.dataset;
      const wanted = items.filter((item) => !filtered || visible(item)).slice(-limit);
      if (!wanted.length) continue;
      const empty = $(".feed-empty", feed);
      if (empty) empty.remove();
      const fragment = document.createDocumentFragment();
      for (const item of wanted.reverse()) fragment.append(row(item));
      feed.prepend(fragment);
      if (feed.children.length > limit) trim(feed, limit);
    }
  }

  function receive(items) {
    const fresh = items.filter((item) => item && item.id && !shown.has(item.id));
    for (const item of fresh) shown.add(item.id);
    if (shown.size > 5000) {
      const keep = Array.from(shown).slice(-2500);
      shown.clear();
      for (const id of keep) shown.add(id);
    }
    if (!fresh.length) return;
    // The charts add each query to its bar as it arrives.
    document.dispatchEvent(
      new CustomEvent("sentinel:queries", {
        detail: fresh.map((item) => ({ t: item.t, status: item.status })),
      }),
    );
    ping();
    if (paused) {
      buffer = buffer.concat(fresh).slice(-BUFFER_LIMIT);
      showBuffer();
      return;
    }
    render(fresh);
  }

  function showBuffer() {
    for (const node of live("buffer")) node.hidden = buffer.length === 0;
    setText("buffer-count", number(buffer.length));
  }

  function applyFilters() {
    for (const feed of feeds) {
      if (!("filterable" in feed.dataset)) continue;
      for (const item of $$(".feed-row", feed)) {
        item.hidden = !visible({ status: item.dataset.status, profile: item.dataset.profile });
      }
    }
  }

  // --- controls on the Live page --------------------------------------------

  for (const box of live("only-blocked")) {
    box.addEventListener("change", () => {
      filters.onlyBlocked = box.checked;
      applyFilters();
    });
  }
  for (const select of live("profile")) {
    select.addEventListener("change", () => {
      filters.profile = select.value;
      applyFilters();
    });
  }

  function setPaused(value) {
    paused = value;
    for (const button of live("pause")) {
      button.setAttribute("aria-pressed", String(paused));
      button.textContent = paused ? "Resume" : "Pause";
      button.classList.toggle("primary", !paused);
    }
    document.documentElement.dataset.paused = String(paused);
    if (!paused && buffer.length) {
      render(buffer);
      buffer = [];
    }
    showBuffer();
  }
  for (const button of live("pause")) button.addEventListener("click", () => setPaused(!paused));
  for (const button of live("resume-buffer")) button.addEventListener("click", () => setPaused(false));

  // --- counters ---------------------------------------------------------------

  function minutes(perMinute) {
    for (const svg of live("minutes")) {
      const totals = perMinute.map(([allowed, blocked]) => allowed + blocked);
      const peak = Math.max(1, ...totals);
      const bars = $$(".minute-bar", svg);
      const blocked = $$(".minute-blocked", svg);
      perMinute.forEach(([, blockedCount], index) => {
        const total = totals[index];
        const height = (total / peak) * 60;
        const blockedHeight = (blockedCount / peak) * 60;
        if (bars[index]) {
          bars[index].setAttribute("y", String(64 - height));
          bars[index].setAttribute("height", String(height));
        }
        if (blocked[index]) {
          blocked[index].setAttribute("y", String(64 - blockedHeight));
          blocked[index].setAttribute("height", String(blockedHeight));
        }
      });
      setText("peak", number(Math.max(0, ...totals)));
    }
  }

  function stats(data) {
    setText("last-minute", number(data.last_minute));
    setText("blocked-minute", number(data.blocked_last_minute));
    setText("open-findings", number(data.open_findings));
    setText("open-count", number(data.open_findings));
    setText("open-count-text", `(${number(data.open_findings)})`);
    for (const pill of live("open-count")) pill.classList.toggle("count-zero", data.open_findings === 0);
    setText("newest", data.newest_event);
    const failing = data.checks_total - data.checks_ok;
    const state = !data.checks_total
      ? "No health checks yet"
      : failing === 0
        ? `All ${data.checks_total} checks OK`
        : `${failing} of ${data.checks_total} checks failing`;
    setText("pipeline-state", state);
    for (const link of live("pipeline")) link.classList.toggle("pipeline-problem", failing > 0);
    if (Array.isArray(data.per_minute)) minutes(data.per_minute);
  }

  // --- new findings arriving in the decision table ----------------------------

  const decide = $("[data-live='decide']");
  let before = new Set();
  if (decide) {
    decide.addEventListener("htmx:beforeSwap", () => {
      before = new Set($$("tr[id^='finding-']", decide).map((tr) => tr.id));
    });
    decide.addEventListener("htmx:afterSwap", () => {
      for (const tr of $$("tr[id^='finding-']", decide)) {
        if (!before.has(tr.id)) {
          tr.classList.add("is-fresh");
          tr.addEventListener("animationend", () => tr.classList.remove("is-fresh"), { once: true });
        }
      }
    });
  }

  // --- the stream -------------------------------------------------------------

  if (!("EventSource" in window)) {
    connection("closed", "This browser cannot show live updates.");
    return;
  }

  const source = new EventSource("/live/stream");
  connection("connecting", "Connecting to the live feed.");

  function parse(event) {
    try {
      return JSON.parse(event.data);
    } catch {
      return null;
    }
  }

  source.addEventListener("open", () => connection("open", "Live: updates as they happen."));
  source.addEventListener("queries", (event) => {
    const items = parse(event);
    if (Array.isArray(items)) receive(items);
  });
  source.addEventListener("stats", (event) => {
    const data = parse(event);
    if (data) stats(data);
  });
  source.addEventListener("findings", () => {
    document.body.dispatchEvent(new CustomEvent("sentinel:findings"));
  });
  source.addEventListener("bye", () => {
    source.close();
    connection("closed", "Signed out: reload the page to log in again.");
  });
  source.addEventListener("error", () => {
    if (source.readyState === EventSource.CLOSED) {
      connection("closed", "Live updates stopped. Reload the page.");
    } else {
      connection("connecting", "Reconnecting to the live feed.");
    }
  });
})();
