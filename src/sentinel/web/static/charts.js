/* NextDNS Sentinel: interactive time charts.
 *
 * Mounts uPlot into every [data-chart] section. A chart asks /api/series for
 * the span in view and the server picks the bar size, so zooming in fetches
 * finer bars. While a chart shows the present it follows live: each query
 * from the live stream (live.js passes them on as "sentinel:queries") is
 * added to its bar at once, and the series is fetched again every so often
 * so the bars stay exact.
 *
 * Every value from the server is untrusted. Text is only ever written with
 * textContent, and only finding numbers are drawn on the canvas. The list of
 * what happened in a period is rendered and escaped by the server and
 * swapped in by htmx; nothing here parses HTML.
 */
(() => {
  "use strict";

  const uPlot = window.uPlot;
  if (typeof uPlot !== "function" || !("ResizeObserver" in window)) return;

  const MIN_SPAN = 600; // 10 minutes
  const MAX_SPAN = 31 * 86400; // the server's limit
  const REDRAW_MS = 400;
  const TICK_MS = 5000;
  const STALE_MS = 15000;
  const KEEP_RECENT_S = 180;
  const PRIORITIES = new Set(["critical", "high", "medium", "low", "info"]);
  const STATUSES = new Set(["open", "acknowledged", "benign"]);

  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
  const number = new Intl.NumberFormat("en-US");
  const compact = new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 });
  const percent = new Intl.NumberFormat("en-US", {
    style: "percent",
    minimumFractionDigits: 1,
    maximumFractionDigits: 1,
  });

  const clamp = (value, low, high) => Math.min(high, Math.max(low, value));
  const pad = (id) => String(id).padStart(4, "0");
  const plural = (count, word) => `${number.format(count)} ${word}${count === 1 ? "" : "s"}`;

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  /* Writes a line of [className, text] parts: "" is plain text. */
  function write(node, parts) {
    node.replaceChildren(
      ...parts
        .filter(([, text]) => text)
        .map(([className, text]) =>
          className ? el(className === "figure" ? "strong" : "span", className, text) : document.createTextNode(text),
        ),
    );
  }

  function palette() {
    const style = getComputedStyle(document.documentElement);
    const get = (name) => style.getPropertyValue(name).trim();
    return {
      allowed: get("--allowed"),
      blocked: get("--blocked"),
      now: get("--primary"),
      usual: get("--low"),
      band: get("--tint"),
      halo: get("--surface"),
      magenta: get("--magenta"),
      onMagenta: get("--on-magenta"),
      decided: get("--surface-3"),
      ink2: get("--ink-2"),
      ink3: get("--ink-3"),
      line: get("--line"),
      lineStrong: get("--line-strong"),
      sans: '"Mona Sans", system-ui, sans-serif',
    };
  }

  function duration(seconds) {
    for (const [size, unit] of [[86400, "day"], [3600, "hour"], [60, "minute"]]) {
      if (seconds % size === 0) return plural(seconds / size, unit);
    }
    return plural(seconds, "second");
  }

  /* Times in the dashboard's zone, falling back to the browser's own. */
  function clockFor(zone) {
    const make = (options) => {
      try {
        return new Intl.DateTimeFormat("en-GB", { ...options, timeZone: zone });
      } catch {
        zone = undefined;
        return new Intl.DateTimeFormat("en-GB", options);
      }
    };
    const timeFormat = make({ hour: "2-digit", minute: "2-digit", hourCycle: "h23" });
    const dayFormat = make({ day: "numeric", month: "short" });
    const time = (s) => timeFormat.format(s * 1000);
    const day = (s) => dayFormat.format(s * 1000);
    return {
      zone,
      time,
      day,
      span(from, to) {
        const sameDay = day(from) === day(to) || (time(to) === "00:00" && day(to - 1) === day(from));
        return sameDay ? `${day(from)} ${time(from)}–${time(to)}` : `${day(from)} ${time(from)} to ${day(to)} ${time(to)}`;
      },
    };
  }

  function roundRect(ctx, x, y, w, h, r) {
    if (typeof ctx.roundRect === "function") ctx.roundRect(x, y, w, h, r);
    else ctx.rect(x, y, w, h);
  }

  function cleanFinding(raw) {
    if (!raw || !Number.isInteger(raw.id) || !Number.isFinite(raw.t)) return null;
    return {
      id: raw.id,
      t: raw.t,
      priority: PRIORITIES.has(raw.priority) ? raw.priority : "info",
      rule: String(raw.rule ?? "").slice(0, 80),
      about: String(raw.about ?? "").slice(0, 120),
      status: STATUSES.has(raw.status) ? raw.status : "open",
    };
  }

  function counts(list) {
    return Array.isArray(list) ? list.map((value) => (Number.isFinite(value) && value > 0 ? value : 0)) : null;
  }

  // --- one chart ------------------------------------------------------------------

  function mount(section) {
    const part = (role) => section.querySelector(`[data-role="${role}"]`);
    const plot = part("plot");
    const readout = part("readout");
    const status = part("status");
    const detail = part("detail");
    const title = part("title");
    const follow = part("follow");
    const fallback = part("fallback");
    const liveButton = section.querySelector('[data-action="live"]');
    const expandButton = section.querySelector('[data-action="expand"]');
    const rangeButtons = Array.from(section.querySelectorAll("[data-range]"));
    if (!plot || !readout || !detail || !expandButton) return;

    const clock = clockFor(section.dataset.tz || undefined);
    const colors = palette();
    const state = {
      range: Number(section.dataset.default) || 86400,
      span: 0,
      following: true,
      min: 0,
      max: 0,
      step: 60,
      t: [],
      total: [],
      blocked: [],
      usual: null,
      findings: [],
      clusters: [],
      hoverCluster: null,
      picked: null,
      keyT: null, // the bar the keyboard is on, by its start time
      serverNow: Date.now() / 1000,
      fetchedAt: Date.now(),
      cutoff: Infinity,
      lastFetch: 0,
      recent: [],
      seq: 0,
      controller: null,
    };
    state.span = state.range;

    let u = null;
    let hoverBand = null;
    let pickedBand = null;

    const nowEst = () => state.serverNow + (Date.now() - state.fetchedAt) / 1000;
    const liveEnd = () => (Math.floor(nowEst() / state.step) + 1) * state.step;

    function view() {
      if (state.following) {
        const max = liveEnd();
        return [max - state.span, max];
      }
      return [state.min, state.max];
    }

    function setView(min, max) {
      const span = clamp(max - min, MIN_SPAN, MAX_SPAN);
      if (min + span >= liveEnd() - state.step / 2) {
        state.following = true;
      } else {
        state.following = false;
        state.min = min;
        state.max = min + span;
      }
      state.span = span;
      apply();
    }

    function announce(text) {
      if (status) status.textContent = text;
    }

    // --- data -----------------------------------------------------------------------

    function data() {
      const half = state.step / 2;
      const nowBucket = state.following ? Math.floor(nowEst() / state.step) * state.step : null;
      // Copies: the live stream changes the counts between redraws.
      return [
        state.t.map((t) => t + half),
        state.total.slice(),
        state.t.map((t, i) => (t === nowBucket ? state.total[i] : null)),
        state.blocked.slice(),
      ];
    }

    function visibleIdx() {
      const [min, max] = view();
      let first = -1;
      let last = -1;
      state.t.forEach((t, i) => {
        if (t + state.step > min && t < max) {
          if (first < 0) first = i;
          last = i;
        }
      });
      return [first, last];
    }

    function grow(until) {
      if (!state.t.length) return false;
      let grew = false;
      while (state.t[state.t.length - 1] < until && state.t.length < 20000) {
        state.t.push(state.t[state.t.length - 1] + state.step);
        state.total.push(0);
        state.blocked.push(0);
        grew = true;
      }
      return grew;
    }

    function add(item) {
      if (!state.t.length) return false;
      const bucket = Math.floor(item.t / state.step) * state.step;
      const index = (bucket - state.t[0]) / state.step;
      if (index < 0 || index > state.t.length + 1440) return false;
      grow(bucket);
      state.total[index] += 1;
      if (item.blocked) state.blocked[index] += 1;
      return true;
    }

    function trim() {
      // While following, bars that slid out of view are dropped.
      const [min] = view();
      while (state.t.length > 2 && state.t[1] + state.step < min) {
        state.t.shift();
        state.total.shift();
        state.blocked.shift();
      }
    }

    function accept(body) {
      const t = counts(body.t);
      const allowed = counts(body.allowed);
      const blocked = counts(body.blocked);
      const step = Number(body.step);
      if (!t || !allowed || !blocked || !(step > 0) || allowed.length !== t.length || blocked.length !== t.length) {
        return false;
      }
      state.step = step;
      state.t = t;
      state.blocked = blocked;
      state.total = allowed.map((value, i) => value + blocked[i]);
      state.usual = Number.isFinite(body.usual) ? body.usual : null;
      state.findings = (Array.isArray(body.findings) ? body.findings : []).map(cleanFinding).filter(Boolean);
      state.serverNow = Number.isFinite(body.now) ? body.now : Date.now() / 1000;
      state.fetchedAt = Date.now();
      state.cutoff = Math.floor(state.serverNow);
      // Queries the live stream delivered after the server counted.
      for (const item of state.recent) if (item.t > state.cutoff) add(item);
      return true;
    }

    async function load({ quiet = false } = {}) {
      const [min, max] = view();
      const from = Math.floor(min);
      const to = Math.ceil(Math.min(max, nowEst()));
      const seq = ++state.seq;
      if (state.controller) state.controller.abort();
      const controller = new AbortController();
      state.controller = controller;
      state.lastFetch = Date.now();
      if (!quiet && u) section.classList.add("is-loading");
      try {
        const response = await fetch(`/api/series?from=${from}&to=${to}`, {
          headers: { Accept: "application/json" },
          credentials: "same-origin",
          cache: "no-store",
          signal: controller.signal,
        });
        if (response.status === 401 || (response.redirected && new URL(response.url).pathname === "/login")) {
          window.location.assign("/login");
          return;
        }
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const body = await response.json();
        if (seq !== state.seq) return;
        if (!accept(body)) throw new Error("unexpected series");
        if (!u) create();
        redraw();
      } catch (error) {
        if (error.name === "AbortError" || seq !== state.seq) return;
        if (u) write(readout, [["", "The chart could not be updated. It will try again shortly."]]);
      } finally {
        if (seq === state.seq) {
          section.classList.remove("is-loading");
          state.controller = null;
        }
      }
    }

    let loadTimer = 0;
    function scheduleLoad(delay = 240) {
      clearTimeout(loadTimer);
      loadTimer = setTimeout(load, delay);
    }

    // --- drawing --------------------------------------------------------------------

    function yTop(self, high) {
      const top = Math.max(high || 0, state.usual || 0, 1);
      const height = self.bbox && self.bbox.height ? self.bbox.height / uPlot.pxRatio : 200;
      const room = state.findings.length ? 30 : 8; // kept free above the tallest bar
      return top / Math.max(0.5, 1 - room / height);
    }

    function xLabels(self, splits, axisIdx, space, incr) {
      return splits.map((s) => {
        if (incr >= 86400) return clock.day(s);
        const time = clock.time(s);
        return time === "00:00" ? clock.day(s) : time;
      });
    }

    function drawBand(self) {
      if (state.usual == null) return;
      const { ctx, bbox } = self;
      const y = Math.round(self.valToPos(state.usual, "y", true));
      const bottom = bbox.top + bbox.height;
      if (!(y < bottom)) return;
      ctx.save();
      ctx.globalAlpha = 0.55;
      ctx.fillStyle = colors.band;
      ctx.fillRect(bbox.left, Math.max(y, bbox.top), bbox.width, bottom - Math.max(y, bbox.top));
      ctx.restore();
    }

    function drawUsual(self) {
      if (state.usual == null) return;
      const { ctx, bbox } = self;
      const r = uPlot.pxRatio;
      const y = Math.round(self.valToPos(state.usual, "y", true)) + 0.5;
      ctx.save();
      ctx.beginPath();
      ctx.moveTo(bbox.left, y);
      ctx.lineTo(bbox.left + bbox.width, y);
      ctx.lineWidth = 4 * r;
      ctx.strokeStyle = colors.halo;
      ctx.stroke();
      ctx.setLineDash([6 * r, 4 * r]);
      ctx.lineWidth = 2 * r;
      ctx.strokeStyle = colors.usual;
      ctx.stroke();
      ctx.restore();
    }

    /* Findings close together on screen share one marker. Sizes are CSS pixels. */
    function cluster(self) {
      const min = self.scales.x.min;
      const max = self.scales.x.max;
      if (min == null || max == null) return [];
      const width = self.bbox.width / uPlot.pxRatio;
      const { ctx } = self;
      ctx.save();
      ctx.font = `700 12px ${colors.sans}`;
      const finish = (c) => {
        const first = c.items[0];
        const last = c.items[c.items.length - 1];
        c.label = c.items.length === 1 ? pad(first.id) : `${pad(first.id)} +${c.items.length - 1}`;
        c.w = Math.ceil(ctx.measureText(c.label).width) + 14;
        c.x = clamp((first.x + last.x) / 2, c.w / 2, Math.max(c.w / 2, width - c.w / 2));
        c.open = c.items.some((item) => item.status === "open");
        c.from = Math.floor(first.t / state.step) * state.step;
        c.to = (Math.floor(last.t / state.step) + 1) * state.step;
        return c;
      };
      const out = [];
      for (const finding of state.findings) {
        if (finding.t < min || finding.t > max) continue;
        const item = { ...finding, x: self.valToPos(finding.t, "x") };
        const last = out[out.length - 1];
        if (last && item.x - 26 < last.x + last.w / 2 + 4) finish(Object.assign(last, { items: [...last.items, item] }));
        else out.push(finish({ items: [item] }));
      }
      ctx.restore();
      return out;
    }

    function drawMarkers(self) {
      state.clusters = cluster(self);
      if (!state.clusters.length) return;
      const { ctx, bbox } = self;
      const r = uPlot.pxRatio;
      const top = bbox.top + 4 * r;
      const height = 18 * r;
      const bottom = bbox.top + bbox.height;
      ctx.save();
      ctx.font = `700 ${12 * r}px ${colors.sans}`;
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      for (const c of state.clusters) {
        ctx.lineWidth = r;
        ctx.strokeStyle = c.open ? colors.magenta : colors.lineStrong;
        ctx.globalAlpha = c.open ? 0.5 : 1;
        for (const item of c.items) {
          const x = Math.round(bbox.left + item.x * r) + 0.5;
          ctx.beginPath();
          ctx.moveTo(x, top + height);
          ctx.lineTo(x, bottom);
          ctx.stroke();
        }
        ctx.globalAlpha = 1;
        const x = bbox.left + c.x * r;
        const w = c.w * r;
        ctx.beginPath();
        roundRect(ctx, x - w / 2, top, w, height, height / 2);
        if (c.open) {
          ctx.fillStyle = colors.magenta;
          ctx.fill();
          ctx.fillStyle = colors.onMagenta;
        } else {
          ctx.fillStyle = colors.decided;
          ctx.fill();
          ctx.strokeStyle = colors.lineStrong;
          ctx.stroke();
          ctx.fillStyle = colors.ink2;
        }
        ctx.fillText(c.label, x, top + height / 2 + 0.5 * r);
      }
      ctx.restore();
    }

    function place(band, range) {
      if (!band) return;
      if (!range || !u) {
        band.hidden = true;
        return;
      }
      const width = u.bbox.width / uPlot.pxRatio;
      const left = clamp(u.valToPos(range[0], "x"), 0, width);
      const right = clamp(u.valToPos(range[1], "x"), 0, width);
      if (right - left < 1) {
        band.hidden = true;
        return;
      }
      band.hidden = false;
      band.style.transform = `translateX(${left}px)`;
      band.style.width = `${right - left}px`;
    }

    function drawOverlay(self) {
      drawUsual(self);
      drawMarkers(self);
      place(pickedBand, state.picked);
    }

    // --- words ----------------------------------------------------------------------

    function findingsBetween(from, to) {
      return state.findings.filter((f) => f.t >= from && f.t < to);
    }

    function summary() {
      const [min, max] = view();
      const [first, last] = visibleIdx();
      let total = 0;
      let blocked = 0;
      for (let i = first; first >= 0 && i <= last; i++) {
        total += state.total[i];
        blocked += state.blocked[i];
      }
      const found = findingsBetween(min, max).length;
      write(readout, [
        ["unit", `Each bar is ${duration(state.step)}. `],
        ["when", clock.span(Math.max(min, state.t[0] ?? min), Math.min(max, nowEst()))],
        ["", ": "],
        ...(total
          ? [
              ["figure", number.format(total)],
              ["", total === 1 ? " query, " : " queries, "],
              ["figure", number.format(blocked)],
              ["", ` blocked (${percent.format(blocked / total)})`],
            ]
          : [["", "no queries"]]),
        ["", found ? `, ${plural(found, "finding")}` : ""],
        ["", "."],
      ]);
    }

    function describeBucket(i) {
      const from = state.t[i];
      const to = from + state.step;
      const total = state.total[i];
      const blocked = state.blocked[i];
      const found = findingsBetween(from, to).length;
      const now = nowEst();
      write(readout, [
        ["when", clock.span(from, to)],
        ["", ": "],
        ["figure", number.format(total)],
        ["", total === 1 ? " query, " : " queries, "],
        ["figure", number.format(blocked)],
        ["", " blocked"],
        ["", total ? ` (${percent.format(blocked / total)})` : ""],
        ["", state.usual != null ? `. Usual ${number.format(Math.round(state.usual))}` : ""],
        ["", found ? `. ${plural(found, "finding")}` : ""],
        ["", state.following && from <= now && now < to ? ". Still counting" : ""],
        ["", "."],
      ]);
    }

    function describeCluster(c) {
      if (c.items.length === 1) {
        const f = c.items[0];
        write(readout, [
          ["when", `Finding ${pad(f.id)}`],
          ["", `, ${f.priority}, ${f.rule}`],
          ["", f.about ? ", about " : ""],
          ["name", f.about],
          ["", `. Last seen ${clock.day(f.t)} ${clock.time(f.t)}, ${f.status}. Click to open it.`],
        ]);
        return;
      }
      const open = c.items.filter((item) => item.status === "open").length;
      write(readout, [
        ["when", plural(c.items.length, "finding")],
        ["", `, ${clock.span(c.from, c.to)}`],
        ["", open ? `. ${number.format(open)} open` : ". All decided"],
        ["", ". Click to list them."],
      ]);
    }

    // --- interaction ----------------------------------------------------------------

    function hitAt(left, top) {
      if (top > 26) return null;
      return state.clusters.find((c) => Math.abs(left - c.x) <= c.w / 2 + 3) || null;
    }

    function onCursor(self) {
      const { left, top, idx } = self.cursor;
      if (left == null || left < 0 || idx == null || state.t[idx] == null) {
        state.hoverCluster = null;
        section.classList.remove("on-marker");
        place(hoverBand, null);
        summary();
        return;
      }
      const hit = hitAt(left, top);
      state.hoverCluster = hit;
      section.classList.toggle("on-marker", Boolean(hit));
      if (hit) {
        place(hoverBand, null);
        describeCluster(hit);
        return;
      }
      place(hoverBand, [state.t[idx], state.t[idx] + state.step]);
      describeBucket(idx);
    }

    function onSelect(self) {
      const { left, width } = self.select;
      if (!(width >= 6)) return;
      const min = self.posToVal(left, "x");
      const max = self.posToVal(left + width, "x");
      self.setSelect({ left: 0, top: 0, width: 0, height: 0 }, false);
      setView(min, max);
      scheduleLoad(0);
      announce(`Zoomed to ${clock.span(min, max)}.`);
    }

    function listRange(from, to) {
      state.picked = [from, to];
      place(pickedBand, state.picked);
      if (typeof window.htmx === "undefined") return;
      detail.setAttribute("aria-busy", "true");
      window.htmx
        .ajax("GET", `/partials/window?from=${Math.floor(from)}&to=${Math.ceil(to)}`, {
          target: detail,
        })
        .then(() => {
          detail.removeAttribute("aria-busy");
          announce(`Listing what happened ${clock.span(from, to)}.`);
          detail.scrollIntoView({ block: "nearest", behavior: reduced.matches ? "auto" : "smooth" });
        });
    }

    function openCluster(c) {
      if (c.items.length === 1 && Number.isInteger(c.items[0].id)) {
        window.location.assign(`/findings/${c.items[0].id}`);
      } else {
        listRange(c.from, c.to);
      }
    }

    function zoomAround(at, factor) {
      const [min, max] = view();
      const span = clamp((max - min) * factor, MIN_SPAN, MAX_SPAN);
      const ratio = clamp((at - min) / (max - min), 0, 1);
      setView(at - ratio * span, at - ratio * span + span);
      scheduleLoad();
    }

    function zoomKey(factor) {
      const [min, max] = view();
      const at = state.keyT != null ? state.keyT + state.step / 2 : state.following ? max : (min + max) / 2;
      zoomAround(at, factor);
      announce(`Showing ${clock.span(...view())}.`);
    }

    function panBy(seconds) {
      const [min, max] = view();
      setView(min + seconds, max + seconds);
      scheduleLoad();
    }

    function backToLive() {
      state.following = true;
      state.span = state.range;
      state.keyT = null;
      apply();
      scheduleLoad(0);
      announce("Back to live.");
    }

    function startPan(event) {
      const [min, max] = view();
      const perPx = (max - min) / Math.max(1, u.over.clientWidth);
      const startX = event.clientX;
      section.classList.add("is-panning");
      const move = (e) => {
        const shift = (e.clientX - startX) * perPx;
        setView(min - shift, max - shift);
      };
      const up = () => {
        window.removeEventListener("mousemove", move);
        window.removeEventListener("mouseup", up);
        section.classList.remove("is-panning");
        scheduleLoad();
      };
      window.addEventListener("mousemove", move);
      window.addEventListener("mouseup", up);
    }

    function showKey() {
      if (state.keyT == null || !u) return;
      state.keyT = Math.floor(state.keyT / state.step) * state.step; // the bar size may have changed
      const left = u.valToPos(state.keyT + state.step / 2, "x");
      u.setCursor({ left, top: u.bbox.height / uPlot.pxRatio / 2 });
      announce(readout.textContent);
    }

    function moveKey(direction) {
      const [first, last] = visibleIdx();
      if (first < 0) return;
      let t = state.keyT == null ? state.t[direction < 0 ? last : first] : state.keyT + direction * state.step;
      const [min, max] = view();
      if (t < min) {
        panBy(t - min);
      } else if (t + state.step > max) {
        if (state.following) t = state.t[last];
        else panBy(t + state.step - max);
      }
      state.keyT = t;
      showKey();
    }

    function onKey(event) {
      if (!u || event.altKey || event.ctrlKey || event.metaKey) return;
      const [min, max] = view();
      let handled = true;
      switch (event.key) {
        case "ArrowLeft":
        case "ArrowRight": {
          const direction = event.key === "ArrowLeft" ? -1 : 1;
          if (event.shiftKey) {
            panBy((direction * (max - min)) / 4);
            announce(`Showing ${clock.span(...view())}.`);
          } else {
            moveKey(direction);
          }
          break;
        }
        case "Home":
        case "End": {
          const [first, last] = visibleIdx();
          if (first >= 0) {
            state.keyT = state.t[event.key === "Home" ? first : last];
            showKey();
          }
          break;
        }
        case "+":
        case "=":
          zoomKey(0.5);
          break;
        case "-":
        case "_":
          zoomKey(2);
          break;
        case "0":
          backToLive();
          break;
        case "Enter":
        case " ":
          if (state.keyT != null) listRange(state.keyT, state.keyT + state.step);
          else handled = false;
          break;
        default:
          handled = false;
      }
      if (handled) event.preventDefault();
    }

    function onWheel(event) {
      const scale = event.deltaMode === 1 ? 16 : event.deltaMode === 2 ? u.over.clientWidth : 1;
      const dx = event.deltaX * scale;
      const dy = event.deltaY * scale;
      const [min, max] = view();
      const width = Math.max(1, u.over.clientWidth);
      if (event.ctrlKey || event.metaKey) {
        event.preventDefault();
        const left = event.clientX - u.over.getBoundingClientRect().left;
        // Following the present, a zoom near the right edge keeps following it.
        const at = state.following && left > width * 0.75 ? max : u.posToVal(left, "x");
        zoomAround(at, Math.exp(clamp(dy, -200, 200) * 0.002));
      } else if (event.shiftKey || Math.abs(dx) > Math.abs(dy)) {
        event.preventDefault();
        const shift = Math.abs(dx) > Math.abs(dy) ? dx : dy;
        panBy((shift * (max - min)) / width);
      }
      // A plain vertical scroll keeps scrolling the page.
    }

    // --- controls -------------------------------------------------------------------

    function apply() {
      for (const button of rangeButtons) {
        button.setAttribute("aria-pressed", String(state.following && Number(button.dataset.range) === state.span));
      }
      if (follow) follow.hidden = !state.following;
      if (liveButton) liveButton.hidden = state.following;
      if (!u) return;
      const [min, max] = view();
      u.setScale("x", { min, max });
    }

    function redraw() {
      if (!u) return;
      if (state.following) {
        grow(Math.floor(nowEst() / state.step) * state.step);
        trim();
      }
      u.batch(() => {
        u.setData(data(), false);
        apply();
      });
      if (state.keyT != null && document.activeElement === plot) showKey();
      else if (!(u.cursor.left >= 0)) summary();
    }

    let redrawQueued = false;
    let lastRedraw = 0;
    function queueRedraw() {
      if (redrawQueued) return;
      redrawQueued = true;
      const wait = Math.max(0, REDRAW_MS - (Date.now() - lastRedraw));
      setTimeout(() => {
        requestAnimationFrame(() => {
          redrawQueued = false;
          lastRedraw = Date.now();
          redraw();
        });
      }, wait);
    }

    function onQueries(event) {
      const items = Array.isArray(event.detail) ? event.detail : [];
      let changed = false;
      for (const raw of items) {
        const t = Number(raw && raw.t);
        if (!Number.isFinite(t)) continue;
        const item = { t, blocked: raw.status === "blocked" };
        state.recent.push(item);
        if (u && state.following && t > state.cutoff && add(item)) changed = true;
      }
      const horizon = nowEst() - KEEP_RECENT_S;
      if (state.recent.length > 200) state.recent = state.recent.filter((item) => item.t > horizon).slice(-5000);
      if (changed) queueRedraw();
    }

    function tick() {
      if (!u || document.hidden || !state.following) return;
      const due = clamp(state.step / 2, 30, 300) * 1000;
      if (Date.now() - state.lastFetch >= due) load({ quiet: true });
      else queueRedraw(); // the window slides on as time passes
    }

    // --- enlarge --------------------------------------------------------------------

    let dialog = null;
    let placeholder = null;

    function collapse() {
      if (!dialog) return;
      placeholder.replaceWith(section);
      dialog.remove();
      dialog = null;
      placeholder = null;
      section.classList.remove("is-enlarged");
      if (title) title.hidden = true;
      expandButton.textContent = "Enlarge";
      expandButton.setAttribute("aria-expanded", "false");
      expandButton.focus({ preventScroll: true });
    }

    function expand() {
      if (dialog) {
        dialog.close();
        return;
      }
      if (typeof HTMLDialogElement !== "function") return;
      dialog = document.createElement("dialog");
      dialog.className = "tchart-dialog";
      dialog.setAttribute("aria-label", section.getAttribute("aria-label") || "Chart");
      // Keeps the page the same height while the chart is away, so nothing scrolls.
      placeholder = el("div", "tchart-placeholder");
      placeholder.style.height = `${section.offsetHeight}px`;
      section.before(placeholder);
      dialog.append(section);
      document.body.append(dialog);
      section.classList.add("is-enlarged");
      if (title) title.hidden = false;
      expandButton.textContent = "Close";
      expandButton.setAttribute("aria-expanded", "true");
      dialog.addEventListener("close", collapse, { once: true });
      dialog.showModal();
      plot.focus({ preventScroll: true });
    }

    // --- create ---------------------------------------------------------------------

    function resize() {
      if (!u) return;
      const width = Math.floor(plot.clientWidth);
      const height = Math.floor(plot.clientHeight);
      if (width > 0 && height > 0 && (width !== u.width || height !== u.height)) u.setSize({ width, height });
    }

    function create() {
      for (const role of ["bar", "readout", "plot", "legend", "hint"]) {
        const node = part(role);
        if (node) node.hidden = false;
      }
      if (fallback) fallback.hidden = true;
      const font = `12px ${colors.sans}`;
      const bars = uPlot.paths.bars({ size: [0.84, Infinity, 1], align: 0 });
      const opts = {
        width: Math.max(200, Math.floor(plot.clientWidth)),
        height: Math.max(120, Math.floor(plot.clientHeight)),
        padding: [6, 20, 0, 0], // room for the last time label
        legend: { show: false },
        cursor: {
          x: false,
          y: false,
          points: { show: false },
          drag: { x: true, y: false, setScale: false, dist: 6 },
          bind: {
            mousedown: (self, target, handler) => (event) => {
              if (event.button === 0 && event.shiftKey) {
                startPan(event);
                return null;
              }
              return handler(event);
            },
            dblclick: () => () => {
              backToLive();
              return null;
            },
          },
        },
        select: { show: true },
        scales: {
          x: { time: true },
          y: { range: (self, low, high) => [0, yTop(self, high)] },
        },
        axes: [
          {
            stroke: colors.ink3,
            font,
            size: 30,
            gap: 6,
            space: 72,
            grid: { show: false },
            ticks: { stroke: colors.lineStrong, width: 1, size: 4 },
            values: xLabels,
          },
          {
            stroke: colors.ink3,
            font,
            size: 44,
            gap: 6,
            space: 36,
            grid: { stroke: colors.line, width: 1 },
            ticks: { show: false },
            values: (self, splits) => splits.map((value) => compact.format(value)),
          },
        ],
        series: [
          {},
          { label: "Queries", fill: colors.allowed, width: 0, paths: bars, points: { show: false } },
          { label: "Current bar", fill: colors.now, width: 0, paths: bars, points: { show: false } },
          { label: "Blocked", fill: colors.blocked, width: 0, paths: bars, points: { show: false } },
        ],
        hooks: {
          drawClear: [drawBand],
          draw: [drawOverlay],
          setCursor: [onCursor],
          setSelect: [onSelect],
        },
      };
      if (clock.zone) opts.tzDate = (ts) => uPlot.tzDate(new Date(ts * 1000), clock.zone);
      u = new uPlot(opts, data(), plot);

      hoverBand = el("div", "tchart-hover");
      pickedBand = el("div", "tchart-picked");
      hoverBand.hidden = true;
      pickedBand.hidden = true;
      u.over.append(pickedBand, hoverBand);

      let down = null;
      u.over.addEventListener("pointerdown", (event) => {
        down = { x: event.clientX, y: event.clientY };
      });
      u.over.addEventListener("click", (event) => {
        if (down && Math.hypot(event.clientX - down.x, event.clientY - down.y) > 5) return; // a drag
        const box = u.over.getBoundingClientRect();
        const left = event.clientX - box.left;
        const hit = hitAt(left, event.clientY - box.top);
        if (hit) {
          openCluster(hit);
          return;
        }
        const idx = u.posToIdx(left);
        if (idx != null && state.t[idx] != null) listRange(state.t[idx], state.t[idx] + state.step);
      });
      u.over.addEventListener("wheel", onWheel, { passive: false });

      plot.addEventListener("keydown", onKey);
      plot.addEventListener("blur", () => {
        state.keyT = null;
        u.setCursor({ left: -10, top: -10 });
      });

      new ResizeObserver(resize).observe(plot);
      if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => u.redraw(true, true));
    }

    // --- wiring ---------------------------------------------------------------------

    for (const button of rangeButtons) {
      button.addEventListener("click", () => {
        state.range = Number(button.dataset.range);
        state.span = state.range;
        state.following = true;
        state.keyT = null;
        apply();
        scheduleLoad(0);
        announce(`Showing the last ${button.dataset.label || button.textContent}.`);
      });
    }
    if (liveButton) liveButton.addEventListener("click", backToLive);
    expandButton.addEventListener("click", expand);
    detail.addEventListener("click", (event) => {
      if (!event.target.closest('[data-action="clear-detail"]')) return;
      detail.replaceChildren();
      state.picked = null;
      place(pickedBand, null);
      plot.focus({ preventScroll: true });
    });
    document.addEventListener("sentinel:queries", onQueries);
    document.addEventListener("visibilitychange", () => {
      // Back on the tab after a while: catch up at once instead of at the next tick.
      if (!document.hidden && u && state.following && Date.now() - state.lastFetch > STALE_MS) {
        load({ quiet: true });
      }
    });
    setInterval(tick, TICK_MS);
    load();
  }

  document.querySelectorAll("[data-chart]").forEach(mount);
})();
