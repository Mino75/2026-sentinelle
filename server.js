/**
 * Node >= 18, zero deps
 *
 * Key update:
 * - Added a "comments" field to each rule (optional) to document intent/edge cases.
 * - Enforced version policy:
 *   - return version only when directly evidenced
 *   - otherwise keep version null + provide evidence + confidence
 */

const http = require("http");
const dns = require("dns").promises;
const net = require("net");
const { URL } = require("url");

const PORT = process.env.PORT ? Number(process.env.PORT) : 3000;

const FETCH_TIMEOUT_MS = 10_000;
const MAX_HTML_BYTES = 700_000;
const MAX_REDIRECTS = 3;

const USER_AGENT =
  "TechProbe/1.2 (+https://example.local; contact=security@example.local)";

// -------------------------
// JSON helpers
// -------------------------
function sendJson(res, statusCode, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(statusCode, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
  });
  res.end(body);
}

async function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > 200_000) {
        reject(Object.assign(new Error("Body too large"), { code: "ETOOBIG" }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(Object.assign(new Error("Invalid JSON"), { code: "EBADJSON" }));
      }
    });
    req.on("error", reject);
  });
}

// -------------------------
// SSRF protections (basic)
// -------------------------
function isPrivateIPv4(ip) {
  const parts = ip.split(".").map((x) => Number(x));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  const [a, b] = parts;

  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 0) return true;
  if (a >= 224) return true;
  return false;
}

function isPrivateIPv6(ip) {
  const lower = ip.toLowerCase();
  if (lower === "::1" || lower === "::") return true;
  if (lower.startsWith("fe80:")) return true;
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true;
  const v4mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (v4mapped && isPrivateIPv4(v4mapped[1])) return true;
  return false;
}

function isBlockedIp(ip) {
  const fam = net.isIP(ip);
  if (fam === 4) return isPrivateIPv4(ip);
  if (fam === 6) return isPrivateIPv6(ip);
  return true;
}

async function assertPublicHostname(hostname) {
  const lookups = [
    dns.resolve4(hostname).catch(() => []),
    dns.resolve6(hostname).catch(() => []),
  ];
  const [v4, v6] = await Promise.all(lookups);
  const ips = [...v4, ...v6];
  if (ips.length === 0) {
    throw Object.assign(new Error("DNS resolution failed"), { code: "EDNS" });
  }
  const blocked = ips.find(isBlockedIp);
  if (blocked) {
    throw Object.assign(new Error("Blocked destination (private/reserved IP)"), {
      code: "ESSRF",
      blockedIp: blocked,
    });
  }
  return ips;
}

function normalizeUrl(input) {
  let u;
  try {
    u = new URL(input);
  } catch {
    throw Object.assign(new Error("Invalid URL"), { code: "EBADURL" });
  }
  if (!["http:", "https:"].includes(u.protocol)) {
    throw Object.assign(new Error("Only http/https allowed"), { code: "EPROTO" });
  }
  u.hash = "";
  return u;
}

async function fetchHtmlWithGuards(startUrl) {
  let current = startUrl;
  const redirects = [];

  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    await assertPublicHostname(current.hostname);

    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);

    let res;
    try {
      res = await fetch(current.toString(), {
        method: "GET",
        redirect: "manual",
        signal: ctrl.signal,
        headers: {
          "user-agent": USER_AGENT,
          "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
      });
    } finally {
      clearTimeout(t);
    }

    const headers = Object.fromEntries(res.headers.entries());

    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const loc = res.headers.get("location");
      if (!loc) throw Object.assign(new Error("Redirect without location"), { code: "EREDIR" });
      const next = new URL(loc, current);
      redirects.push({ from: current.toString(), to: next.toString(), status: res.status });
      current = next;
      continue;
    }

    const reader = res.body?.getReader?.();
    if (!reader) throw Object.assign(new Error("No response body"), { code: "ENOBODY" });

    let bytes = 0;
    const chunks = [];
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > MAX_HTML_BYTES) {
        try { await reader.cancel(); } catch {}
        break;
      }
      chunks.push(Buffer.from(value));
    }

    return {
      finalUrl: current.toString(),
      status: res.status,
      headers,
      html: Buffer.concat(chunks).toString("utf8"),
      redirects,
      truncated: bytes > MAX_HTML_BYTES,
    };
  }

  throw Object.assign(new Error("Too many redirects"), { code: "EREDIRMAX" });
}

// -------------------------
// Detection config
// -------------------------
/**
 * Version policy (enforced by design):
 * - return version only when directly evidenced
 * - otherwise keep version null + provide evidence + confidence
 *
 * "comments" field is for human maintainers (your own notes).
 */
const DETECTION_RULES = [
  // ---- CDN/WAF/hosting ----
  {
    category: "cdn_waf",
    name: "Cloudflare",
    confidence: 0.85,
    comments: "Strong header fingerprints. High confidence when cf-ray is present.",
    any: [
      { type: "header", header: "cf-ray", re: /.+/i, evidence: (m) => [`header:cf-ray=${m[0]}`] },
      { type: "header", header: "server", re: /cloudflare/i, evidence: () => ["header:server~cloudflare"] },
    ],
  },
  {
    category: "cdn_waf",
    name: "Fastly",
    confidence: 0.75,
    comments: "Fastly can appear in via/x-served-by; can be hidden behind other CDNs.",
    any: [
      { type: "header", header: "x-served-by", re: /fastly/i, evidence: () => ["header:x-served-by~fastly"] },
      { type: "header", header: "via", re: /fastly/i, evidence: () => ["header:via~fastly"] },
    ],
  },
  {
    category: "hosting",
    name: "Vercel",
    confidence: 0.75,
    comments: "x-vercel-id is a strong signal.",
    any: [{ type: "header", header: "x-vercel-id", re: /.+/i, evidence: () => ["header:x-vercel-id"] }],
  },
  {
    category: "hosting",
    name: "Netlify",
    confidence: 0.75,
    comments: "x-nf-request-id is a strong signal.",
    any: [{ type: "header", header: "x-nf-request-id", re: /.+/i, evidence: () => ["header:x-nf-request-id"] }],
  },

  // ---- Analytics ----
  {
    category: "analytics",
    name: "Google Tag Manager",
    confidence: 0.85,
    comments: "GTM ID and gtm.js URL are robust in most deployments.",
    any: [
      { type: "html", re: /googletagmanager\.com\/gtm\.js/i, evidence: () => ["script:googletagmanager.com/gtm.js"] },
      { type: "html", re: /\bGTM-[A-Z0-9]+\b/i, evidence: (m) => [`id:${m[0]}`] },
      { type: "html", re: /dataLayer\.push\s*\(/i, evidence: () => ["js:dataLayer.push(...)"] },
    ],
  },
  {
    category: "analytics",
    name: "Google Analytics (GA4)",
    confidence: 0.8,
    comments: "GA4 measurement IDs (G-XXXX) can be extracted; GA version itself is not reliably inferable.",
    any: [
      { type: "html", re: /googletagmanager\.com\/gtag\/js/i, evidence: () => ["script:gtag/js"] },
      {
        type: "html",
        re: /\bG-[A-Z0-9]{6,}\b/i,
        evidence: (m) => [`id:${m[0]}`],
        bumpConfidenceTo: 0.9,
      },
    ],
  },
  {
    category: "analytics",
    name: "Google Analytics (Universal Analytics)",
    confidence: 0.75,
    comments: "UA is deprecated but still found. UA property ID is extractable when present.",
    any: [
      { type: "html", re: /google-analytics\.com\/analytics\.js/i, evidence: () => ["script:analytics.js"] },
      { type: "html", re: /\bUA-\d{4,}-\d+\b/i, evidence: (m) => [`id:${m[0]}`], bumpConfidenceTo: 0.85 },
    ],
  },
  {
    category: "analytics",
    name: "Matomo",
    confidence: 0.8,
    comments: "Matomo can be self-hosted; signatures include matomo.js/piwik.js and _pk_* cookies.",
    any: [
      { type: "html", re: /\bmatomo\.js\b/i, evidence: () => ["html:matomo.js"] },
      { type: "html", re: /\bpiwik\.js\b/i, evidence: () => ["html:piwik.js"] },
      { type: "html", re: /\b(matomo|piwik)\.php\b/i, evidence: (m) => [`html:${m[0]}`] },
      { type: "cookie", re: /\b_pk_(id|ses)\./i, evidence: () => ["cookie:_pk_*"] },
    ],
  },

  // ---- CMS/platforms ----
  {
    category: "cms",
    name: "WordPress",
    confidence: 0.9,
    comments: "wp-content/wp-includes are strong. Generator meta can be removed.",
    any: [
      { type: "html", re: /\/wp-content\//i, evidence: () => ["path:/wp-content/"] },
      { type: "html", re: /\/wp-includes\//i, evidence: () => ["path:/wp-includes/"] },
      { type: "metaGenerator", re: /wordpress/i, evidence: (m) => [`meta:generator=${m[0]}`] },
    ],
  },
  {
    category: "cms",
    name: "Drupal",
    confidence: 0.78,
    comments: "Generator is optional. /sites/default is a common Drupal footprint.",
    any: [
      { type: "metaGenerator", re: /drupal/i, evidence: (m) => [`meta:generator=${m[0]}`] },
      { type: "html", re: /\/sites\/default\//i, evidence: () => ["path:/sites/default/"] },
    ],
  },
  {
    category: "cms",
    name: "Joomla",
    confidence: 0.75,
    comments: "Meta generator is common but can be removed.",
    any: [{ type: "metaGenerator", re: /joomla/i, evidence: (m) => [`meta:generator=${m[0]}`] }],
  },
  {
    category: "platform",
    name: "Shopify",
    confidence: 0.82,
    comments: "cdn.shopify.com is a strong indicator for storefront assets.",
    any: [{ type: "html", re: /cdn\.shopify\.com/i, evidence: () => ["asset:cdn.shopify.com"] }],
  },

  // ---- Front frameworks ----
  {
    category: "frontend_framework",
    name: "Next.js",
    confidence: 0.82,
    comments: "Next-specific runtime markers are relatively stable.",
    any: [
      { type: "html", re: /\/_next\/static\//i, evidence: () => ["path:/_next/static/"] },
      { type: "html", re: /__NEXT_DATA__/i, evidence: () => ["html:__NEXT_DATA__"] },
    ],
  },
  {
    category: "frontend_framework",
    name: "Nuxt",
    confidence: 0.82,
    comments: "Nuxt markers include /_nuxt and __NUXT__.",
    any: [
      { type: "html", re: /\/_nuxt\//i, evidence: () => ["path:/_nuxt/"] },
      { type: "html", re: /__NUXT__/i, evidence: () => ["html:__NUXT__"] },
    ],
  },
  {
    category: "frontend_framework",
    name: "Angular",
    confidence: 0.6,
    comments: 'ng-version is direct evidence of Angular and its version (when present). Otherwise bundle heuristics are weaker.',
    any: [
      {
        type: "html",
        re: /ng-version="([^"]+)"/i,
        evidence: (m) => [`attr:ng-version=${m[1]}`],
        versionFrom: (m) => m[1], // direct evidence => allowed
        bumpConfidenceTo: 0.88,
      },
      { type: "html", re: /\/(main|polyfills|runtime)\.[a-f0-9]{8,}\.js/i, evidence: () => ["heuristic:angular-like bundle pattern"] },
    ],
  },
  {
    category: "frontend_framework",
    name: "React",
    confidence: 0.55,
    comments: "React is often bundled; direct version is rarely observable. Keep confidence moderate.",
    any: [
      { type: "html", re: /react-dom(\.production)?\.min\.js/i, evidence: () => ["script:react-dom*.js"] },
      { type: "html", re: /react(\.production)?\.min\.js/i, evidence: () => ["script:react*.js"] },
      { type: "html", re: /data-react(root|id)=/i, evidence: (m) => [`attr:${m[0]}`], bumpConfidenceTo: 0.7 },
    ],
  },
  {
    category: "frontend_framework",
    name: "Vue.js",
    confidence: 0.55,
    comments: "Vue is often bundled; scoped-style attr data-v-* is a useful heuristic, not a proof.",
    any: [
      { type: "html", re: /vue(\.runtime)?(\.global)?(\.prod)?\.js/i, evidence: (m) => [`script:${m[0]}`] },
      { type: "html", re: /data-v-[a-f0-9]{8,}/i, evidence: () => ["attr:data-v-*(scoped styles)"], bumpConfidenceTo: 0.72 },
    ],
  },

  // ---- Libraries / UI ----
  {
    category: "js_library",
    name: "jQuery",
    confidence: 0.6,
    comments: "Version is returned only when directly evidenced (e.g., global jQuery.fn.jquery or versioned filename).",
    any: [
      {
        type: "html",
        re: /jquery-([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js/i,
        evidence: (m) => [`script:jquery-${m[1]}.js`],
        versionFrom: (m) => m[1], // direct evidence => allowed
        bumpConfidenceTo: 0.85,
      },
      { type: "html", re: /jquery(?:\.min)?\.js/i, evidence: () => ["script:jquery(.min).js"] },
      {
        type: "fn",
        fn: ({ html }) => {
          const m = html.match(/jQuery\.fn\.jquery\s*=\s*["']([\d.]+)["']/i);
          if (!m) return { match: false };
          return {
            match: true,
            version: m[1], // direct evidence => allowed
            evidence: [`js:jQuery.fn.jquery=${m[1]}`],
            bumpConfidenceTo: 0.9,
          };
        },
      },
    ],
  },
  {
    category: "ui_framework",
    name: "Bootstrap",
    confidence: 0.7,
    comments: "Version is not reliably detectable unless explicitly present in filename/banner.",
    any: [
      {
        type: "html",
        re: /bootstrap-([0-9]+\.[0-9]+(?:\.[0-9]+)?)\.min\.(css|js)/i,
        evidence: (m) => [`asset:bootstrap-${m[1]}.min.${m[2]}`],
        versionFrom: (m) => m[1], // direct evidence => allowed
        bumpConfidenceTo: 0.85,
      },
      { type: "html", re: /bootstrap(\.min)?\.(css|js)/i, evidence: (m) => [`asset:${m[0]}`] },
    ],
  },

  // ---- Backend hints (not proof) ----
  {
    category: "backend_hint",
    name: "PHP (hint)",
    confidence: 0.5,
    comments: "Cookie-based hint only. Do not treat as a proven language/framework.",
    any: [{ type: "cookie", re: /\bPHPSESSID=/i, evidence: () => ["cookie:PHPSESSID"] }],
    note: "Hint only (cookie). Not a proof of the actual application language.",
  },
  {
    category: "backend_hint",
    name: "Java (hint)",
    confidence: 0.5,
    comments: "Cookie-based hint only. Many non-Java stacks can emulate similar cookies.",
    any: [{ type: "cookie", re: /\bJSESSIONID=/i, evidence: () => ["cookie:JSESSIONID"] }],
    note: "Hint only (cookie). Not a proof of Spring Boot or any specific framework.",
  },
  {
    category: "backend_hint",
    name: ".NET (hint)",
    confidence: 0.55,
    comments: "Cookie/header hint only. Frequently stripped in hardened production.",
    any: [
      { type: "cookie", re: /\b\.(AspNetCore|ASPXAUTH)=/i, evidence: () => ["cookie:AspNet*"] },
      { type: "header", header: "x-aspnet-version", re: /.+/i, evidence: (m) => [`header:x-aspnet-version=${m[0]}`] },
    ],
    note: "Hint only (cookie/header). Often removed in hardened setups.",
  },
];

// -------------------------
// Detection engine
// -------------------------
function headersToLowerMap(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) out[k.toLowerCase()] = String(v);
  return out;
}

function extractMetaGenerator(html) {
  const m = html.match(
    /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["'][^>]*>/i
  );
  return m ? m[1] : null;
}

function applyRule(rule, ctx) {
  const evidence = [];
  let version = null;
  let matched = false;
  let confidence = rule.confidence ?? 0.5;

  for (const cond of rule.any || []) {
    let res = { match: false };

    if (cond.type === "header") {
      const hv = ctx.headers[cond.header.toLowerCase()];
      if (hv) {
        const m = hv.match(cond.re);
        if (m) {
          res.match = true;
          res.evidence = cond.evidence ? cond.evidence(m, hv) : [`header:${cond.header}`];
        }
      }
    } else if (cond.type === "cookie") {
      const sc = ctx.headers["set-cookie"] || "";
      const m = sc.match(cond.re);
      if (m) {
        res.match = true;
        res.evidence = cond.evidence ? cond.evidence(m, sc) : ["header:set-cookie"];
      }
    } else if (cond.type === "html") {
      const m = ctx.html.match(cond.re);
      if (m) {
        res.match = true;
        res.evidence = cond.evidence ? cond.evidence(m, ctx.html) : ["html:match"];
        // Version policy: only set when directly extracted from a match (filename, attr, meta, etc.)
        if (cond.versionFrom) version = cond.versionFrom(m);
      }
    } else if (cond.type === "metaGenerator") {
      if (ctx.metaGenerator) {
        const m = ctx.metaGenerator.match(cond.re);
        if (m) {
          res.match = true;
          res.evidence = cond.evidence ? cond.evidence(m, ctx.metaGenerator) : ["meta:generator"];
          // Version policy: do NOT infer version from generator unless rule explicitly parses it.
        }
      }
    } else if (cond.type === "fn") {
      const out = cond.fn(ctx);
      if (out && out.match) {
        res = out;
      }
    }

    if (res.match) {
      matched = true;
      if (res.evidence) evidence.push(...res.evidence);

      // Version policy: only accept version when explicitly provided by a direct-evidence extractor.
      if (typeof res.version === "string" && res.version.trim()) version = res.version.trim();

      if (res.bumpConfidenceTo && res.bumpConfidenceTo > confidence) confidence = res.bumpConfidenceTo;
      if (cond.bumpConfidenceTo && cond.bumpConfidenceTo > confidence) confidence = cond.bumpConfidenceTo;
    }
  }

  if (!matched) return null;

  return {
    category: rule.category,
    name: rule.name,
    version: version || undefined,
    confidence,
    evidence: [...new Set(evidence)].slice(0, 10),
    note: rule.note,
    comments: rule.comments, // keep maintainer notes in output; remove if you don't want to expose
  };
}

function detectTechnos({ url, headers, html }) {
  const h = headersToLowerMap(headers);
  const metaGenerator = extractMetaGenerator(html);
  const title = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]?.trim() || null;

  const ctx = { url, headers: h, html, metaGenerator, title };

  const findings = [];
  for (const rule of DETECTION_RULES) {
    const f = applyRule(rule, ctx);
    if (f) findings.push(f);
  }

  const scriptCount = (html.match(/<script\b/gi) || []).length;
  if (scriptCount === 0) {
    findings.push({
      category: "page_profile",
      name: "Low-JS page",
      confidence: 0.6,
      evidence: ["html:<script count=0"],
      comments: "Heuristic: useful for profiling, not a technology fingerprint.",
    });
  }

  return {
    url,
    title,
    generator: metaGenerator,
    findings,
  };
}

// -------------------------
// API handler
// -------------------------
async function handleAnalyze(req, res) {
  let body;
  try {
    body = await readJsonBody(req);
  } catch (e) {
    return sendJson(res, 400, { error: e.code || "EBADREQ", message: e.message });
  }

  const inputUrl = body?.url;
  if (typeof inputUrl !== "string" || inputUrl.trim().length === 0) {
    return sendJson(res, 400, { error: "EINPUT", message: 'Missing field "url" (string).' });
  }

  let u;
  try {
    u = normalizeUrl(inputUrl.trim());
  } catch (e) {
    return sendJson(res, 400, { error: e.code || "EBADURL", message: e.message });
  }

  try {
    const fetchedAt = new Date().toISOString();
    const r = await fetchHtmlWithGuards(u);

    const tech = detectTechnos({
      url: r.finalUrl,
      headers: r.headers,
      html: r.html,
    });

    const performance = {
      mode: "lightweight",
      status: r.status,
      note:
        "This endpoint does not compute Lighthouse metrics (FCP/LCP/INP/CLS). Integrate PageSpeed Insights API or run Lighthouse headless for full perf scoring.",
    };

    return sendJson(res, 200, {
      inputUrl: u.toString(),
      finalUrl: r.finalUrl,
      fetchedAt,
      redirects: r.redirects,
      truncated: r.truncated,
      response: { status: r.status, headers: r.headers },
      performance,
      tech,
    });
  } catch (e) {
    const status =
      e.code === "ESSRF" ? 403 :
      e.code === "EDNS" ? 400 :
      e.name === "AbortError" ? 504 :
      500;

    return sendJson(res, status, {
      error: e.code || e.name || "EFAIL",
      message: e.message || "Failed",
      details: e.blockedIp ? { blockedIp: e.blockedIp } : undefined,
    });
  }
}

// -------------------------
// Router
// -------------------------
const server = http.createServer(async (req, res) => {
  const { method, url } = req;

  res.setHeader("access-control-allow-origin", "*");
  res.setHeader("access-control-allow-methods", "POST, OPTIONS");
  res.setHeader("access-control-allow-headers", "content-type");

  if (method === "OPTIONS") {
    res.writeHead(204);
    return res.end();
  }

  if (method === "POST" && url === "/analyze") {
    return handleAnalyze(req, res);
  }

  sendJson(res, 404, { error: "ENOTFOUND", message: "Route not found" });
});

server.listen(PORT, () => {
  console.log(`Listening on http://localhost:${PORT}`);
});
