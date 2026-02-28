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
const tls = require("tls");
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
// Fetch html
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

// detect delivery
function detectDelivery(headers) {
  const h = {};
  for (const [k, v] of Object.entries(headers || {})) h[k.toLowerCase()] = String(v);

  const enc = (h["content-encoding"] || "").toLowerCase() || null;
  const ct = h["content-type"] || null;
  const cl = h["content-length"] ? Number(h["content-length"]) : null;

  const vary = h["vary"] || null;

  return {
    contentType: ct,
    contentLengthHeader: Number.isFinite(cl) ? cl : null,
    contentEncoding: enc, // gzip/br/deflate/zstd/null
    isCompressed: enc ? ["gzip", "br", "deflate", "zstd"].some((x) => enc.includes(x)) : false,
    varyAcceptEncoding: vary ? /accept-encoding/i.test(vary) : false,
    evidence: [
      enc ? `header:content-encoding=${enc}` : "header:content-encoding missing",
      h["content-length"] ? `header:content-length=${h["content-length"]}` : "header:content-length missing",
      vary ? `header:vary=${vary}` : "header:vary missing",
    ],
  };
}


// Detection protocols
async function detectProtocols(finalUrl, headers) {
  const out = {
    transport: finalUrl.startsWith("https:") ? "https" : "http",
    http2: null,     // true/false/null (unknown)
    http3: null,     // true/false/null (unknown)
    evidence: [],
  };

  const altSvc = (headers["alt-svc"] || headers["Alt-Svc"] || "").toString();
  if (altSvc) {
    if (/\bh3(=|-)/i.test(altSvc)) {
      out.http3 = true;
      out.evidence.push(`header:alt-svc=${altSvc.slice(0, 120)}`);
    } else {
      out.http3 = false;
      out.evidence.push("header:alt-svc present (no h3 token)");
    }
  }

  if (finalUrl.startsWith("https:")) {
    try {
      const u = new URL(finalUrl);
      const port = u.port ? Number(u.port) : 443;

      await assertPublicHostname(u.hostname);

      const alpn = await new Promise((resolve, reject) => {
        const socket = tls.connect({
          host: u.hostname,
          port,
          servername: u.hostname,
          ALPNProtocols: ["h2", "http/1.1"],
          timeout: 5000,
        });

        socket.once("secureConnect", () => {
          const proto = socket.alpnProtocol || null;
          socket.end();
          resolve(proto);
        });

        socket.once("error", reject);
        socket.once("timeout", () => {
          socket.destroy();
          reject(new Error("ALPN timeout"));
        });
      });

      if (alpn === "h2") {
        out.http2 = true;
        out.evidence.push("tls:alpn=h2");
      } else if (alpn === "http/1.1") {
        out.http2 = false;
        out.evidence.push("tls:alpn=http/1.1");
      } else {
        out.http2 = null;
        out.evidence.push("tls:alpn=unknown");
      }
    } catch {
      out.http2 = null;
      out.evidence.push("tls:alpn check failed");
    }
  }

  return out;
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
// ---- PWA (Progressive Web App) hints ----
{
  category: "app_capability",
  name: "PWA (hint)",
  confidence: 0.8,
  comments: "Manifest + service worker registration are the strongest passive signals.",
  any: [
    { type: "html", re: /<link[^>]+rel=["']manifest["']/i, evidence: () => ["html:link rel=manifest"] },
    { type: "html", re: /navigator\.serviceWorker\.register\s*\(/i, evidence: () => ["js:serviceWorker.register(...)"] , bumpConfidenceTo: 0.9 },
    { type: "html", re: /<meta[^>]+name=["']theme-color["']/i, evidence: () => ["html:meta theme-color"] },
    { type: "html", re: /apple-touch-icon/i, evidence: () => ["html:apple-touch-icon"] },
  ],
  note: "Hint only. A manifest alone does not guarantee installability; fetching and validating the manifest would improve accuracy.",
},

// ---- Databases / Data services (mostly hint-based) ----
{
  category: "database_hint",
  name: "Firebase (hint)",
  confidence: 0.85,
  comments: "Firebase is often detectable because client SDKs/endpoints appear in the frontend.",
  any: [
    { type: "html", re: /www\.gstatic\.com\/firebasejs\//i, evidence: () => ["script:gstatic/firebasejs"] },
    { type: "html", re: /firebase(app|analytics|auth|firestore|database)\b/i, evidence: () => ["html:firebase sdk references"] },
    { type: "html", re: /firestore\.googleapis\.com/i, evidence: () => ["endpoint:firestore.googleapis.com"] },
    { type: "html", re: /firebaseio\.com/i, evidence: () => ["endpoint:*.firebaseio.com (Realtime DB)"] },
  ],
  note: "Indicates Firebase usage in the web app. Does not prove which Firebase products are enabled server-side.",
},
{
  category: "database_hint",
  name: "MongoDB Realm / Atlas App Services (hint)",
  confidence: 0.6,
  comments: "Only detectable when client integrations leak realm endpoints/SDK usage.",
  any: [
    { type: "html", re: /realm\.mongodb\.com/i, evidence: () => ["endpoint:realm.mongodb.com"] },
    { type: "html", re: /mongodb-stitch/i, evidence: () => ["html:mongodb-stitch (legacy naming)"] },
  ],
  note: "Hint only. Most MongoDB usage is backend-only and not visible.",
},
{
  category: "database_hint",
  name: "MySQL (hint)",
  confidence: 0.25,
  comments: "Only detectable via error leaks. Do not treat as reliable.",
  any: [
    { type: "html", re: /\bSQLSTATE\[[0-9A-Z]+\]\b/i, evidence: (m) => [`html:sqlstate=${m[0]}`] },
    { type: "html", re: /\bMySQL server version\b/i, evidence: () => ["html:mysql error text"] },
    { type: "html", re: /\bmysqli?_connect\b/i, evidence: () => ["html:mysqli_connect (error leak)"] },
  ],
  note: "Hint only. Error messages can be spoofed; many stacks suppress them.",
},
{
  category: "database_hint",
  name: "PostgreSQL (hint)",
  confidence: 0.25,
  comments: "Only detectable via error leaks. Do not treat as reliable.",
  any: [
    { type: "html", re: /\bPG::/i, evidence: () => ["html:PG::* (Ruby PG errors)"] },
    { type: "html", re: /\bPostgreSQL\b/i, evidence: () => ["html:postgresql error text"] },
  ],
  note: "Hint only. Most production sites will not leak DB errors.",
},
  
  
  // ---- Operating System hints (very low reliability) ----
{
  category: "operating_system_hint",
  name: "Windows Server (hint)",
  confidence: 0.45,
  comments: "Detected primarily via Microsoft IIS or ASP.NET stack exposure. OS cannot be proven via HTTP alone.",
  any: [
    {
      type: "header",
      header: "server",
      re: /\bMicrosoft-IIS\/([\d.]+)/i,
      evidence: (m) => [`header:server=${m[0]}`],
    },
    {
      type: "header",
      header: "x-powered-by",
      re: /\bASP\.NET\b/i,
      evidence: () => ["header:x-powered-by~ASP.NET"],
    },
  ],
  note: "Hint only. IIS can theoretically run in containers or reverse proxy chains.",
},
{
  category: "operating_system_hint",
  name: "Linux (hint)",
  confidence: 0.35,
  comments: "Inferred from typical Linux-native server stacks (nginx, Apache, etc.). Not definitive.",
  any: [
    {
      type: "header",
      header: "server",
      re: /\bnginx\b/i,
      evidence: () => ["header:server~nginx (commonly Linux)"],
    },
    {
      type: "header",
      header: "server",
      re: /\bApache\b/i,
      evidence: () => ["header:server~Apache (commonly Linux)"],
    },
  ],
  note: "Very weak inference. These servers also run on Windows.",
},
{
  category: "operating_system_hint",
  name: "Debian (hint)",
  confidence: 0.4,
  comments: "Some Apache/Nginx builds expose Debian package suffix.",
  any: [
    {
      type: "header",
      header: "server",
      re: /\bDebian\b/i,
      evidence: (m) => [`header:server~${m[0]}`],
    },
  ],
  note: "Only detectable when explicitly leaked in server header.",
},
{
  category: "operating_system_hint",
  name: "Ubuntu (hint)",
  confidence: 0.4,
  comments: "Sometimes exposed in Apache build string.",
  any: [
    {
      type: "header",
      header: "server",
      re: /\bUbuntu\b/i,
      evidence: (m) => [`header:server~${m[0]}`],
    },
  ],
  note: "Only detectable when server header is not hardened.",
},
{
  category: "operating_system_hint",
  name: "FreeBSD (hint)",
  confidence: 0.35,
  comments: "Rarely exposed; sometimes visible in custom builds.",
  any: [
    {
      type: "header",
      header: "server",
      re: /\bFreeBSD\b/i,
      evidence: (m) => [`header:server~${m[0]}`],
    },
  ],
  note: "Very uncommon in public production headers.",
},
  
  
  // ---- Container / Orchestration hints (very low reliability) ----
{
  category: "infra_hint",
  name: "Kubernetes (hint)",
  confidence: 0.4,
  comments: "Indirect detection via ingress controllers or service mesh headers.",
  any: [
    {
      type: "header",
      header: "x-envoy-upstream-service-time",
      re: /.+/i,
      evidence: () => ["header:x-envoy-upstream-service-time (Envoy/Istio mesh)"],
    },
    {
      type: "header",
      header: "x-envoy-decorator-operation",
      re: /.+/i,
      evidence: () => ["header:x-envoy-* (service mesh indicator)"],
    },
    {
      type: "header",
      header: "server",
      re: /\bnginx\b/i,
      evidence: () => ["server:nginx (possible ingress-nginx)"],
    },
  ],
  note: "Hint only. Nginx and Envoy are also used outside Kubernetes.",
},
{
  category: "infra_hint",
  name: "Docker (hint)",
  confidence: 0.25,
  comments: "Docker itself does not expose HTTP fingerprints. Only rare misconfig leaks can reveal it.",
  any: [
    {
      type: "header",
      header: "server",
      re: /\bDocker\b/i,
      evidence: () => ["header:server~Docker (rare/misconfig)"],
    },
  ],
  note: "Docker is not detectable in hardened production environments.",
},
{
  category: "infra_hint",
  name: "AWS EKS / ALB (hint)",
  confidence: 0.5,
  comments: "Cloud provider LB headers may imply container orchestration behind it.",
  any: [
    {
      type: "header",
      header: "x-amzn-trace-id",
      re: /.+/i,
      evidence: () => ["header:x-amzn-trace-id (AWS ALB)"],
    },
  ],
  note: "Indicates AWS infra, not necessarily Kubernetes.",
},
{
  category: "infra_hint",
  name: "GCP GKE / Google LB (hint)",
  confidence: 0.5,
  comments: "Google load balancer may indicate GKE usage.",
  any: [
    {
      type: "header",
      header: "via",
      re: /\bgoogle\b/i,
      evidence: () => ["header:via~google"],
    },
  ],
  note: "Indicates Google Cloud load balancing, not guaranteed Kubernetes.",
},
  
  
  // ---- Cloud Providers (Infrastructure hints) ----
{
  category: "cloud_provider_hint",
  name: "Amazon Web Services (AWS)",
  confidence: 0.7,
  comments: "Detectable via AWS ALB/CloudFront headers or trace IDs.",
  any: [
    { type: "header", header: "x-amzn-trace-id", re: /.+/i, evidence: () => ["header:x-amzn-trace-id"] },
    { type: "header", header: "via", re: /cloudfront/i, evidence: () => ["header:via~cloudfront"] },
    { type: "header", header: "server", re: /AmazonS3/i, evidence: () => ["server:AmazonS3"] },
  ],
  note: "Indicates AWS infra layer, not necessarily EC2 vs EKS vs Lambda.",
},
{
  category: "cloud_provider_hint",
  name: "Microsoft Azure",
  confidence: 0.7,
  comments: "Azure App Service and Front Door expose characteristic headers.",
  any: [
    { type: "header", header: "server", re: /Microsoft-IIS/i, evidence: () => ["server:Microsoft-IIS"] },
    { type: "header", header: "x-azure-ref", re: /.+/i, evidence: () => ["header:x-azure-ref"] },
    { type: "header", header: "x-ms-request-id", re: /.+/i, evidence: () => ["header:x-ms-request-id"] },
  ],
  note: "May indicate Azure App Service or Azure Front Door.",
},
{
  category: "cloud_provider_hint",
  name: "Google Cloud Platform (GCP)",
  confidence: 0.7,
  comments: "Google load balancer and App Engine expose distinct headers.",
  any: [
    { type: "header", header: "server", re: /gws/i, evidence: () => ["server:gws"] },
    { type: "header", header: "via", re: /google/i, evidence: () => ["header:via~google"] },
    { type: "header", header: "x-cloud-trace-context", re: /.+/i, evidence: () => ["header:x-cloud-trace-context"] },
  ],
  note: "Indicates Google Cloud infra (GCE/GKE/App Engine).",
},
{
  category: "cloud_provider_hint",
  name: "Alibaba Cloud (Aliyun)",
  confidence: 0.75,
  comments: "Alibaba CDN and OSS expose characteristic domains and headers.",
  any: [
    { type: "header", header: "server", re: /aliyun/i, evidence: () => ["server:aliyun"] },
    { type: "html", re: /alicdn\.com/i, evidence: () => ["asset:alicdn.com"] },
  ],
  note: "Strong presence in China and APAC markets.",
},
{
  category: "cloud_provider_hint",
  name: "Tencent Cloud",
  confidence: 0.7,
  comments: "Tencent CDN and infrastructure headers sometimes visible.",
  any: [
    { type: "header", header: "server", re: /tencent/i, evidence: () => ["server:tencent"] },
    { type: "html", re: /qcloudcdn\.com/i, evidence: () => ["asset:qcloudcdn.com"] },
  ],
  note: "Major Chinese cloud provider.",
},
{
  category: "cloud_provider_hint",
  name: "Huawei Cloud",
  confidence: 0.7,
  comments: "Huawei CDN and OBS domains detectable.",
  any: [
    { type: "header", header: "server", re: /huawei/i, evidence: () => ["server:huawei"] },
    { type: "html", re: /huaweicloud\.com/i, evidence: () => ["asset:huaweicloud.com"] },
  ],
  note: "Strong presence in Asia, Africa, and enterprise markets.",
},
{
  category: "cloud_provider_hint",
  name: "Oracle Cloud Infrastructure (OCI)",
  confidence: 0.6,
  comments: "OCI sometimes exposes Oracle-specific headers.",
  any: [
    { type: "header", header: "server", re: /oracle/i, evidence: () => ["server:oracle"] },
    { type: "header", header: "x-oracle-dms-ecid", re: /.+/i, evidence: () => ["header:x-oracle-dms-ecid"] },
  ],
  note: "Enterprise-heavy footprint.",
},
{
  category: "cloud_provider_hint",
  name: "IBM Cloud",
  confidence: 0.6,
  comments: "IBM Cloud / Bluemix identifiers.",
  any: [
    { type: "header", header: "server", re: /ibm/i, evidence: () => ["server:ibm"] },
    { type: "html", re: /bluemix/i, evidence: () => ["html:bluemix"] },
  ],
  note: "Often enterprise workloads.",
},
{
  category: "cloud_provider_hint",
  name: "DigitalOcean",
  confidence: 0.65,
  comments: "Droplet infra rarely exposes headers; CDN/Spaces may leak domain.",
  any: [
    { type: "html", re: /digitaloceanspaces\.com/i, evidence: () => ["asset:digitaloceanspaces.com"] },
  ],
  note: "Low passive detectability unless using Spaces CDN.",
},
{
  category: "cloud_provider_hint",
  name: "OVHcloud",
  confidence: 0.65,
  comments: "OVH sometimes visible via hosting headers or asset domains.",
  any: [
    { type: "header", header: "server", re: /ovh/i, evidence: () => ["server:ovh"] },
    { type: "html", re: /ovhcloud\.com/i, evidence: () => ["asset:ovhcloud.com"] },
  ],
  note: "Major European cloud provider.",
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
  {
  category: "ecommerce_platform",
  name: "Magento",
  confidence: 0.85,
  comments: "Magento exposes distinctive static asset paths and requirejs patterns.",
  any: [
    { type: "html", re: /\/static\/version\d+\//i, evidence: () => ["path:/static/version*/ (Magento static assets)"] },
    { type: "html", re: /mage\/cookies\.js/i, evidence: () => ["script:mage/cookies.js"] },
    { type: "html", re: /Magento_Ui\//i, evidence: () => ["path:Magento_Ui/"] },
  ],
},
{
  category: "ecommerce_platform",
  name: "PrestaShop",
  confidence: 0.9,
  comments: "PrestaShop has very recognizable /modules/ and /themes/ structure.",
  any: [
    { type: "html", re: /\/modules\/[a-z0-9_\-]+\//i, evidence: () => ["path:/modules/*"] },
    { type: "html", re: /\/themes\/[a-z0-9_\-]+\//i, evidence: () => ["path:/themes/*"] },
    { type: "metaGenerator", re: /prestashop/i, evidence: (m) => [`meta:generator=${m[0]}`] },
  ],
},
{
  category: "ecommerce_platform",
  name: "Shopify",
  confidence: 0.92,
  comments: "cdn.shopify.com and Shopify-specific JS globals are strong indicators.",
  any: [
    { type: "html", re: /cdn\.shopify\.com/i, evidence: () => ["asset:cdn.shopify.com"] },
    { type: "html", re: /Shopify\.theme/i, evidence: () => ["js:Shopify.theme"] },
  ],
},
{
  category: "ecommerce_platform",
  name: "WooCommerce",
  confidence: 0.88,
  comments: "WooCommerce runs on WordPress; look for wc-* assets and endpoints.",
  any: [
    { type: "html", re: /woocommerce/i, evidence: () => ["html:woocommerce keyword"] },
    { type: "html", re: /\/wp-content\/plugins\/woocommerce\//i, evidence: () => ["path:/wp-content/plugins/woocommerce/"] },
    { type: "html", re: /wc-ajax=/i, evidence: () => ["query:wc-ajax="] },
  ],
},
{
  category: "ecommerce_platform",
  name: "BigCommerce",
  confidence: 0.85,
  comments: "BigCommerce exposes bc-* scripts and CDN references.",
  any: [
    { type: "html", re: /cdn\d+\.bigcommerce\.com/i, evidence: () => ["asset:bigcommerce CDN"] },
    { type: "html", re: /window\.BCData/i, evidence: () => ["js:window.BCData"] },
  ],
},
{
  category: "ecommerce_platform",
  name: "OpenCart",
  confidence: 0.82,
  comments: "Common OpenCart route patterns and catalog/view structure.",
  any: [
    { type: "html", re: /index\.php\?route=common\/home/i, evidence: () => ["route:common/home"] },
    { type: "html", re: /catalog\/view\/theme\//i, evidence: () => ["path:catalog/view/theme/"] },
  ],
},
{
  category: "ecommerce_platform",
  name: "Salesforce Commerce Cloud",
  confidence: 0.8,
  comments: "Former Demandware. Look for dw-specific assets and pipelines.",
  any: [
    { type: "html", re: /\/on\/demandware\.store\//i, evidence: () => ["path:/on/demandware.store/"] },
    { type: "html", re: /dwac_/i, evidence: () => ["html:dwac_* marker"] },
  ],
},
{
  category: "ecommerce_platform",
  name: "SAP Commerce (Hybris)",
  confidence: 0.75,
  comments: "Hybris storefronts may expose accelerator paths.",
  any: [
    { type: "html", re: /\/_ui\/responsive\//i, evidence: () => ["path:/_ui/responsive/"] },
    { type: "html", re: /hybris/i, evidence: () => ["html:hybris keyword"] },
  ],
},
{
  category: "ecommerce_platform",
  name: "Wix eCommerce",
  confidence: 0.85,
  comments: "Wix storefronts load wixstatic assets and Wix-specific JS runtime.",
  any: [
    { type: "html", re: /static\.wixstatic\.com/i, evidence: () => ["asset:static.wixstatic.com"] },
    { type: "html", re: /wix-code-sdk/i, evidence: () => ["html:wix-code-sdk"] },
  ],
},
{
  category: "ecommerce_platform",
  name: "Squarespace Commerce",
  confidence: 0.82,
  comments: "Squarespace commerce relies on distinctive static.squarespace.com assets.",
  any: [
    { type: "html", re: /static\.squarespace\.com/i, evidence: () => ["asset:static.squarespace.com"] },
    { type: "metaGenerator", re: /squarespace/i, evidence: (m) => [`meta:generator=${m[0]}`] },
  ],
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
  name: ".NET / C# (hint)",
  confidence: 0.55,
  comments: "ASP.NET cookies/headers are good hints when exposed; often stripped in production.",
  any: [
    { type: "cookie", re: /\b\.(AspNetCore|ASPXAUTH)=/i, evidence: () => ["cookie:AspNet*"] },
    { type: "cookie", re: /\bASPSESSIONID/i, evidence: () => ["cookie:ASPSESSIONID*"] }, // older ASP/ASP.NET patterns
    { type: "header", header: "x-aspnet-version", re: /.+/i, evidence: (m) => [`header:x-aspnet-version=${m[0]}`] },
    { type: "header", header: "x-aspnetmvc-version", re: /.+/i, evidence: (m) => [`header:x-aspnetmvc-version=${m[0]}`] },
  ],
  note: "Hint only (cookie/header). Not a proof of the exact .NET stack or version.",
},
{
  category: "backend_hint",
  name: "Node.js (hint)",
  confidence: 0.5,
  comments: "Express/Koa/Hapi often expose X-Powered-By or connect.sid; frequently removed.",
  any: [
    { type: "header", header: "x-powered-by", re: /\bexpress\b/i, evidence: (m) => [`header:x-powered-by=${m[0]}`] },
    { type: "cookie", re: /\bconnect\.sid=/i, evidence: () => ["cookie:connect.sid"] },
  ],
  note: "Hint only. Node apps can hide these signals; other stacks can emulate them.",
},
{
  category: "backend_hint",
  name: "Python (hint)",
  confidence: 0.45,
  comments: "Python frameworks sometimes leak server headers; usually hidden behind reverse proxies.",
  any: [
    { type: "header", header: "server", re: /\bgunicorn\b/i, evidence: () => ["header:server~gunicorn"] },
    { type: "header", header: "server", re: /\buwsgi\b/i, evidence: () => ["header:server~uwsgi"] },
    { type: "cookie", re: /\bsessionid=/i, evidence: () => ["cookie:sessionid (common in Django)"] },
  ],
  note: "Hint only. 'sessionid' is not exclusive to Django; headers are often masked.",
},
{
  category: "backend_hint",
  name: "Ruby (hint)",
  confidence: 0.5,
  comments: "Rails apps often use _app_session cookies; Rack/Puma can appear in headers.",
  any: [
    { type: "cookie", re: /_session=/i, evidence: () => ["cookie:*_session"] }, // e.g., _myapp_session
    { type: "header", header: "server", re: /\bpuma\b/i, evidence: () => ["header:server~puma"] },
    { type: "header", header: "x-runtime", re: /.+/i, evidence: (m) => [`header:x-runtime=${m[0]}`] }, // sometimes Rails
  ],
  note: "Hint only. Cookie names are app-defined; not exclusive to Rails.",
},
{
  category: "backend_hint",
  name: "Go (hint)",
  confidence: 0.45,
  comments: "Some Go servers identify themselves; usually removed in hardened setups.",
  any: [
    { type: "header", header: "server", re: /\bcaddy\b/i, evidence: () => ["header:server~caddy (often Go)"] },
    { type: "header", header: "server", re: /\bfasthttp\b/i, evidence: () => ["header:server~fasthttp"] },
  ],
  note: "Hint only. Server headers are not reliable indicators of the app language.",
},
{
  category: "backend_hint",
  name: "Rust (hint)",
  confidence: 0.4,
  comments: "Rarely exposed; may show up as framework/server identifiers.",
  any: [
    { type: "header", header: "server", re: /\b(actix|rocket|warp)\b/i, evidence: (m) => [`header:server~${m[0]}`] },
  ],
  note: "Hint only. These markers are uncommon on public-facing production systems.",
},
{
  category: "backend_hint",
  name: "Kotlin (JVM) (hint)",
  confidence: 0.35,
  comments: "Kotlin runs on the JVM; without app-level disclosure, it's indistinguishable from Java.",
  any: [
    { type: "header", header: "x-powered-by", re: /\bktor\b/i, evidence: () => ["header:x-powered-by~ktor"] },
  ],
  note: "Hint only. Most Kotlin backends look identical to Java at the HTTP layer.",
},
{
  category: "backend_hint",
  name: "Scala (JVM) (hint)",
  confidence: 0.35,
  comments: "Scala is also JVM-based; Play can leak headers in some configs.",
  any: [
    { type: "header", header: "server", re: /\bplay\b/i, evidence: () => ["header:server~play"] },
  ],
  note: "Hint only. JVM stacks are hard to separate reliably via passive fingerprints.",
},
{
  category: "backend_hint",
  name: "Elixir (hint)",
  confidence: 0.4,
  comments: "Phoenix sometimes exposes 'cowboy' server header (Erlang/Elixir ecosystem).",
  any: [
    { type: "header", header: "server", re: /\bcowboy\b/i, evidence: () => ["header:server~cowboy"] },
  ],
  note: "Hint only. Cowboy can front multiple BEAM languages; not exclusive to Elixir.",
},
{
  category: "backend_hint",
  name: "JavaScript (Server) (hint)",
  confidence: 0.35,
  comments: "Generic JS-server hint if only a non-specific x-powered-by leaks.",
  any: [
    { type: "header", header: "x-powered-by", re: /\b(koa|hapi|next\.js|nestjs)\b/i, evidence: (m) => [`header:x-powered-by=${m[0]}`] },
  ],
  note: "Hint only. Any x-powered-by is easy to remove/spoof.",
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
// detect technos
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
    const protocols = await detectProtocols(r.finalUrl, r.headers);
    
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
      protocols,
      delivery,
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
