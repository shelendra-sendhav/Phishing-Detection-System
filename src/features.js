const suspiciousWords = [
  "account",
  "banking",
  "bonus",
  "confirm",
  "free",
  "gift",
  "login",
  "password",
  "paypal",
  "prize",
  "recover",
  "secure",
  "security",
  "signin",
  "support",
  "update",
  "verify",
  "wallet",
  "webscr"
];

const shortenerDomains = new Set([
  "bit.ly",
  "cutt.ly",
  "goo.gl",
  "is.gd",
  "ow.ly",
  "rebrand.ly",
  "s.id",
  "t.co",
  "tiny.cc",
  "tinyurl.com"
]);

const riskyTlds = new Set(["biz", "click", "country", "gq", "info", "link", "loan", "ml", "tk", "top", "work", "xyz", "zip"]);

export function normalizeUrl(input) {
  const trimmed = String(input || "").trim();
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) return trimmed;
  return `http://${trimmed}`;
}

function safeUrl(input) {
  try {
    return new URL(normalizeUrl(input));
  } catch {
    return null;
  }
}

function entropy(text) {
  if (!text) return 0;
  const counts = new Map();
  for (const char of text) counts.set(char, (counts.get(char) || 0) + 1);
  let total = 0;
  for (const count of counts.values()) {
    const probability = count / text.length;
    total -= probability * Math.log2(probability);
  }
  return total;
}

export function extractFeatures(input) {
  const normalized = normalizeUrl(input);
  const parsed = safeUrl(normalized);
  const hostname = parsed ? parsed.hostname.toLowerCase() : "";
  const pathname = parsed ? parsed.pathname.toLowerCase() : "";
  const fullText = `${hostname}${pathname}`.toLowerCase();
  const labels = hostname.split(".").filter(Boolean);
  const tld = labels.at(-1) || "";

  return {
    url_length: normalized.length,
    hostname_length: hostname.length,
    digit_count: (normalized.match(/\d/g) || []).length,
    special_char_count: (normalized.match(/[?&=%_$~!*(),;:+-]/g) || []).length,
    dot_count: (hostname.match(/\./g) || []).length,
    hyphen_count: (hostname.match(/-/g) || []).length,
    subdomain_count: Math.max(labels.length - 2, 0),
    has_ip_address: /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) ? 1 : 0,
    has_at_symbol: normalized.includes("@") ? 1 : 0,
    uses_https: parsed?.protocol === "https:" ? 1 : 0,
    suspicious_word_count: suspiciousWords.filter((word) => fullText.includes(word)).length,
    shortener_domain: shortenerDomains.has(hostname) ? 1 : 0,
    risky_tld: riskyTlds.has(tld) ? 1 : 0,
    query_length: parsed ? parsed.search.length : 0,
    path_depth: pathname.split("/").filter(Boolean).length,
    hostname_entropy: Number(entropy(hostname).toFixed(3))
  };
}

export const featureNames = Object.keys(extractFeatures("https://example.com"));
