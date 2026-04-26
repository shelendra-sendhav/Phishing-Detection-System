import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { extractFeatures, normalizeUrl } from "./features.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const modelPath = path.join(__dirname, "..", "ml", "model.json");
const model = JSON.parse(readFileSync(modelPath, "utf8"));

function sigmoid(value) {
  return 1 / (1 + Math.exp(-value));
}

function predictProbability(url) {
  const features = extractFeatures(url);
  let score = model.bias;

  for (const name of model.featureNames) {
    const scaled = (features[name] - model.means[name]) / (model.stds[name] || 1);
    score += scaled * model.weights[name];
  }

  return {
    probability: sigmoid(score),
    features
  };
}

function buildReasons(features) {
  const reasons = [];

  if (features.has_ip_address) reasons.push("The URL uses an IP address instead of a normal domain.");
  if (features.has_at_symbol) reasons.push("The URL contains an @ symbol, which can hide the real destination.");
  if (features.suspicious_word_count > 0) reasons.push("It contains words commonly used in phishing pages.");
  if (features.shortener_domain) reasons.push("It uses a URL shortener, which can hide the final destination.");
  if (!features.uses_https) reasons.push("It does not use HTTPS.");
  if (features.subdomain_count >= 3) reasons.push("It has many subdomains, a common trick for impersonation.");
  if (features.url_length > 90) reasons.push("The URL is unusually long.");
  if (features.risky_tld) reasons.push("The top-level domain is frequently seen in suspicious links.");

  return reasons.length ? reasons : ["No major phishing indicators were detected by the model."];
}

export function getHealth() {
  return {
    status: "ok",
    modelVersion: model.version,
    modelType: model.modelType,
    trainingRows: model.trainingRows,
    trainingAccuracy: model.trainingAccuracy
  };
}

export function scanUrl(inputUrl) {
  const normalizedUrl = normalizeUrl(inputUrl);
  const { probability, features } = predictProbability(normalizedUrl);
  const percentage = Math.round(probability * 100);

  return {
    url: normalizedUrl,
    isPhishing: probability >= model.threshold,
    phishingProbability: probability,
    phishingPercentage: percentage,
    riskLevel: percentage >= 75 ? "High" : percentage >= 45 ? "Medium" : "Low",
    reasons: buildReasons(features),
    featureSnapshot: features
  };
}

export function validateUrlInput(value) {
  const input = String(value || "").trim();

  if (!input) {
    return { valid: false, message: "Please enter a URL." };
  }

  if (input.length > 2048) {
    return { valid: false, message: "URL is too long to scan." };
  }

  try {
    const parsed = new URL(normalizeUrl(input));
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return { valid: false, message: "Only HTTP and HTTPS URLs can be scanned." };
    }
  } catch {
    return { valid: false, message: "Please enter a valid URL." };
  }

  return { valid: true, input };
}
