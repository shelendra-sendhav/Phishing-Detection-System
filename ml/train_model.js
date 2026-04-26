import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { extractFeatures, featureNames, normalizeUrl } from "../src/features.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const defaultDataset = path.join(__dirname, "..", "data", "training_urls.csv");
const outputPath = path.join(__dirname, "model.json");

function parseCsv(text) {
  const lines = text.trim().split(/\r?\n/);
  const headers = lines.shift().split(",").map((header) => header.trim().toLowerCase());
  const urlIndex = headers.findIndex((header) => ["url", "website", "link"].includes(header));
  const labelIndex = headers.findIndex((header) => ["label", "class", "status", "result"].includes(header));

  if (urlIndex === -1 || labelIndex === -1) {
    throw new Error("Dataset must include URL and label columns.");
  }

  return lines
    .map((line) => line.split(","))
    .filter((columns) => columns.length > Math.max(urlIndex, labelIndex))
    .map((columns) => {
      const rawLabel = columns[labelIndex].trim().toLowerCase();
      const label = ["1", "phishing", "bad", "malicious", "yes", "true"].includes(rawLabel) ? 1 : 0;
      return { url: normalizeUrl(columns[urlIndex].trim()), label };
    });
}

function standardize(rows) {
  const means = {};
  const stds = {};

  for (const name of featureNames) {
    means[name] = rows.reduce((sum, row) => sum + row.features[name], 0) / rows.length;
    const variance = rows.reduce((sum, row) => sum + (row.features[name] - means[name]) ** 2, 0) / rows.length;
    stds[name] = Math.sqrt(variance) || 1;
  }

  return { means, stds };
}

function sigmoid(value) {
  return 1 / (1 + Math.exp(-value));
}

function train(rows) {
  const { means, stds } = standardize(rows);
  const weights = Object.fromEntries(featureNames.map((name) => [name, 0]));
  let bias = 0;
  const learningRate = 0.08;
  const epochs = 3500;
  const regularization = 0.002;

  for (let epoch = 0; epoch < epochs; epoch += 1) {
    const gradients = Object.fromEntries(featureNames.map((name) => [name, 0]));
    let biasGradient = 0;

    for (const row of rows) {
      let score = bias;
      for (const name of featureNames) {
        const value = (row.features[name] - means[name]) / stds[name];
        score += value * weights[name];
      }

      const error = sigmoid(score) - row.label;
      biasGradient += error;

      for (const name of featureNames) {
        const value = (row.features[name] - means[name]) / stds[name];
        gradients[name] += error * value;
      }
    }

    bias -= learningRate * (biasGradient / rows.length);
    for (const name of featureNames) {
      const penalty = regularization * weights[name];
      weights[name] -= learningRate * ((gradients[name] / rows.length) + penalty);
    }
  }

  return { weights, bias, means, stds };
}

function evaluate(rows, model) {
  let correct = 0;
  for (const row of rows) {
    let score = model.bias;
    for (const name of featureNames) {
      score += ((row.features[name] - model.means[name]) / model.stds[name]) * model.weights[name];
    }
    const prediction = sigmoid(score) >= 0.5 ? 1 : 0;
    if (prediction === row.label) correct += 1;
  }
  return correct / rows.length;
}

const datasetPath = process.argv[2] ? path.resolve(process.argv[2]) : defaultDataset;
const records = parseCsv(await readFile(datasetPath, "utf8"));
const rows = records.map((record) => ({
  ...record,
  features: extractFeatures(record.url)
}));

const model = train(rows);
const accuracy = evaluate(rows, model);

await writeFile(
  outputPath,
  `${JSON.stringify(
    {
      version: new Date().toISOString(),
      modelType: "standardized_logistic_regression",
      threshold: 0.5,
      trainingRows: rows.length,
      trainingAccuracy: Number(accuracy.toFixed(4)),
      featureNames,
      ...model
    },
    null,
    2
  )}\n`
);

console.log(`Model trained on ${rows.length} URLs.`);
console.log(`Training accuracy: ${(accuracy * 100).toFixed(1)}%`);
console.log(`Saved model to ${outputPath}`);
