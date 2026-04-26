import { scanUrl, validateUrlInput } from "../src/detector.js";

export default function handler(request, response) {
  if (request.method !== "POST") {
    response.setHeader("Allow", "POST");
    return response.status(405).json({ error: "Method not allowed" });
  }

  const validation = validateUrlInput(request.body?.url);

  if (!validation.valid) {
    return response.status(400).json({ error: validation.message });
  }

  response.setHeader("Cache-Control", "no-store");
  return response.status(200).json(scanUrl(validation.input));
}
