# Phishing URL Detection System

A production-ready full-stack project that takes a URL as input and predicts whether it is phishing. It returns a verdict, phishing percentage, risk level, detected signals, and a technical feature snapshot.

## Project Parts

- `public/` contains the static frontend deployed by Vercel.
- `api/health.js` and `api/predict.js` are Vercel serverless API routes.
- `server.js` is the local development server.
- `src/features.js` extracts URL features.
- `src/detector.js` loads the trained model and produces scan results.
- `ml/train_model.js` trains the logistic regression model.
- `ml/model.json` is the trained model used in production.
- `data/training_urls.csv` is a starter training dataset.

## Run Locally

```bash
node server.js
```

Open:

```text
http://localhost:3000
```

## Deploy To Vercel

This project is ready for Vercel as a static frontend plus serverless functions.

1. Push the project to GitHub.
2. Import the repository in Vercel.
3. Keep the default framework setting as `Other`.
4. Build command can stay empty, or use:

```bash
npm run vercel-build
```

5. Output directory should stay empty because Vercel serves the `public/` folder automatically.

If you use the Vercel CLI:

```bash
vercel deploy
```

For production:

```bash
vercel deploy --prod
```

## API

```http
POST /api/predict
Content-Type: application/json

{
  "url": "http://paypal.com.security-check-login.xyz/verify/account"
}
```

Example response:

```json
{
  "isPhishing": true,
  "phishingPercentage": 91,
  "riskLevel": "High"
}
```

Health check:

```http
GET /api/health
```

## Train The Model

Use the included starter dataset:

```bash
node ml/train_model.js
```

Use a Kaggle CSV after downloading it:

```bash
node ml/train_model.js path/to/kaggle_dataset.csv
```

The CSV should include a URL column named `url`, `website`, or `link`, and a label column named `label`, `class`, `status`, or `result`. Phishing labels can be `phishing`, `bad`, `malicious`, `yes`, `true`, or `1`; anything else is treated as legitimate.

## Production Notes

- The app validates URL input before scanning.
- API responses are not cached.
- Security headers are configured in `vercel.json`.
- Static assets are cacheable on Vercel.
- Browser scan history is stored only in the user's local browser storage.

This is still an educational phishing detector. A real commercial detector should use a larger dataset, live threat intelligence, domain age, DNS signals, and continuous retraining.
