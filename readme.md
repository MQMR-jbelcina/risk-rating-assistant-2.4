# Risk Rating Assistant

A React/Next.js application that evaluates vendor risk ratings from analyst notes using the policy and procedure catalog defined in `rules/rating_rules.json`.

## Getting started

1. Install dependencies:

   ```bash
   npm install
   ```

2. Run the development server:

   ```bash
   npm run dev
   ```

3. Open http://localhost:3000 in your browser. Paste analyst notes into the text area and click **Evaluate Vendor** to compute the risk rating.

The page loads with the sample notes from `sample_notes.txt` so you can see a fully satisfied example immediately.

## Project structure

- `app/` – Next.js app router pages and global layout/styles.
- `components/` – UI components, including the interactive risk evaluator.
- `lib/evaluator.ts` – TypeScript implementation of the policy-driven risk evaluation engine.
- `rules/rating_rules.json` – Source catalog with all controls, conditions, and rating thresholds.
- `sample_notes.txt` – Example analyst notes demonstrating a comprehensive submission.

## Scripts

- `npm run dev` – Start the development server with hot reloading.
- `npm run build` – Create an optimized production build.
- `npm run start` – Run the production build locally.
- `npm run lint` – Run Next.js ESLint checks.
