import fs from "node:fs/promises";
import path from "node:path";
import RiskEvaluator from "../components/RiskEvaluator";

async function loadSampleNotes(): Promise<string> {
  const samplePath = path.join(process.cwd(), "sample_notes.txt");
  try {
    const file = await fs.readFile(samplePath, "utf-8");
    return file.trim();
  } catch (error) {
    console.warn("Sample notes could not be loaded:", error);
    return "";
  }
}

export default async function HomePage() {
  const sampleNotes = await loadSampleNotes();
  return <RiskEvaluator initialNotes={sampleNotes} />;
}
