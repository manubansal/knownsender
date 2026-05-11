import fs from "fs";
import path from "path";
import { MarkdownContent } from "./markdown-content";

// Read at build time (static page). Try repo root first, then web-relative.
function loadMarkdown(): string {
  const candidates = [
    path.join(process.cwd(), "..", "docs", "how-claven-works.md"),
    path.join(process.cwd(), "docs", "how-claven-works.md"),
  ];
  for (const p of candidates) {
    try {
      return fs.readFileSync(p, "utf-8");
    } catch {
      continue;
    }
  }
  return "# How Claven Works\n\nDocumentation not found.";
}

export default function HowItWorksPage() {
  const md = loadMarkdown();

  return (
    <main className="flex flex-1 flex-col items-center px-6 py-16">
      <article className="w-full max-w-2xl">
        <MarkdownContent content={md} />
      </article>
    </main>
  );
}
