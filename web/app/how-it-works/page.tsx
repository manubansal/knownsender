import fs from "fs";
import path from "path";
import { MarkdownContent } from "./markdown-content";

export default function HowItWorksPage() {
  let md = "# How Claven Works\n\nDocumentation not found.";
  const candidates = [
    path.join(/* turbopackIgnore: true */ process.cwd(), "docs", "how-claven-works.md"),
    path.join(/* turbopackIgnore: true */ process.cwd(), "..", "docs", "how-claven-works.md"),
    path.join(/* turbopackIgnore: true */ process.cwd(), "web", "docs", "how-claven-works.md"),
  ];
  for (const p of candidates) {
    try {
      md = fs.readFileSync(p, "utf-8");
      break;
    } catch {
      continue;
    }
  }

  return (
    <main className="flex flex-1 flex-col items-center px-6 py-16">
      <article className="w-full max-w-2xl">
        <MarkdownContent content={md} />
      </article>
    </main>
  );
}
