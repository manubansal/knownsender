import fs from "fs";
import path from "path";
import { MarkdownContent } from "./markdown-content";

export default function HowItWorksPage() {
  let md = "# How Claven Works\n\nDocumentation not found.";
  try {
    md = fs.readFileSync(
      path.join(process.cwd(), "docs", "how-claven-works.md"),
      "utf-8",
    );
  } catch {
    // Fallback text above
  }

  return (
    <main className="flex flex-1 flex-col items-center px-6 py-16">
      <article className="w-full max-w-2xl">
        <MarkdownContent content={md} />
      </article>
    </main>
  );
}
