import { buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "https://api.claven.app";

export default function Home() {
  return (
    <main className="flex flex-1 flex-col items-center justify-center px-6 py-24">
      <div className="flex flex-col items-center gap-6 text-center max-w-md">
        <h1 className="text-4xl font-bold tracking-tight">Claven</h1>
        <p className="text-lg text-muted-foreground leading-relaxed">
          Automatic Gmail labeling. Define your rules once — Claven applies them
          to every new email.
        </p>
        <a
          href={`${API_URL}/oauth/start`}
          className={cn(buttonVariants({ size: "lg" }), "mt-2")}
        >
          Connect Gmail
        </a>
      </div>
    </main>
  );
}
