"use client";

import { buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { CheckCircle } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

function ConnectedContent() {
  const params = useSearchParams();
  const email = params.get("email") ?? "your account";

  return (
    <div className="flex flex-col items-center gap-6 text-center max-w-md">
      <CheckCircle className="h-12 w-12 text-green-500" />
      <h1 className="text-3xl font-bold tracking-tight">You&rsquo;re connected</h1>
      <p className="text-lg text-muted-foreground leading-relaxed">
        <span className="font-medium text-foreground">{email}</span> is now
        connected to Claven. New emails arriving in your inbox will be labeled
        automatically.
      </p>
      <a href="/" className={cn(buttonVariants({ variant: "outline" }))}>
        Back to home
      </a>
    </div>
  );
}

export default function ConnectedPage() {
  return (
    <main className="flex flex-1 flex-col items-center justify-center px-6 py-24">
      <Suspense>
        <ConnectedContent />
      </Suspense>
    </main>
  );
}
