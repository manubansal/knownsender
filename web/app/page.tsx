"use client";

import { buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "https://api.claven.app";

const ERROR_MESSAGES: Record<string, string> = {
  oauth_denied: "You declined the Gmail permission. Grant access to continue.",
  invalid_state: "The sign-in session expired. Please try again.",
  token_exchange_failed: "Could not complete sign-in. Please try again.",
  token_verification_failed: "Could not verify your account. Please try again.",
  signup_failed: "Sign-in succeeded but account setup failed. Please try again.",
  invalid_request: "Something went wrong. Please try again.",
};

function HomeContent() {
  const params = useSearchParams();
  const error = params.get("error");
  const errorMessage = error ? (ERROR_MESSAGES[error] ?? "Something went wrong. Please try again.") : null;

  return (
    <div className="flex flex-col items-center gap-6 text-center max-w-md">
      <h1 className="text-4xl font-bold tracking-tight">Claven</h1>
      <p className="text-lg text-muted-foreground leading-relaxed">
        Automatic Gmail labeling. Define your rules once — Claven applies them
        to every new email.
      </p>
      {errorMessage && (
        <p className="text-sm text-destructive">{errorMessage}</p>
      )}
      <a
        href={`${API_URL}/oauth/start`}
        className={cn(buttonVariants({ size: "lg" }), "mt-2")}
      >
        {errorMessage ? "Try again" : "Sign in with Google"}
      </a>
    </div>
  );
}

export default function Home() {
  return (
    <main className="flex flex-1 flex-col items-center justify-center px-6 py-24">
      <Suspense>
        <HomeContent />
      </Suspense>
    </main>
  );
}
