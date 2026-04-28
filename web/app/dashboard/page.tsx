"use client";

import { buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { CheckCircle, XCircle } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "https://api.claven.app";

type MeResponse = {
  email: string;
  connected: boolean;
  history_id: number | null;
};

type State =
  | { status: "loading" }
  | { status: "unauthenticated" }
  | { status: "loaded"; data: MeResponse };

export default function DashboardPage() {
  const router = useRouter();
  const [state, setState] = useState<State>({ status: "loading" });
  const [disconnecting, setDisconnecting] = useState(false);

  useEffect(() => {
    fetch(`${API_URL}/api/me`, { credentials: "include" }).then((res) => {
      if (!res.ok) {
        setState({ status: "unauthenticated" });
      } else {
        res.json().then((data: MeResponse) => setState({ status: "loaded", data }));
      }
    });
  }, []);

  async function handleDisconnect() {
    setDisconnecting(true);
    await fetch(`${API_URL}/api/disconnect`, { method: "POST", credentials: "include" });
    router.replace("/");
  }

  if (state.status === "loading") {
    return (
      <main className="flex flex-1 flex-col items-center justify-center px-6 py-24">
        <p className="text-muted-foreground">Loading…</p>
      </main>
    );
  }

  if (state.status === "unauthenticated") {
    return (
      <main className="flex flex-1 flex-col items-center justify-center px-6 py-24">
        <div className="flex flex-col items-center gap-6 text-center max-w-md">
          <p className="text-muted-foreground">You are not signed in.</p>
          <a href={`${API_URL}/oauth/start`} className={cn(buttonVariants())}>
            Connect Gmail
          </a>
        </div>
      </main>
    );
  }

  const { email, connected } = state.data;

  return (
    <main className="flex flex-1 flex-col items-center justify-center px-6 py-24">
      <div className="flex flex-col items-center gap-6 text-center max-w-md">
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>

        <p className="text-lg font-medium">{email}</p>

        <div className="flex items-center gap-2">
          {connected ? (
            <>
              <CheckCircle className="h-5 w-5 text-green-500" />
              <span className="text-sm text-muted-foreground">Connected</span>
            </>
          ) : (
            <>
              <XCircle className="h-5 w-5 text-destructive" />
              <span className="text-sm text-muted-foreground">Not connected</span>
            </>
          )}
        </div>

        <button
          onClick={handleDisconnect}
          disabled={disconnecting}
          className={cn(buttonVariants({ variant: "outline" }), "mt-2")}
        >
          {disconnecting ? "Disconnecting…" : "Disconnect"}
        </button>
      </div>
    </main>
  );
}
