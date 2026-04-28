"use client";

import { buttonVariants } from "@/components/ui/button";
import { SIGN_IN_LABEL } from "@/lib/constants";
import { cn } from "@/lib/utils";
import { CheckCircle, RefreshCw, Zap } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "https://api.claven.app";

type MeResponse = {
  email: string;
  connected: boolean;
  history_id: number | null;
  known_senders: number;
  processed_count: number;
  pending_count: number | null;
  unread_count: number | null;
  read_count: number | null;
  inbox_count: number | null;
};

type LabelRule = {
  field: string;
  known_sender?: boolean;
  contains?: string[];
};

type LabelConfig = {
  id: string;
  name: string;
  description?: string;
  rules: LabelRule[];
};

type State =
  | { status: "loading" }
  | { status: "unauthenticated" }
  | { status: "loaded"; data: MeResponse; labels: LabelConfig[] };

export default function DashboardPage() {
  const router = useRouter();
  const [state, setState] = useState<State>({ status: "loading" });
  const [connecting, setConnecting] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);
  const [loggingOut, setLoggingOut] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 10_000);
    return () => clearInterval(id);
  }, []);

  async function loadData() {
    try {
      const [meRes, configRes] = await Promise.all([
        fetch(`${API_URL}/api/me`, { credentials: "include" }),
        fetch(`${API_URL}/api/config`),
      ]);
      if (!meRes.ok) {
        setState({ status: "unauthenticated" });
        return;
      }
      const [data, config] = await Promise.all([meRes.json(), configRes.json()]);
      setState({ status: "loaded", data, labels: config.labels ?? [] });
      setLastUpdated(new Date());
    } catch {
      setState({ status: "unauthenticated" });
    }
  }

  useEffect(() => { loadData(); }, []);

  function formatRelativeTime(date: Date): string {
    const seconds = Math.floor((now - date.getTime()) / 1000);
    if (seconds < 60) return seconds <= 5 ? "just now" : `${seconds} seconds ago`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return minutes === 1 ? "1 minute ago" : `${minutes} minutes ago`;
    const hours = Math.floor(minutes / 60);
    return hours === 1 ? "1 hour ago" : `${hours} hours ago`;
  }

  async function handleRefresh() {
    setRefreshing(true);
    await loadData();
    setRefreshing(false);
  }

  async function handleLogout() {
    setLoggingOut(true);
    await fetch(`${API_URL}/api/logout`, { method: "POST", credentials: "include" });
    router.replace("/");
  }

  async function handleSwitchAccount() {
    await fetch(`${API_URL}/api/logout`, { method: "POST", credentials: "include" });
    window.location.href = `${API_URL}/oauth/start?return_to=${encodeURIComponent(window.location.origin)}`;
  }

  async function handleConnect() {
    setConnecting(true);
    const res = await fetch(`${API_URL}/api/connect`, { method: "POST", credentials: "include" });
    if (res.ok) {
      const data = await res.json();
      setState((prev) =>
        prev.status === "loaded"
          ? { ...prev, data: { ...prev.data, connected: true, history_id: data.history_id } }
          : prev,
      );
    }
    setConnecting(false);
  }

  async function handleDisconnect() {
    setDisconnecting(true);
    await fetch(`${API_URL}/api/disconnect`, { method: "POST", credentials: "include" });
    setState((prev) =>
      prev.status === "loaded"
        ? { ...prev, data: { ...prev.data, connected: false, history_id: null } }
        : prev,
    );
    setDisconnecting(false);
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
          <a
            href={`${API_URL}/oauth/start`}
            onClick={(e) => {
              e.preventDefault();
              window.location.href = `${API_URL}/oauth/start?return_to=${encodeURIComponent(window.location.origin)}`;
            }}
            className={cn(buttonVariants())}
          >
            {SIGN_IN_LABEL}
          </a>
        </div>
      </main>
    );
  }

  const { email, connected, known_senders, processed_count, pending_count, unread_count, read_count, inbox_count } = state.data;
  const { labels } = state;

  return (
    <>
      <header className="flex items-center justify-end gap-2 border-b px-6 py-3">
        <button
          onClick={handleSwitchAccount}
          className={cn(buttonVariants({ variant: "ghost", size: "sm" }))}
        >
          Switch account
        </button>
        <button
          onClick={handleLogout}
          disabled={loggingOut}
          className={cn(buttonVariants({ variant: "ghost", size: "sm" }))}
        >
          {loggingOut ? "Logging out…" : "Log out"}
        </button>
      </header>
      <main className="flex flex-1 flex-col items-center justify-center px-6 py-24">
        <div className="flex flex-col items-center gap-6 text-center max-w-md">
          <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>

          <p className="text-lg font-medium">{email}</p>

          <div className="w-full flex flex-col gap-1">
            <div className="w-full rounded-lg border bg-muted/40 px-5 py-4 text-sm divide-y divide-border/50">
              {labels.map((label) => {
                const isKnownSender = label.rules.some((r) => r.known_sender);
                const desc = label.description ?? label.rules
                  .map((r) =>
                    r.known_sender
                      ? `${r.field} is a known sender`
                      : `${r.field} contains ${r.contains?.join(", ")}`,
                  )
                  .join("; ");
                return (
                  <div key={label.id} className="flex flex-col gap-0.5 py-3 first:pt-0 last:pb-0">
                    <span className="font-medium">{label.name}</span>
                    <span className="text-xs text-muted-foreground">{desc}</span>
                    {isKnownSender && (
                      <div className="flex justify-between mt-1.5">
                        <span className="text-xs text-muted-foreground">Known senders</span>
                        <span className="text-xs tabular-nums text-muted-foreground">{known_senders}</span>
                      </div>
                    )}
                  </div>
                );
              })}
              <div className="flex justify-between py-3 first:pt-0 last:pb-0">
                <span className="text-muted-foreground">Processed</span>
                <span className="tabular-nums">{processed_count}</span>
              </div>
              <div className="flex justify-between py-3 first:pt-0 last:pb-0">
                <span className="text-muted-foreground">Pending</span>
                <span className="tabular-nums">{pending_count ?? "—"}</span>
              </div>
              {inbox_count !== null && (
                <div className="flex justify-between py-3 first:pt-0 last:pb-0">
                  <span className="text-muted-foreground">In inbox</span>
                  <span className="tabular-nums">{inbox_count}</span>
                </div>
              )}
              {read_count !== null && (
                <div className="flex justify-between py-3 first:pt-0 last:pb-0">
                  <span className="text-muted-foreground">Read</span>
                  <span className="tabular-nums">{read_count}</span>
                </div>
              )}
              {unread_count !== null && (
                <div className="flex justify-between py-3 first:pt-0 last:pb-0">
                  <span className="text-muted-foreground">Unread</span>
                  <span className="tabular-nums">{unread_count}</span>
                </div>
              )}
            </div>
            <div className="flex items-center justify-between">
              {lastUpdated !== null ? (
                <span className="text-xs text-muted-foreground">
                  Last updated{" "}
                  <span data-testid="last-updated-time">
                    {formatRelativeTime(lastUpdated)}
                  </span>
                </span>
              ) : (
                <span />
              )}
              <button
                onClick={handleRefresh}
                disabled={refreshing}
                aria-label="Refresh stats"
                className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground disabled:opacity-50"
              >
                <RefreshCw className={cn("h-3 w-3", refreshing && "animate-spin")} />
                <span>Refresh now</span>
              </button>
            </div>
          </div>

          <div className="flex flex-col items-center gap-3">
            <div className="flex items-center gap-2">
              {connected ? (
                <>
                  <CheckCircle className="h-5 w-5 text-green-500" />
                  <span className="text-sm text-muted-foreground">Connected</span>
                </>
              ) : (
                <>
                  <Zap className="h-5 w-5 text-muted-foreground" />
                  <span className="text-sm text-muted-foreground">Connected and ready to start filtering</span>
                </>
              )}
            </div>

            {connected ? (
              <button
                onClick={handleDisconnect}
                disabled={disconnecting}
                className={cn(buttonVariants({ variant: "outline" }))}
              >
                {disconnecting ? "Disconnecting…" : "Disconnect"}
              </button>
            ) : (
              <button
                onClick={handleConnect}
                disabled={connecting}
                className={cn(buttonVariants())}
              >
                {connecting ? "Starting…" : "Start filtering"}
              </button>
            )}
          </div>
        </div>
      </main>
    </>
  );
}
