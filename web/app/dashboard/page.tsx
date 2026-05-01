"use client";

import { buttonVariants } from "@/components/ui/button";
import { SIGN_IN_LABEL } from "@/lib/constants";
import { cn } from "@/lib/utils";
import { CheckCircle, Clock, Loader2, RefreshCw, Zap } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "https://api.claven.app";

type MeResponse = {
  email: string;
  connected: boolean;
  history_id: number | null;
  known_senders: number;
  sent_scanned_count: number;
  sent_total_count: number | null;
  sent_scan_status: string | null;
  inbox_scan_in_progress: boolean;
  last_fetched_at: string | null;
  last_labeled_at: string | null;
  newest_mail_at: string | null;
  newest_labeled_at: string | null;
  unread_count: number | null;
  read_count: number | null;
  inbox_count: number | null;
  all_mail_count: number | null;
  allmail_labeled_known_count: number | null;
  allmail_labeled_unknown_count: number | null;
  allmail_labeled_total_count: number | null;
  inbox_unlabeled_first_page_count: number | null;
  inbox_unlabeled_deep_count: number | null;
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
  unknown_label?: string;
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
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);
    try {
      const [meRes, configRes] = await Promise.all([
        fetch(`${API_URL}/api/me`, { credentials: "include", signal: controller.signal }),
        fetch(`${API_URL}/api/config`, { signal: controller.signal }),
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
    } finally {
      clearTimeout(timeout);
    }
  }

  useEffect(() => { loadData(); }, []);

  // Live progress via Server-Sent Events — workers push updates after each
  // batch commit via Postgres NOTIFY. No polling, no wasted API calls.
  // Debounced: rapid events (multiple batches/second) collapse into one
  // loadData call every 3 seconds to avoid flooding /api/me.
  useEffect(() => {
    if (state.status !== "loaded") return;
    let debounceTimer: ReturnType<typeof setTimeout> | null = null;
    const es = new EventSource(`${API_URL}/api/events`, { withCredentials: true });
    es.onmessage = () => {
      if (!debounceTimer) {
        debounceTimer = setTimeout(() => {
          debounceTimer = null;
          loadData();
        }, 3_000);
      }
    };
    es.onerror = () => {
      // SSE disconnected — EventSource auto-reconnects (browser default)
    };
    return () => {
      es.close();
      if (debounceTimer) clearTimeout(debounceTimer);
    };
  }, [state.status]);

  function formatRelativeTime(date: Date, suffix = "ago"): string {
    const seconds = Math.floor((now - date.getTime()) / 1000);
    if (seconds < 60) return seconds <= 5 && suffix === "ago" ? "just now" : `${seconds} seconds ${suffix}`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return minutes === 1 ? `1 minute ${suffix}` : `${minutes} minutes ${suffix}`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return hours === 1 ? `1 hour ${suffix}` : `${hours} hours ${suffix}`;
    const days = Math.floor(hours / 24);
    return days === 1 ? `1 day ${suffix}` : `${days} days ${suffix}`;
  }

  async function handleRefresh() {
    setRefreshing(true);
    try {
      await loadData();
    } finally {
      setRefreshing(false);
    }
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
      await loadData();
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

  const { email, connected, known_senders, sent_scanned_count, sent_total_count, sent_scan_status, inbox_scan_in_progress, unread_count, read_count, inbox_count, all_mail_count, allmail_labeled_known_count, allmail_labeled_unknown_count, allmail_labeled_total_count, inbox_unlabeled_first_page_count, inbox_unlabeled_deep_count } = state.data;
  const { labels } = state;

  return (
    <>
      <header className="flex items-center justify-end gap-2 border-b px-6 py-3">
        {connected && (
          <button
            onClick={handleDisconnect}
            disabled={disconnecting}
            className={cn(buttonVariants({ variant: "ghost", size: "sm" }))}
          >
            {disconnecting ? "Disconnecting…" : "Disconnect"}
          </button>
        )}
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

          <div className="flex items-center gap-2">
            {connected ? (
              <>
                <CheckCircle className="h-5 w-5 text-green-500" />
                <span className="text-sm text-muted-foreground">Connected</span>
              </>
            ) : (
              <>
                <Zap className="h-5 w-5 text-muted-foreground" />
                <span className="text-sm text-muted-foreground">Connected and ready to start labeling</span>
              </>
            )}
          </div>

          <div className="w-full flex flex-col gap-1">
            <div className="w-full rounded-lg border bg-muted/40 px-5 py-4 text-sm divide-y divide-border/50">
              <div className="flex justify-between gap-4 py-3 first:pt-0 last:pb-0">
                <span className="text-muted-foreground">Inbox</span>
                <span className="tabular-nums">{inbox_count ?? "—"}</span>
              </div>
              <div className="flex justify-between gap-4 py-3 first:pt-0 last:pb-0">
                <span className="text-muted-foreground">Read</span>
                <span className="tabular-nums">{read_count ?? "—"}</span>
              </div>
              <div className="flex justify-between gap-4 py-3 first:pt-0 last:pb-0">
                <span className="text-muted-foreground">Unread</span>
                <span className="tabular-nums">{unread_count ?? "—"}</span>
              </div>
              <div className="flex justify-between gap-4 py-3 first:pt-0 last:pb-0">
                <span className="text-muted-foreground">All mail</span>
                <span className="tabular-nums">{all_mail_count ?? "—"}</span>
              </div>
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
                      <div className="flex flex-col gap-2 mt-2">
                        <span className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground/60">Sent scan</span>
                        <div className="flex flex-col gap-0.5">
                          <div className="flex justify-between gap-4 items-center">
                            <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                              {sent_scan_status === "in_progress" ? (
                                <Loader2 className="h-3 w-3 animate-spin" data-testid="sent-scan-spinner" />
                              ) : sent_scan_status === "complete" ? (
                                <CheckCircle className="h-3 w-3 text-green-500" data-testid="sent-scan-complete" />
                              ) : null}
                              Messages scanned
                            </span>
                            <span className="text-xs tabular-nums text-muted-foreground">
                              {sent_scanned_count}{sent_total_count !== null ? ` / ${sent_total_count}` : ""}
                            </span>
                          </div>
                          <div className="flex justify-between gap-4 items-center">
                            <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                              {sent_scan_status === "in_progress" ? (
                                <Loader2 className="h-3 w-3 animate-spin" data-testid="known-senders-spinner" />
                              ) : sent_scan_status === "complete" ? (
                                <CheckCircle className="h-3 w-3 text-green-500" data-testid="known-senders-complete" />
                              ) : null}
                              Known senders found
                            </span>
                            <span className="text-xs tabular-nums text-muted-foreground">{known_senders}</span>
                          </div>
                        </div>
                      </div>
                    )}
                    {label.unknown_label !== undefined && (() => {
                      const scanDone = connected && sent_scan_status === "complete";
                      const filterComplete = scanDone && !inbox_scan_in_progress;
                      const FilterIcon = inbox_scan_in_progress ? Loader2 : filterComplete ? CheckCircle : Clock;
                      const iconColor = filterComplete ? "text-green-500" : "";
                      const iconExtra = inbox_scan_in_progress ? "animate-spin" : "";
                      const iconTestId = inbox_scan_in_progress ? "filter-labeling-icon" : filterComplete ? "filter-complete-icon" : "filter-waiting-icon";
                      return (
                        <div className="flex flex-col gap-2 mt-2">
                          <span className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground/60">Inbox scan</span>
                          <div className="flex flex-col gap-0.5">
                            <div className="flex justify-between gap-4 items-center">
                              <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                                <FilterIcon className={`h-3 w-3 ${iconColor} ${iconExtra}`} data-testid={iconTestId} />
                                Allmail labeled
                              </span>
                              <span className="text-xs tabular-nums text-muted-foreground">
                                {allmail_labeled_total_count ?? "—"}
                              </span>
                            </div>
                            <div className="flex justify-between gap-4 items-center">
                              <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                                <FilterIcon className={`h-3 w-3 ${iconColor} ${iconExtra}`} data-testid={iconTestId} />
                                Allmail known-sender
                              </span>
                              <span className="text-xs tabular-nums text-muted-foreground">{allmail_labeled_known_count ?? "—"}</span>
                            </div>
                            <div className="flex justify-between gap-4 items-center">
                              <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                                <FilterIcon className={`h-3 w-3 ${iconColor} ${iconExtra}`} data-testid={iconTestId} />
                                Allmail unknown-sender
                              </span>
                              <span className="text-xs tabular-nums text-muted-foreground">{allmail_labeled_unknown_count ?? "—"}</span>
                            </div>
                            <div className="flex justify-between gap-4 items-center">
                              <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                                <FilterIcon className={`h-3 w-3 ${iconColor} ${iconExtra}`} data-testid={iconTestId} />
                                Inbox unlabeled
                              </span>
                              <span className="text-xs tabular-nums text-muted-foreground">{inbox_unlabeled_deep_count ?? "—"}</span>
                            </div>
                            <div className="flex justify-between gap-4 items-center mt-1 pt-1 border-t border-border/30">
                              <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                                <span className="inline-block h-3 w-3 text-center text-[8px] leading-3">●</span>
                                Last fetched
                              </span>
                              <span className="text-xs tabular-nums text-muted-foreground">
                                {state.data.last_fetched_at
                                  ? formatRelativeTime(new Date(state.data.last_fetched_at))
                                  : "—"}
                              </span>
                            </div>
                            <div className="flex justify-between gap-4 items-center">
                              <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                                <span className="inline-block h-3 w-3 text-center text-[8px] leading-3">●</span>
                                Last labeled
                              </span>
                              <span className="text-xs tabular-nums text-muted-foreground">
                                {state.data.last_labeled_at
                                  ? formatRelativeTime(new Date(state.data.last_labeled_at))
                                  : "—"}
                              </span>
                            </div>
                            <div className="flex justify-between gap-4 items-center">
                              <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                                <span className="inline-block h-3 w-3 text-center text-[8px] leading-3">●</span>
                                Newest email
                              </span>
                              <span className="text-xs tabular-nums text-muted-foreground">
                                {state.data.newest_mail_at
                                  ? formatRelativeTime(new Date(state.data.newest_mail_at), "old")
                                  : "—"}
                              </span>
                            </div>
                            <div className="flex justify-between gap-4 items-center">
                              <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                                <span className="inline-block h-3 w-3 text-center text-[8px] leading-3">●</span>
                                Newest labeled
                              </span>
                              <span className="text-xs tabular-nums text-muted-foreground">
                                {state.data.newest_labeled_at
                                  ? formatRelativeTime(new Date(state.data.newest_labeled_at), "old")
                                  : "—"}
                              </span>
                            </div>
                          </div>
                        </div>
                      );
                    })()}
                    <div className="flex justify-between gap-4 items-center mt-3 pt-2 border-t border-border/50">
                      <span className="text-xs font-semibold">Noise reduced</span>
                      <span className="text-xs font-semibold tabular-nums">
                        {allmail_labeled_total_count !== null && allmail_labeled_unknown_count !== null && allmail_labeled_total_count > 0
                          ? `${Math.round((allmail_labeled_unknown_count / allmail_labeled_total_count) * 100)}%`
                          : "—"}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="flex items-center justify-between gap-4">
              {lastUpdated !== null ? (
                <span className="text-xs text-muted-foreground min-w-0 truncate">
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
                className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground disabled:opacity-50 shrink-0"
              >
                <RefreshCw className={cn("h-3 w-3", refreshing && "animate-spin")} />
                <span>Refresh now</span>
              </button>
            </div>
          </div>

          <button
            onClick={connected ? handleDisconnect : handleConnect}
            disabled={connecting || disconnecting}
            className={cn(buttonVariants(connected ? { variant: "outline" } : {}))}
          >
            {connecting ? "Starting…" : disconnecting ? "Pausing…" : connected ? "Pause labeling" : "Start labeling"}
          </button>
        </div>
      </main>
    </>
  );
}
