import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import DashboardPage from "@/app/dashboard/page";
import { SIGN_IN_LABEL } from "@/lib/constants";

// Module-level mocks — defined before vi.mock so the factory can close over them.
const replaceMock = vi.fn();
const pushMock = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock, replace: replaceMock }),
  useSearchParams: () => ({ get: () => null }),
}));

const API_URL = "https://api.claven.app";

const DEFAULT_ME: object = {
  email: "user@example.com",
  connected: true,
  history_id: 12345,
  known_senders: 0,
  sent_scanned_count: 0,
  sent_total_count: null,
  sent_scan_status: null,
  inbox_scan_in_progress: false,
  unread_count: null,
  read_count: null,
  inbox_count: null,
};

const DEFAULT_CONFIG: object = { labels: [] };

function mockFetch(
  me: { ok: boolean; status?: number; body?: object } = { ok: true, body: DEFAULT_ME },
  config: object = DEFAULT_CONFIG,
) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockImplementation((url: string) => {
      if (url.includes("/api/config")) {
        return Promise.resolve({ ok: true, status: 200, json: async () => config });
      }
      // /api/me and everything else
      return Promise.resolve({
        ok: me.ok,
        status: me.status ?? (me.ok ? 200 : 401),
        json: async () => me.body ?? {},
      });
    }),
  );
}

beforeEach(() => {
  replaceMock.mockReset();
  pushMock.mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Dashboard page", () => {
  describe("loading state", () => {
    it("shows a loading indicator before data arrives", () => {
      vi.stubGlobal("fetch", vi.fn().mockReturnValue(new Promise(() => {})));
      render(<DashboardPage />);
      expect(screen.getByText(/loading/i)).toBeInTheDocument();
    });
  });

  describe("authenticated", () => {
    beforeEach(() => {
      mockFetch({
        ok: true,
        body: { email: "user@example.com", connected: true, history_id: 12345, known_senders: 7, unread_count: 42 },
      });
    });

    it("shows the user's email", async () => {
      render(<DashboardPage />);
      await screen.findByText("user@example.com");
    });

    it("shows connected status", async () => {
      render(<DashboardPage />);
      await screen.findByText(/connected/i);
    });

    it("shows a disconnect button", async () => {
      render(<DashboardPage />);
      await screen.findByRole("button", { name: /disconnect/i });
    });

    it("fetches /api/me on mount", async () => {
      render(<DashboardPage />);
      await screen.findByText("user@example.com");
      expect(vi.mocked(fetch)).toHaveBeenCalledWith(
        `${API_URL}/api/me`,
        expect.objectContaining({ credentials: "include" }),
      );
    });
  });

  describe("not connected", () => {
    beforeEach(() => {
      mockFetch({
        ok: true,
        body: { email: "user@example.com", connected: false, history_id: null, known_senders: 3, unread_count: 10 },
      });
    });

    it("shows ready to connect status when history_id is absent", async () => {
      render(<DashboardPage />);
      await screen.findByText(/connected and ready to start filtering/i);
    });

    it("shows connect gmail button", async () => {
      render(<DashboardPage />);
      await screen.findByRole("button", { name: /start filtering/i });
    });

    it("does not show disconnect button", async () => {
      render(<DashboardPage />);
      await screen.findByText(/connected and ready to start filtering/i);
      expect(screen.queryByRole("button", { name: /disconnect/i })).not.toBeInTheDocument();
    });

    it("calls /api/connect on connect button click", async () => {
      render(<DashboardPage />);
      const button = await screen.findByRole("button", { name: /start filtering/i });

      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({
          ok: true,
          json: async () => ({ ok: true, history_id: 99999 }),
        }),
      );
      await userEvent.click(button);

      await waitFor(() =>
        expect(vi.mocked(fetch)).toHaveBeenCalledWith(
          `${API_URL}/api/connect`,
          expect.objectContaining({ method: "POST", credentials: "include" }),
        ),
      );
    });

    it("shows connected after successful connect", async () => {
      render(<DashboardPage />);
      const button = await screen.findByRole("button", { name: /start filtering/i });

      const connectedMe = { ...DEFAULT_ME, connected: true, history_id: 99999 };
      vi.stubGlobal(
        "fetch",
        vi.fn().mockImplementation((url: string) => {
          if (url.includes("/api/connect")) {
            return Promise.resolve({ ok: true, json: async () => ({ ok: true, history_id: 99999 }) });
          }
          if (url.includes("/api/config")) {
            return Promise.resolve({ ok: true, status: 200, json: async () => DEFAULT_CONFIG });
          }
          return Promise.resolve({ ok: true, status: 200, json: async () => connectedMe });
        }),
      );
      await userEvent.click(button);
      await screen.findByText(/connected/i);
      expect(screen.queryByText(/connected and ready to start filtering/i)).not.toBeInTheDocument();
    });
  });

  describe("unauthenticated", () => {
    it("shows sign-in prompt when /api/me returns 401", async () => {
      mockFetch({ ok: false, status: 401 });
      render(<DashboardPage />);
      await screen.findByRole("link", { name: SIGN_IN_LABEL });
    });
  });

  describe("disconnect", () => {
    it("calls /api/disconnect on button click", async () => {
      mockFetch({
        ok: true,
        body: { email: "user@example.com", connected: true, history_id: 12345 },
      });
      render(<DashboardPage />);
      const button = await screen.findByRole("button", { name: /disconnect/i });

      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({ ok: true, json: async () => ({ ok: true }) }),
      );
      await userEvent.click(button);

      await waitFor(() =>
        expect(vi.mocked(fetch)).toHaveBeenCalledWith(
          `${API_URL}/api/disconnect`,
          expect.objectContaining({ method: "POST", credentials: "include" }),
        ),
      );
    });

    it("stays on dashboard after disconnect", async () => {
      mockFetch({
        ok: true,
        body: { email: "user@example.com", connected: true, history_id: 12345 },
      });
      render(<DashboardPage />);
      const button = await screen.findByRole("button", { name: /disconnect/i });

      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({ ok: true, json: async () => ({ ok: true }) }),
      );
      await userEvent.click(button);
      await waitFor(() => expect(replaceMock).not.toHaveBeenCalled());
    });

    it("shows ready to connect after disconnect", async () => {
      mockFetch({
        ok: true,
        body: { email: "user@example.com", connected: true, history_id: 12345 },
      });
      render(<DashboardPage />);
      const button = await screen.findByRole("button", { name: /disconnect/i });

      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({ ok: true, json: async () => ({ ok: true }) }),
      );
      await userEvent.click(button);
      await screen.findByText(/connected and ready to start filtering/i);
    });

    it("shows connect gmail button after disconnect", async () => {
      mockFetch({
        ok: true,
        body: { email: "user@example.com", connected: true, history_id: 12345 },
      });
      render(<DashboardPage />);
      const button = await screen.findByRole("button", { name: /disconnect/i });

      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({ ok: true, json: async () => ({ ok: true }) }),
      );
      await userEvent.click(button);
      await screen.findByRole("button", { name: /start filtering/i });
    });
  });

  describe("logout", () => {
    it("shows a log out button", async () => {
      mockFetch({
        ok: true,
        body: { email: "user@example.com", connected: true, history_id: 12345 },
      });
      render(<DashboardPage />);
      await screen.findByRole("button", { name: /log out/i });
    });

    it("calls /api/logout on click", async () => {
      mockFetch({
        ok: true,
        body: { email: "user@example.com", connected: true, history_id: 12345 },
      });
      render(<DashboardPage />);
      const button = await screen.findByRole("button", { name: /log out/i });

      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({ ok: true, json: async () => ({ ok: true }) }),
      );
      await userEvent.click(button);

      await waitFor(() =>
        expect(vi.mocked(fetch)).toHaveBeenCalledWith(
          `${API_URL}/api/logout`,
          expect.objectContaining({ method: "POST", credentials: "include" }),
        ),
      );
    });

    it("redirects to home after logout", async () => {
      mockFetch({
        ok: true,
        body: { email: "user@example.com", connected: true, history_id: 12345 },
      });
      render(<DashboardPage />);
      const button = await screen.findByRole("button", { name: /log out/i });

      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({ ok: true, json: async () => ({ ok: true }) }),
      );
      await userEvent.click(button);
      await waitFor(() => expect(replaceMock).toHaveBeenCalledWith("/"));
    });
  });

  describe("stats", () => {
    it("shows known senders count after rule title and description", async () => {
      mockFetch(
        { ok: true, body: { ...DEFAULT_ME, known_senders: 42 } },
        { labels: [{ id: "known-sender", name: "Known Sender", rules: [{ field: "from", known_sender: true }] }] },
      );
      render(<DashboardPage />);
      await screen.findByText("42");
    });

    it("shows messages scanned as fraction before known senders", async () => {
      mockFetch(
        { ok: true, body: { ...DEFAULT_ME, known_senders: 10, sent_scanned_count: 150, sent_total_count: 500 } },
        { labels: [{ id: "known-sender", name: "Known Sender", rules: [{ field: "from", known_sender: true }] }] },
      );
      render(<DashboardPage />);
      await screen.findByText(/messages scanned/i);
      await screen.findByText("150 / 500");
    });

    it("shows messages scanned without total when total is null", async () => {
      mockFetch(
        { ok: true, body: { ...DEFAULT_ME, known_senders: 10, sent_scanned_count: 75, sent_total_count: null } },
        { labels: [{ id: "known-sender", name: "Known Sender", rules: [{ field: "from", known_sender: true }] }] },
      );
      render(<DashboardPage />);
      await screen.findByText(/messages scanned/i);
      await screen.findByText("75");
    });

    it("shows messages scanned row even when zero", async () => {
      mockFetch(
        { ok: true, body: { ...DEFAULT_ME, known_senders: 0, sent_scanned_count: 0, sent_total_count: null } },
        { labels: [{ id: "known-sender", name: "Known Sender", rules: [{ field: "from", known_sender: true }] }] },
      );
      render(<DashboardPage />);
      await screen.findByText(/messages scanned/i);
    });

    it("shows spinner when sent scan is in progress", async () => {
      mockFetch(
        { ok: true, body: { ...DEFAULT_ME, sent_scan_status: "in_progress", sent_scanned_count: 50, sent_total_count: 200 } },
        { labels: [{ id: "known-sender", name: "Known Sender", rules: [{ field: "from", known_sender: true }] }] },
      );
      render(<DashboardPage />);
      await screen.findByTestId("sent-scan-spinner");
    });

    it("does not show spinner when sent scan is complete", async () => {
      mockFetch(
        { ok: true, body: { ...DEFAULT_ME, sent_scan_status: "complete", sent_scanned_count: 200, sent_total_count: 200 } },
        { labels: [{ id: "known-sender", name: "Known Sender", rules: [{ field: "from", known_sender: true }] }] },
      );
      render(<DashboardPage />);
      await screen.findByText(/messages scanned/i);
      expect(screen.queryByTestId("sent-scan-spinner")).not.toBeInTheDocument();
    });

    it("shows spinner on known senders when scan is in progress", async () => {
      mockFetch(
        { ok: true, body: { ...DEFAULT_ME, sent_scan_status: "in_progress", known_senders: 5 } },
        { labels: [{ id: "known-sender", name: "Known Sender", rules: [{ field: "from", known_sender: true }] }] },
      );
      render(<DashboardPage />);
      await screen.findByTestId("known-senders-spinner");
    });

    it("does not show spinner on known senders when scan is complete", async () => {
      mockFetch(
        { ok: true, body: { ...DEFAULT_ME, sent_scan_status: "complete", known_senders: 42 } },
        { labels: [{ id: "known-sender", name: "Known Sender", rules: [{ field: "from", known_sender: true }] }] },
      );
      render(<DashboardPage />);
      await screen.findByText("42");
      expect(screen.queryByTestId("known-senders-spinner")).not.toBeInTheDocument();
    });

    it("shows unread count", async () => {
      mockFetch({ ok: true, body: { ...DEFAULT_ME, unread_count: 99 } });
      render(<DashboardPage />);
      await screen.findByText(/99/);
    });

    it("shows inbox count", async () => {
      mockFetch({ ok: true, body: { ...DEFAULT_ME, inbox_count: 250 } });
      render(<DashboardPage />);
      await screen.findByText(/inbox/i);
      await screen.findByText("250");
    });

    const FILTER_CONFIG = {
      labels: [{
        id: "known-sender",
        name: "Known Sender",
        unknown_label: "unknown-sender",
        rules: [{ field: "from", known_sender: true }],
      }],
    };

    it("shows labeled as known-sender count under the label that has unknown_label", async () => {
      mockFetch({ ok: true, body: { ...DEFAULT_ME, filtered_in_count: 15 } }, FILTER_CONFIG);
      render(<DashboardPage />);
      await screen.findByText(/labeled as known-sender/i);
      await screen.findByText("15");
    });

    it("shows em dash for labeled as known-sender when null", async () => {
      mockFetch({ ok: true, body: { ...DEFAULT_ME, filtered_in_count: null } }, FILTER_CONFIG);
      render(<DashboardPage />);
      await screen.findByText(/labeled as known-sender/i);
    });

    it("shows labeled as unknown-sender count under the label that has unknown_label", async () => {
      mockFetch({ ok: true, body: { ...DEFAULT_ME, filtered_out_count: 8 } }, FILTER_CONFIG);
      render(<DashboardPage />);
      await screen.findByText(/labeled as unknown-sender/i);
      await screen.findByText("8");
    });

    it("shows em dash for labeled as unknown-sender when null", async () => {
      mockFetch({ ok: true, body: { ...DEFAULT_ME, filtered_out_count: null } }, FILTER_CONFIG);
      render(<DashboardPage />);
      await screen.findByText(/labeled as unknown-sender/i);
    });

    it("shows unlabeled count under the label that has unknown_label", async () => {
      mockFetch({ ok: true, body: { ...DEFAULT_ME, unlabeled_count: 3 } }, FILTER_CONFIG);
      render(<DashboardPage />);
      await screen.findByText(/unlabeled/i);
      await screen.findByText("3");
    });

    it("shows em dash for unlabeled when null", async () => {
      mockFetch({ ok: true, body: { ...DEFAULT_ME, unlabeled_count: null } }, FILTER_CONFIG);
      render(<DashboardPage />);
      await screen.findByText(/unlabeled/i);
    });

    it("shows waiting icon on filter rows when scan is not complete", async () => {
      mockFetch(
        { ok: true, body: { ...DEFAULT_ME, connected: true, sent_scan_status: "in_progress", inbox_count: 50, unlabeled_count: 10, filtered_in_count: 5, filtered_out_count: 3 } },
        FILTER_CONFIG,
      );
      render(<DashboardPage />);
      const icons = await screen.findAllByTestId("filter-waiting-icon");
      expect(icons.length).toBe(4);
    });

    it("shows active icon on filter rows when connected and scan is complete", async () => {
      mockFetch(
        { ok: true, body: { ...DEFAULT_ME, connected: true, sent_scan_status: "complete", inbox_count: 50, unlabeled_count: 10, filtered_in_count: 5, filtered_out_count: 3 } },
        FILTER_CONFIG,
      );
      render(<DashboardPage />);
      const icons = await screen.findAllByTestId("filter-active-icon");
      expect(icons.length).toBe(4);
    });

    it("shows waiting icon when not connected even if scan complete", async () => {
      mockFetch(
        { ok: true, body: { ...DEFAULT_ME, connected: false, sent_scan_status: "complete", inbox_count: 50, unlabeled_count: 10, filtered_in_count: 5, filtered_out_count: 3 } },
        FILTER_CONFIG,
      );
      render(<DashboardPage />);
      const icons = await screen.findAllByTestId("filter-waiting-icon");
      expect(icons.length).toBe(4);
    });

    it("shows spinner on filter rows during initial labeling", async () => {
      mockFetch(
        { ok: true, body: { ...DEFAULT_ME, connected: true, sent_scan_status: "complete", inbox_scan_in_progress: true, inbox_count: 50, unlabeled_count: 50, filtered_in_count: 0, filtered_out_count: 0 } },
        FILTER_CONFIG,
      );
      render(<DashboardPage />);
      const icons = await screen.findAllByTestId("filter-labeling-icon");
      expect(icons.length).toBe(4);
    });

    it("shows active icon after initial labeling completes", async () => {
      mockFetch(
        { ok: true, body: { ...DEFAULT_ME, connected: true, sent_scan_status: "complete", inbox_scan_in_progress: false, inbox_count: 50, unlabeled_count: 10, filtered_in_count: 30, filtered_out_count: 20 } },
        FILTER_CONFIG,
      );
      render(<DashboardPage />);
      const icons = await screen.findAllByTestId("filter-active-icon");
      expect(icons.length).toBe(4);
    });

    it("shows read count from api", async () => {
      mockFetch({ ok: true, body: { ...DEFAULT_ME, read_count: 70 } });
      render(<DashboardPage />);
      await screen.findByText(/^read$/i);
      await screen.findByText("70");
    });

    it("shows em dash for read count when null", async () => {
      mockFetch({ ok: true, body: { ...DEFAULT_ME, read_count: null, unread_count: 30 } });
      render(<DashboardPage />);
      await screen.findByText("30");
      await screen.findByText(/^read$/i);
    });

    it("shows last updated label after data loads", async () => {
      mockFetch({ ok: true, body: DEFAULT_ME });
      render(<DashboardPage />);
      await screen.findByText(/last updated/i);
    });

    it("shows a relative time next to last updated", async () => {
      mockFetch({ ok: true, body: DEFAULT_ME });
      render(<DashboardPage />);
      await screen.findByText(/last updated/i);
      expect(screen.getByTestId("last-updated-time").textContent).toMatch(
        /just now|\d+ seconds? ago|\d+ minutes? ago|\d+ hours? ago/,
      );
    });

    it("still shows last updated time after refresh", async () => {
      mockFetch({ ok: true, body: DEFAULT_ME });
      render(<DashboardPage />);
      await screen.findByTestId("last-updated-time");

      vi.stubGlobal(
        "fetch",
        vi.fn().mockImplementation((url: string) => {
          if (url.includes("/api/config")) {
            return Promise.resolve({ ok: true, status: 200, json: async () => DEFAULT_CONFIG });
          }
          return Promise.resolve({ ok: true, status: 200, json: async () => DEFAULT_ME });
        }),
      );
      await userEvent.click(screen.getByRole("button", { name: /refresh stats/i }));

      await screen.findByTestId("last-updated-time");
    });

    it("shows description from config when provided", async () => {
      mockFetch(
        { ok: true, body: DEFAULT_ME },
        { labels: [{ id: "known-sender", name: "Known Sender", description: "Someone you've emailed before", rules: [{ field: "from", known_sender: true }] }] },
      );
      render(<DashboardPage />);
      await screen.findByText("Known Sender");
      await screen.findByText("Someone you've emailed before");
    });

    it("falls back to computed description when description is absent", async () => {
      mockFetch(
        { ok: true, body: DEFAULT_ME },
        { labels: [{ id: "known-sender", name: "Known Sender", rules: [{ field: "from", known_sender: true }] }] },
      );
      render(<DashboardPage />);
      await screen.findByText("Known Sender");
      await screen.findByText(/from is a known sender/i);
    });

  });

  describe("refresh", () => {
    it("shows a refresh button in the info box", async () => {
      mockFetch({ ok: true, body: DEFAULT_ME });
      render(<DashboardPage />);
      await screen.findByRole("button", { name: /refresh stats/i });
    });

    it("re-fetches /api/me on refresh button click", async () => {
      mockFetch({ ok: true, body: DEFAULT_ME });
      render(<DashboardPage />);
      const button = await screen.findByRole("button", { name: /refresh stats/i });

      const refreshedMe = { ...DEFAULT_ME, unread_count: 10 };
      vi.stubGlobal(
        "fetch",
        vi.fn().mockImplementation((url: string) => {
          if (url.includes("/api/config")) {
            return Promise.resolve({ ok: true, status: 200, json: async () => DEFAULT_CONFIG });
          }
          return Promise.resolve({ ok: true, status: 200, json: async () => refreshedMe });
        }),
      );
      await userEvent.click(button);

      await waitFor(() =>
        expect(vi.mocked(fetch)).toHaveBeenCalledWith(
          `${API_URL}/api/me`,
          expect.objectContaining({ credentials: "include" }),
        ),
      );
    });

    it("updates counts after refresh", async () => {
      mockFetch({ ok: true, body: DEFAULT_ME });
      render(<DashboardPage />);
      const button = await screen.findByRole("button", { name: /refresh stats/i });

      const refreshedMe = { ...DEFAULT_ME, unread_count: 77 };
      vi.stubGlobal(
        "fetch",
        vi.fn().mockImplementation((url: string) => {
          if (url.includes("/api/config")) {
            return Promise.resolve({ ok: true, status: 200, json: async () => DEFAULT_CONFIG });
          }
          return Promise.resolve({
            ok: true,
            status: 200,
            json: async () => refreshedMe,
          });
        }),
      );
      await userEvent.click(button);
      await screen.findByText("77");
    });
  });

  describe("switch account", () => {
    it("shows a switch account button", async () => {
      mockFetch({ ok: true, body: DEFAULT_ME });
      render(<DashboardPage />);
      await screen.findByRole("button", { name: /switch account/i });
    });

    it("calls /api/logout and redirects to sign-in on switch account", async () => {
      mockFetch({ ok: true, body: DEFAULT_ME });
      render(<DashboardPage />);
      const button = await screen.findByRole("button", { name: /switch account/i });

      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({ ok: true, json: async () => ({ ok: true }) }),
      );
      await userEvent.click(button);

      await waitFor(() =>
        expect(vi.mocked(fetch)).toHaveBeenCalledWith(
          `${API_URL}/api/logout`,
          expect.objectContaining({ method: "POST", credentials: "include" }),
        ),
      );
    });
  });
});
