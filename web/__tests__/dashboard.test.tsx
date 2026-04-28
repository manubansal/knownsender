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
  processed_count: 0,
  pending_count: null,
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

      vi.stubGlobal(
        "fetch",
        vi.fn().mockResolvedValue({
          ok: true,
          json: async () => ({ ok: true, history_id: 99999 }),
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
    it("shows known senders count next to its rule label", async () => {
      mockFetch(
        { ok: true, body: { ...DEFAULT_ME, known_senders: 42 } },
        { labels: [{ name: "Known", rules: [{ field: "from", known_sender: true }] }] },
      );
      render(<DashboardPage />);
      await screen.findByText("42");
    });

    it("shows unread count", async () => {
      mockFetch({ ok: true, body: { ...DEFAULT_ME, unread_count: 99 } });
      render(<DashboardPage />);
      await screen.findByText(/99/);
    });

    it("shows inbox count", async () => {
      mockFetch({ ok: true, body: { ...DEFAULT_ME, inbox_count: 250 } });
      render(<DashboardPage />);
      await screen.findByText(/in inbox/i);
      await screen.findByText("250");
    });

    it("shows processed count", async () => {
      mockFetch({ ok: true, body: { ...DEFAULT_ME, processed_count: 123 } });
      render(<DashboardPage />);
      await screen.findByText(/processed/i);
      await screen.findByText("123");
    });

    it("shows pending count when available", async () => {
      mockFetch({ ok: true, body: { ...DEFAULT_ME, pending_count: 47 } });
      render(<DashboardPage />);
      await screen.findByText(/pending/i);
      await screen.findByText("47");
    });

    it("shows em dash for pending when pending_count is null", async () => {
      mockFetch({ ok: true, body: { ...DEFAULT_ME, pending_count: null } });
      render(<DashboardPage />);
      await screen.findByText(/pending/i);
      await screen.findByText("—");
    });

    it("shows read count from api", async () => {
      mockFetch({ ok: true, body: { ...DEFAULT_ME, read_count: 70 } });
      render(<DashboardPage />);
      await screen.findByText(/^read$/i);
      await screen.findByText("70");
    });

    it("does not show read count when read_count is null", async () => {
      mockFetch({ ok: true, body: { ...DEFAULT_ME, read_count: null, unread_count: 30 } });
      render(<DashboardPage />);
      await screen.findByText(/30/);
      expect(screen.queryByText(/^read$/i)).not.toBeInTheDocument();
    });

    it("shows last updated label after data loads", async () => {
      mockFetch({ ok: true, body: DEFAULT_ME });
      render(<DashboardPage />);
      await screen.findByText(/last updated/i);
    });

    it("shows a time value next to last updated", async () => {
      mockFetch({ ok: true, body: DEFAULT_ME });
      render(<DashboardPage />);
      await screen.findByText(/last updated/i);
      // time rendered as HH:MM AM/PM or HH:MM
      expect(screen.getByTestId("last-updated-time").textContent).toMatch(/\d{1,2}:\d{2}/);
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

    it("shows rule name and description from /api/config", async () => {
      mockFetch(
        { ok: true, body: DEFAULT_ME },
        { labels: [{ name: "Known", rules: [{ field: "from", known_sender: true }] }] },
      );
      render(<DashboardPage />);
      await screen.findByText("Known");
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

      const refreshedMe = { ...DEFAULT_ME, processed_count: 5, unread_count: 10 };
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
      mockFetch({ ok: true, body: { ...DEFAULT_ME, processed_count: 0 } });
      render(<DashboardPage />);
      const button = await screen.findByRole("button", { name: /refresh stats/i });

      vi.stubGlobal(
        "fetch",
        vi.fn().mockImplementation((url: string) => {
          if (url.includes("/api/config")) {
            return Promise.resolve({ ok: true, status: 200, json: async () => DEFAULT_CONFIG });
          }
          return Promise.resolve({
            ok: true,
            status: 200,
            json: async () => ({ ...DEFAULT_ME, processed_count: 99 }),
          });
        }),
      );
      await userEvent.click(button);
      await screen.findByText("99");
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
