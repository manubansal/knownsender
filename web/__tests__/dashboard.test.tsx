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

function mockFetch(response: { ok: boolean; status?: number; body?: object }) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: response.ok,
      status: response.status ?? (response.ok ? 200 : 401),
      json: async () => response.body ?? {},
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
        body: { email: "user@example.com", connected: true, history_id: 12345 },
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
        body: { email: "user@example.com", connected: false, history_id: null },
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
});
