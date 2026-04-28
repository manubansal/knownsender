import { render, screen } from "@testing-library/react";
import { useSearchParams } from "next/navigation";
import { beforeEach, describe, expect, it, vi } from "vitest";

import Home from "@/app/page";

vi.mock("next/navigation");

function mockParams(params: Record<string, string | null>) {
  vi.mocked(useSearchParams).mockReturnValue({
    get: (key: string) => params[key] ?? null,
  } as ReturnType<typeof useSearchParams>);
}

const API_URL = "https://api.claven.app";

describe("Home page", () => {
  beforeEach(() => {
    mockParams({});
  });

  describe("no error param", () => {
    it("shows Sign in with Google button", () => {
      render(<Home />);
      expect(screen.getByRole("link", { name: "Sign in with Google" })).toBeInTheDocument();
    });

    it("Sign in with Google link points to the OAuth start endpoint", () => {
      render(<Home />);
      expect(screen.getByRole("link", { name: "Sign in with Google" })).toHaveAttribute(
        "href",
        `${API_URL}/oauth/start`,
      );
    });

    it("shows no error message", () => {
      render(<Home />);
      expect(screen.queryByRole("paragraph")).not.toHaveTextContent(/wrong|denied|expired|failed/i);
    });
  });

  describe("with error param", () => {
    it("shows Try again instead of Sign in with Google", () => {
      mockParams({ error: "oauth_denied" });
      render(<Home />);
      expect(screen.getByRole("link", { name: "Try again" })).toBeInTheDocument();
      expect(screen.queryByRole("link", { name: "Sign in with Google" })).not.toBeInTheDocument();
    });

    it("Try again link still points to the OAuth start endpoint", () => {
      mockParams({ error: "oauth_denied" });
      render(<Home />);
      expect(screen.getByRole("link", { name: "Try again" })).toHaveAttribute(
        "href",
        `${API_URL}/oauth/start`,
      );
    });

    it.each([
      ["oauth_denied", "You declined the Gmail permission"],
      ["invalid_state", "sign-in session expired"],
      ["token_exchange_failed", "Could not complete sign-in"],
      ["token_verification_failed", "Could not verify your account"],
      ["signup_failed", "account setup failed"],
      ["invalid_request", "Something went wrong"],
    ])("error=%s shows correct message", (error, expectedText) => {
      mockParams({ error });
      render(<Home />);
      expect(screen.getByText(new RegExp(expectedText, "i"))).toBeInTheDocument();
    });

    it("unknown error code shows fallback message", () => {
      mockParams({ error: "totally_unknown_error" });
      render(<Home />);
      expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
    });
  });
});
