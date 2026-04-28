import { render, screen } from "@testing-library/react";
import { useSearchParams } from "next/navigation";
import { beforeEach, describe, expect, it, vi } from "vitest";

import ConnectedPage from "@/app/connected/page";

vi.mock("next/navigation");

function mockParams(params: Record<string, string | null>) {
  vi.mocked(useSearchParams).mockReturnValue({
    get: (key: string) => params[key] ?? null,
  } as ReturnType<typeof useSearchParams>);
}

describe("Connected page", () => {
  beforeEach(() => {
    mockParams({});
  });

  it("shows the connected heading", () => {
    render(<ConnectedPage />);
    expect(screen.getByRole("heading", { name: /connected/i })).toBeInTheDocument();
  });

  it("shows the email when provided", () => {
    mockParams({ email: "user@example.com" });
    render(<ConnectedPage />);
    expect(screen.getByText("user@example.com")).toBeInTheDocument();
  });

  it("shows fallback when no email param", () => {
    render(<ConnectedPage />);
    expect(screen.getByText("your account")).toBeInTheDocument();
  });

  it("Back to home link points to /", () => {
    render(<ConnectedPage />);
    expect(screen.getByRole("link", { name: /back to home/i })).toHaveAttribute("href", "/");
  });
});
