import { test, expect } from "@playwright/test";

test("overview to low-disk investigation exposes evidence references", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Good morning, operations" })).toBeVisible();
  await page.getByRole("link", { name: /Start an investigation/ }).click();
  await page.getByRole("button", { name: "Which devices have less than 20% disk free?" }).click();
  await expect(page.getByText(/2 devices|device.*2/i)).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText(/Evidence/i).first()).toBeVisible();
  await expect(page.getByRole("button", { name: /ev_/ }).first()).toBeVisible();
});

test("battery health question returns an evidence gap, not a percentage", async ({ page }) => {
  await page.goto("/copilot");
  await page.getByRole("button", { name: "What is the exact battery health percentage?" }).click();
  await expect(page.getByText(/insufficient evidence|cannot determine|not available/i).first()).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText(/\b\d{1,3}%\b/)).toHaveCount(0);
});

test("tenant account change clears previous page state and actions stay role gated", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Authorized demo tenant").selectOption("globex-002");
  await expect(page.getByText("Globex / Fleet operations")).toBeVisible();
  await page.goto("/actions");
  await expect(page.getByText("No external orders, tickets, replacements, or messages are sent by this console.")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Draft sandbox proposal" })).toHaveCount(0);
  await page.getByLabel("Development fixture role").selectOption("operator");
  await expect(page.getByRole("heading", { name: "Draft sandbox proposal" })).toBeVisible();
});
