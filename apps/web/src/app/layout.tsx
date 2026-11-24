import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";
import { SessionProvider } from "@/components/session-provider";
import AppShell from "@/components/app-shell";

export const metadata: Metadata = {
  title: "Fleet Intelligence · Rayda",
  description: "Evidence-led fleet operations console",
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <body><SessionProvider><AppShell>{children}</AppShell></SessionProvider></body>
    </html>
  );
}
