import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "Vendor Risk Rating Assistant",
  description:
    "Evaluate vendor analyst notes against policy-driven safeguards to determine risk ratings."
};

export default function RootLayout({
  children
}: {
  children: ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-slate-100 text-slate-900">
        <div className="mx-auto max-w-5xl px-4 py-10">
          <header className="mb-8 space-y-2">
            <h1 className="text-3xl font-bold text-slate-900">
              Vendor Risk Rating Assistant
            </h1>
            <p className="text-slate-600">
              Paste analyst notes to see how the vendor maps to the policy catalog and
              determine the resulting risk rating.
            </p>
          </header>
          <main>{children}</main>
        </div>
      </body>
    </html>
  );
}
