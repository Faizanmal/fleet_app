import type { NextConfig } from "next";

// Keep Windows and constrained CI builds deterministic; production runtimes can tune workers.
const nextConfig: NextConfig = { output: "standalone", experimental: { cpus: 1 } };

export default nextConfig;
