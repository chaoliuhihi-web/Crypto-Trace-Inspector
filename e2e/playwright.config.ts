import { defineConfig } from "@playwright/test";

const isCI = !!process.env.CI;

export default defineConfig({
  testDir: "./tests",
  timeout: 5 * 60 * 1000, // 采集/导出可能较慢，给足空间
  expect: {
    timeout: 15 * 1000,
  },
  retries: isCI ? 1 : 0,
  reporter: [
    ["list"],
    ["html", { outputFolder: "../output/playwright/report", open: "never" }],
  ],
  use: {
    baseURL: process.env.E2E_BASE_URL || "http://127.0.0.1:8787",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  // E2E 测试跑在真实服务上：由 Playwright 在测试前自动启动并等待健康检查通过。
  webServer: {
    command: "bash ../scripts/e2e_web_server.sh",
    url: "http://127.0.0.1:8787/api/health",
    reuseExistingServer: !isCI,
    timeout: 120 * 1000,
  },
  outputDir: "../output/playwright/test-output",
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});

