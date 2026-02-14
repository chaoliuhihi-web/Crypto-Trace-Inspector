import { expect, test } from "@playwright/test";
import { execFileSync } from "node:child_process";
import path from "node:path";
import fs from "node:fs";

function goBin(): string {
  // 本仓库脚本会优先设置 GO_BIN；CI 上通常 go 在 PATH 里。
  return (process.env.GO_BIN || "").trim() || "go";
}

test("E2E smoke: 建案 -> 主机采集 -> 司法导出ZIP -> verify", async ({
  page,
  request,
}) => {
  const repoRoot = path.resolve(__dirname, "../..");
  // 目标：不依赖真机/外部环境，跑通“可用闭环”：
  // - UI 建案
  // - UI 触发 scan-all（只勾选主机，避免移动端前置条件导致失败）
  // - UI 生成司法导出包 ZIP
  // - CLI 对 ZIP 内 hashes.sha256 + manifest.json 做离线校验

  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "01 案件信息" })
  ).toBeVisible();

  // --- 建案 ---
  const caseNo = `E2E-${Date.now()}`;
  await page.getByPlaceholder("如：2026-01-001（可选）").fill(caseNo);
  await page.getByPlaceholder("如：涉币资金流向排查").fill("E2E Smoke");
  await page.getByPlaceholder("请输入案件备注信息...").fill(
    "playwright e2e smoke"
  );
  await page.getByRole("button", { name: "[新建案件]" }).click();

  // 案件创建后，“创建时间”会从 "-" 变成具体时间字符串（该输入框在页面上是第一个 disabled input）。
  await expect(page.locator("input[disabled]").first()).not.toHaveValue("-");

  // --- 采集（仅主机） ---
  await page.goto("/collection");
  await expect(
    page.getByRole("heading", { name: "03 数据采集" })
  ).toBeVisible();

  // 勾选项顺序：主机 / Android / iOS。关闭移动端，保证在 CI/无设备时也能稳定跑通。
  const checkboxes = page.locator('input[type="checkbox"]');
  await checkboxes.nth(0).setChecked(true);
  await checkboxes.nth(1).setChecked(false);
  await checkboxes.nth(2).setChecked(false);

  await page.getByRole("button", { name: "[开始采集]" }).click();

  // 等待 job 完成。页面底部会显示“当前阶段：完成”。
  await expect(page.getByText("当前阶段：完成")).toBeVisible({
    timeout: 4 * 60 * 1000,
  });

  // 读取当前选中 case_id（由前端存于 localStorage）
  const caseID = await page.evaluate(() => {
    return localStorage.getItem("crypto_inspector.selected_case_id") || "";
  });
  expect(caseID).toBeTruthy();

  // 通过 API 做一次“证据存在性”断言（不依赖 UI 表格结构）
  const artsResp = await request.get(
    `/api/cases/${encodeURIComponent(caseID)}/artifacts`
  );
  expect(artsResp.ok()).toBeTruthy();
  const artsJSON = (await artsResp.json()) as any;
  const artifacts = (artsJSON?.artifacts as any[]) || [];
  expect(artifacts.length).toBeGreaterThan(0);

  // --- 校验证据快照（sha256/size） ---
  // E2E 环境下证据目录应当完整可复核：全部 ok。
  const verifyArtifactsResp = await request.post(
    `/api/cases/${encodeURIComponent(caseID)}/verify/artifacts`,
    { data: { operator: "e2e", note: "e2e verify artifacts" } }
  );
  expect(verifyArtifactsResp.ok()).toBeTruthy();
  const verifyArtifactsJSON = (await verifyArtifactsResp.json()) as any;
  expect(verifyArtifactsJSON?.ok).toBeTruthy();

  // --- 校验审计链（强校验：prev_hash 连续 + chain_hash 重算一致） ---
  const verifyAuditsResp = await request.post(
    `/api/cases/${encodeURIComponent(caseID)}/verify/audits`,
    { data: { operator: "e2e", note: "e2e verify audits", limit: 5000 } }
  );
  expect(verifyAuditsResp.ok()).toBeTruthy();
  const verifyAuditsJSON = (await verifyAuditsResp.json()) as any;
  expect(verifyAuditsJSON?.ok).toBeTruthy();

  // --- 生成司法导出 ZIP ---
  await page.goto("/report");
  await expect(
    page.getByRole("heading", { name: "07 报告生成" })
  ).toBeVisible();

  // --- 生成取证 PDF ---
  await page.getByRole("button", { name: "[生成取证 PDF]" }).click();
  await expect(
    page.getByText("已生成（请在“历史报告”列表中下载 forensic_pdf）")
  ).toBeVisible({
    timeout: 3 * 60 * 1000,
  });

  await page.getByRole("button", { name: "[生成司法导出包（ZIP）]" }).click();
  await expect(page.getByText("已生成（请在“历史报告”列表中下载 forensic_zip）")).toBeVisible({
    timeout: 3 * 60 * 1000,
  });

  // 拉取 reports 列表，定位 forensic_zip 的 file_path
  const reportsResp = await request.get(
    `/api/cases/${encodeURIComponent(caseID)}/reports`
  );
  expect(reportsResp.ok()).toBeTruthy();
  const reportsJSON = (await reportsResp.json()) as any;
  const reports = (reportsJSON?.reports as any[]) || [];
  const pdfReport = reports.find((r) => r?.report_type === "forensic_pdf");
  expect(pdfReport).toBeTruthy();
  const zipReport = reports.find((r) => r?.report_type === "forensic_zip");
  expect(zipReport).toBeTruthy();

  // PDF 文件存在性检查（不校验内容；二进制下载校验由 /download 负责）
  const pdfPath = String(pdfReport.file_path || "").trim();
  expect(pdfPath.endsWith(".pdf")).toBeTruthy();
  const pdfAbs = path.isAbsolute(pdfPath)
    ? pdfPath
    : path.resolve(repoRoot, pdfPath);
  expect(fs.existsSync(pdfAbs)).toBeTruthy();

  const zipPath = String(zipReport.file_path || "").trim();
  expect(zipPath.endsWith(".zip")).toBeTruthy();
  const zipAbs = path.isAbsolute(zipPath) ? zipPath : path.resolve(repoRoot, zipPath);
  expect(fs.existsSync(zipAbs)).toBeTruthy();

  // --- 离线校验 ZIP（hash 清单 + manifest） ---
  // 使用 go run 调用仓库内的 verify 子命令，确保“导出包可复核”。
  // 注意：这里用 go run 而不是依赖某个已编译二进制，避免 E2E 环境差异。
  execFileSync(
    goBin(),
    ["run", "./cmd/inspector-cli", "verify", "forensic-zip", "--zip", zipAbs],
    {
      cwd: repoRoot,
      stdio: "inherit",
      env: { ...process.env },
    }
  );
});
