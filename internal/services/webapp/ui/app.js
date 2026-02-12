/* eslint-disable */
// 内部试用版 UI：尽量用最少依赖跑通“列表 -> 一键扫描 -> 看结果”。

const api = {
  async getJSON(path) {
    const res = await fetch(path, { method: "GET" });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  },
  async postJSON(path, body) {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    return data;
  },
};

function $(id) {
  return document.getElementById(id);
}

function esc(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function fmtTs(ts) {
  if (!ts) return "-";
  try {
    return new Date(ts * 1000).toLocaleString();
  } catch {
    return String(ts);
  }
}

let state = {
  cases: [],
  activeCaseID: "",
};

async function loadCases() {
  const data = await api.getJSON("/api/cases?limit=200&offset=0");
  state.cases = data.cases || [];
  renderCaseList();
}

function renderCaseList() {
  const list = $("caseList");
  const q = ($("caseSearch").value || "").trim().toLowerCase();
  const items = state.cases.filter((c) => {
    const s = `${c.case_id} ${c.case_no || ""} ${c.title || ""}`.toLowerCase();
    return q === "" ? true : s.includes(q);
  });

  list.innerHTML = items
    .map((c) => {
      const active = c.case_id === state.activeCaseID ? "case-item--active" : "";
      return `
        <div class="case-item ${active}" data-case-id="${esc(c.case_id)}">
          <div class="case-item__id">${esc(c.case_id)}</div>
          <div class="case-item__title">${esc(c.title || "(no title)")}</div>
          <div class="case-item__meta">
            ${esc(c.status)} · ${esc(c.case_no || "-")} · ${esc(fmtTs(c.updated_at))}
          </div>
        </div>
      `;
    })
    .join("");

  [...list.querySelectorAll(".case-item")].forEach((el) => {
    el.addEventListener("click", () => {
      const id = el.getAttribute("data-case-id") || "";
      selectCase(id);
    });
  });
}

async function selectCase(caseID) {
  state.activeCaseID = caseID;
  window.location.hash = `case=${encodeURIComponent(caseID)}`;
  renderCaseList();

  $("emptyState").classList.add("hidden");
  $("caseView").classList.remove("hidden");
  $("reportContent").textContent = "";

  await Promise.all([
    loadOverview(),
    loadHits(),
    loadArtifacts(),
    loadPrechecks(),
    loadAudits(),
    loadReports(),
  ]);
}

async function loadOverview() {
  const ov = await api.getJSON(`/api/cases/${encodeURIComponent(state.activeCaseID)}/overview`);
  $("caseTitle").textContent = ov.title || ov.case_id;
  $("caseMeta").textContent = `${ov.case_id} · ${ov.case_no || "-"} · ${ov.status}`;
  $("kDevices").textContent = String(ov.device_count || 0);
  $("kArtifacts").textContent = String(ov.artifact_count || 0);
  $("kHits").textContent = String(ov.hit_count || 0);
  $("kReports").textContent = String(ov.report_count || 0);
}

async function loadHits() {
  const hitType = $("hitType").value || "";
  const q = hitType ? `?hit_type=${encodeURIComponent(hitType)}` : "";
  const data = await api.getJSON(`/api/cases/${encodeURIComponent(state.activeCaseID)}/hits${q}`);
  const hits = data.hits || [];
  $("hitsTable").innerHTML = renderTable(
    ["hit_id", "hit_type", "rule_id", "matched_value", "confidence", "verdict", "device_id"],
    hits,
    (row, k) => (k === "confidence" ? (row[k] ?? 0).toFixed(2) : row[k])
  );
}

async function loadArtifacts() {
  const data = await api.getJSON(`/api/cases/${encodeURIComponent(state.activeCaseID)}/artifacts`);
  const rows = data.artifacts || [];
  $("artifactsTable").innerHTML = renderTable(
    ["artifact_id", "artifact_type", "source_ref", "collected_at", "size_bytes", "sha256", "download"],
    rows,
    (row, k) => {
      if (k === "collected_at") return fmtTs(row.collected_at);
      if (k === "download")
        return `<a href="/api/artifacts/${encodeURIComponent(row.artifact_id)}/download">download</a>`;
      return row[k];
    }
  );
}

async function loadPrechecks() {
  const data = await api.getJSON(`/api/cases/${encodeURIComponent(state.activeCaseID)}/prechecks`);
  const rows = data.prechecks || [];
  $("prechecksTable").innerHTML = renderTable(
    ["checked_at", "scan_scope", "check_code", "required", "status", "message", "device_id"],
    rows,
    (row, k) => {
      if (k === "checked_at") return fmtTs(row.checked_at);
      if (k === "required") return row.required ? "true" : "false";
      return row[k];
    }
  );
}

async function loadAudits() {
  const data = await api.getJSON(`/api/cases/${encodeURIComponent(state.activeCaseID)}/audits?limit=800`);
  const rows = data.audits || [];
  $("auditsTable").innerHTML = renderTable(
    ["occurred_at", "event_type", "action", "status", "actor", "device_id", "source"],
    rows,
    (row, k) => (k === "occurred_at" ? fmtTs(row.occurred_at) : row[k])
  );
}

async function loadReports() {
  const data = await api.getJSON(`/api/cases/${encodeURIComponent(state.activeCaseID)}/reports`);
  const rows = data.reports || [];
  $("reportsTable").innerHTML = renderTable(
    ["generated_at", "report_id", "report_type", "sha256", "status", "download"],
    rows,
    (row, k) => {
      if (k === "generated_at") return fmtTs(row.generated_at);
      if (k === "download")
        return `<a href="/api/reports/${encodeURIComponent(row.report_id)}/download">download</a>`;
      return row[k];
    }
  );
}

async function loadLatestReportContent() {
  const data = await api.getJSON(`/api/cases/${encodeURIComponent(state.activeCaseID)}/report?content=true`);
  const content = data.content || "";
  $("reportContent").textContent = content;
}

function renderTable(headers, rows, cellFn) {
  const th = headers.map((h) => `<th>${esc(h)}</th>`).join("");
  const tbody = (rows || [])
    .map((r) => {
      const tds = headers
        .map((h) => {
          const v = cellFn ? cellFn(r, h) : r[h];
          if (typeof v === "string" && v.startsWith("<a ")) return `<td>${v}</td>`;
          return `<td>${esc(v ?? "")}</td>`;
        })
        .join("");
      return `<tr>${tds}</tr>`;
    })
    .join("");
  return `<table><thead><tr>${th}</tr></thead><tbody>${tbody}</tbody></table>`;
}

function openModal() {
  $("scanHint").textContent = "";
  $("modalBackdrop").classList.remove("hidden");
}

function closeModal() {
  $("modalBackdrop").classList.add("hidden");
}

async function startScanAll() {
  $("scanHint").textContent = "已提交任务，正在执行...";

  const operator = $("scanOperator").value || "system";
  const profile = $("scanProfile").value || "internal";
  const authOrder = $("scanAuthOrder").value || "";
  const authBasis = $("scanAuthBasis").value || "";
  const note = $("scanNote").value || "";
  const iosFullBackup = ($("scanIOSBackup").value || "true") === "true";
  const privacyMode = $("scanPrivacy").value || "off";

  let job = await api.postJSON("/api/jobs/scan-all", {
    operator,
    profile,
    auth_order: authOrder,
    auth_basis: authBasis,
    note,
    ios_full_backup: iosFullBackup,
    privacy_mode: privacyMode,
  });

  closeModal();

  const jobID = job.job_id;
  if (!jobID) return;

  // 简单轮询
  const poll = async () => {
    const j = await api.getJSON(`/api/jobs/${encodeURIComponent(jobID)}`);
    if (j.status === "running") {
      setTimeout(poll, 1500);
      return;
    }
    if (j.status === "failed") {
      alert(`scan all failed: ${j.error || "unknown"}`);
      await loadCases();
      return;
    }
    await loadCases();
    if (j.case_id) await selectCase(j.case_id);
  };
  setTimeout(poll, 800);
}

function initTabs() {
  const tabs = [...document.querySelectorAll(".tab")];
  const panes = [...document.querySelectorAll(".pane")];

  function activate(name) {
    tabs.forEach((t) => t.classList.toggle("tab--active", t.getAttribute("data-tab") === name));
    panes.forEach((p) => p.classList.toggle("hidden", p.getAttribute("data-pane") !== name));
  }

  tabs.forEach((t) => {
    t.addEventListener("click", () => activate(t.getAttribute("data-tab")));
  });
}

function pickCaseFromHash() {
  const h = window.location.hash || "";
  const m = h.match(/case=([^&]+)/);
  if (!m) return "";
  try {
    return decodeURIComponent(m[1]);
  } catch {
    return "";
  }
}

async function main() {
  initTabs();

  $("caseSearch").addEventListener("input", renderCaseList);
  $("btnRefresh").addEventListener("click", async () => {
    await loadCases();
    if (state.activeCaseID) await selectCase(state.activeCaseID);
  });

  $("btnScanAll").addEventListener("click", openModal);
  $("btnCancelScan").addEventListener("click", closeModal);
  $("btnConfirmScan").addEventListener("click", startScanAll);

  $("btnLoadHits").addEventListener("click", loadHits);
  $("btnLoadArtifacts").addEventListener("click", loadArtifacts);
  $("btnLoadPrechecks").addEventListener("click", loadPrechecks);
  $("btnLoadAudits").addEventListener("click", loadAudits);
  $("btnLoadReports").addEventListener("click", loadReports);
  $("btnLoadReportContent").addEventListener("click", loadLatestReportContent);
  $("hitType").addEventListener("change", loadHits);

  await loadCases();

  const fromHash = pickCaseFromHash();
  if (fromHash) {
    const exists = state.cases.find((c) => c.case_id === fromHash);
    if (exists) await selectCase(fromHash);
  }
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e);
  alert(String(e && e.message ? e.message : e));
});

