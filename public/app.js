const state = {
  incidents: [],
  selectedId: null,
  status: "",
  query: "",
  detail: null,
  busy: false,
  aiConfigured: true,
};

const els = {
  health: document.querySelector("#health"),
  healthLabel: document.querySelector("#health-label"),
  demoPill: document.querySelector("#demo-pill"),
  count: document.querySelector("#queue-count"),
  queue: document.querySelector("#queue"),
  queueEmpty: document.querySelector("#queue-empty"),
  queueError: document.querySelector("#queue-error"),
  search: document.querySelector("#search"),
  segments: [...document.querySelectorAll(".segment")],
  detailEmpty: document.querySelector("#detail-empty"),
  detailContent: document.querySelector("#detail-content"),
  tokenDialog: document.querySelector("#token-dialog"),
  tokenForm: document.querySelector("#token-form"),
  tokenInput: document.querySelector("#token-input"),
};

const VERDICT_LABEL = {
  true_positive: "True positive",
  benign_positive: "Benign positive",
  false_positive: "False positive",
  undetermined: "Undetermined",
};

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function verdictClass(value) {
  if (value === "true_positive") return "tp";
  if (value === "false_positive") return "fp";
  if (value === "benign_positive") return "benign";
  return "";
}

function statusClass(value) {
  return ["pending", "approved", "edited", "rejected"].includes(value) ? value : "";
}

function fmtPercent(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) return "n/a";
  return `${(Number(value) * 100).toFixed(1)}%`;
}

function fmtDate(value) {
  if (!value) return "n/a";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function getToken() {
  return sessionStorage.getItem("triage-review-token") || "";
}

function setToken(token) {
  if (token) sessionStorage.setItem("triage-review-token", token);
  else sessionStorage.removeItem("triage-review-token");
}

async function request(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  const token = getToken();
  if (token) headers["X-Review-Token"] = token;
  const response = await fetch(path, { ...options, headers });
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (response.status === 401) {
    openTokenDialog();
    throw new Error(payload?.detail || "Review token required");
  }
  if (!response.ok) {
    throw new Error(payload?.detail || `Request failed (${response.status})`);
  }
  return payload;
}

function showError(message) {
  els.queueError.textContent = message;
  els.queueError.hidden = false;
}

function clearError() {
  els.queueError.hidden = true;
  els.queueError.textContent = "";
}

async function checkHealth() {
  try {
    const health = await request("/health");
    els.health.classList.remove("is-bad");
    els.health.classList.add("is-ok");
    els.healthLabel.textContent = `${health.database} ready`;
    els.demoPill.textContent = health.demo_mode ? "Demo data" : "Live review";
    state.aiConfigured = Boolean(health.ai_configured);
  } catch {
    els.health.classList.remove("is-ok");
    els.health.classList.add("is-bad");
    els.healthLabel.textContent = "API unavailable";
  }
}

function filteredIncidents() {
  const query = state.query.trim().toLowerCase();
  if (!query) return state.incidents;
  return state.incidents.filter((item) =>
    [item.incident_id, item.title, item.verdict, item.route, item.status]
      .join(" ")
      .toLowerCase()
      .includes(query),
  );
}

function renderQueue() {
  const items = filteredIncidents();
  els.count.textContent = String(items.length);
  els.queue.innerHTML = "";
  els.queueEmpty.hidden = items.length > 0;

  for (const incident of items) {
    const li = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.className = `queue-item${incident.incident_id === state.selectedId ? " is-selected" : ""}`;
    button.setAttribute("aria-pressed", String(incident.incident_id === state.selectedId));
    button.innerHTML = `
      <span>
        <span class="queue-item-id">${escapeHtml(incident.incident_id)}</span>
        <span class="queue-item-title">${escapeHtml(incident.title)}</span>
        <span class="queue-item-meta">
          <span class="badge ${verdictClass(incident.verdict)}">${escapeHtml(VERDICT_LABEL[incident.verdict] || incident.verdict)}</span>
          <span class="badge ${statusClass(incident.status)}">${escapeHtml(incident.status)}</span>
          ${incident.needs_human ? '<span class="badge high">needs human</span>' : ""}
        </span>
      </span>
      <span class="queue-item-confidence">${fmtPercent(incident.confidence)}</span>
    `;
    button.addEventListener("click", () => selectIncident(incident.incident_id));
    li.append(button);
    els.queue.append(li);
  }
}

async function loadIncidents({ keepSelection = true } = {}) {
  clearError();
  const params = new URLSearchParams({ limit: "200" });
  if (state.status) params.set("status", state.status);
  try {
    const payload = await request(`/api/incidents?${params}`);
    state.incidents = payload.items;
    if (!keepSelection || !state.incidents.some((item) => item.incident_id === state.selectedId)) {
      state.selectedId = null;
      state.detail = null;
      renderDetailEmpty();
    }
    renderQueue();
  } catch (error) {
    showError(error.message);
    state.incidents = [];
    renderQueue();
  }
}

function renderDetailEmpty() {
  els.detailEmpty.hidden = false;
  els.detailContent.hidden = true;
  els.detailContent.innerHTML = "";
}

function explanationBody(exp, cached) {
  if (!exp) {
    if (!state.aiConfigured) {
      return '<p class="ai-hint">AI explanations are not configured on this deployment.</p>';
    }
    return '<p class="ai-hint">Ask a language model to explain this decision and cite the evidence below. The model cannot change the verdict, close the incident, or trigger remediation.</p>';
  }
  const cited = Array.isArray(exp.evidence_ids) ? exp.evidence_ids : [];
  const tokens = (Number(exp.prompt_tokens) || 0) + (Number(exp.completion_tokens) || 0);
  return `
    <p class="ai-text">${escapeHtml(exp.explanation)}</p>
    <p class="ai-next"><span class="meta-label">Suggested check</span>${escapeHtml(exp.next_step)}</p>
    <div class="ai-meta">
      <span class="badge ai-uncertainty ${escapeHtml(exp.uncertainty)}">${escapeHtml(exp.uncertainty)} uncertainty</span>
      ${cited.map((id) => `<span class="badge">${escapeHtml(id)}</span>`).join("")}
    </div>
    <p class="ai-foot">${escapeHtml(exp.model)} · ${escapeHtml(exp.prompt_version)}${cached ? " · cached" : ""} · ${tokens} tokens</p>
  `;
}

async function runExplanation(button) {
  if (!state.selectedId || !state.detail) return;
  const body = document.querySelector("#ai-body");
  const status = document.querySelector("#ai-status");
  if (!body || !status) return;
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "Asking Groq…";
  status.textContent = "";
  status.className = "ai-status";
  body.innerHTML = '<p class="ai-hint">Reading the decision and evidence…</p>';
  try {
    const payload = await request(
      `/api/incidents/${encodeURIComponent(state.selectedId)}/explain`,
      { method: "POST" },
    );
    body.innerHTML = explanationBody(payload.explanation, payload.cached);
    button.textContent = "Regenerate";
    status.textContent = payload.cached
      ? "Served from cache. No new model call."
      : "Generated by a language model. Review before acting.";
    status.className = "ai-status is-ok";
  } catch (error) {
    body.innerHTML = explanationBody(state.detail.explanation, true);
    status.textContent = error.message;
    status.className = "ai-status is-bad";
  } finally {
    button.disabled = false;
    if (button.textContent === "Asking Groq…") button.textContent = original;
  }
}

function renderDetail(payload) {
  const { incident, reviews, audit } = payload;
  const explanation = payload.explanation || null;
  state.detail = payload;
  els.detailEmpty.hidden = true;
  els.detailContent.hidden = false;

  const evidence = Array.isArray(incident.evidence) ? incident.evidence : [];
  const remediation = Array.isArray(incident.remediation) ? incident.remediation : [];
  const latestReview = reviews.length ? reviews[reviews.length - 1] : null;

  els.detailContent.innerHTML = `
    <div class="detail-head">
      <div>
        <p class="eyebrow">${escapeHtml(incident.case_id)} / ${escapeHtml(incident.incident_id)}</p>
        <h2>${escapeHtml(incident.title)}</h2>
        <p class="detail-sub">${escapeHtml(incident.route)} route · ${escapeHtml(incident.status)} · updated ${fmtDate(incident.updated_at)}</p>
      </div>
      <div class="detail-verdict">
        <span class="confidence">${fmtPercent(incident.confidence)}</span>
        <span class="confidence-label">confidence</span>
        <span class="badge ${verdictClass(incident.verdict)}">${escapeHtml(VERDICT_LABEL[incident.verdict] || incident.verdict)}</span>
      </div>
    </div>

    <p class="summary">${escapeHtml(incident.summary)}</p>

    <div class="meta-grid">
      <div class="meta-cell"><span class="meta-label">Priority</span><span class="meta-value">${escapeHtml(incident.priority)}</span></div>
      <div class="meta-cell"><span class="meta-label">Human review</span><span class="meta-value">${incident.needs_human ? "Required" : "Not required"}</span></div>
      <div class="meta-cell"><span class="meta-label">Classifier</span><span class="meta-value">${escapeHtml(incident.case_id ? "calibrated" : "n/a")}</span></div>
      <div class="meta-cell"><span class="meta-label">Demo label</span><span class="meta-value">${escapeHtml(VERDICT_LABEL[incident.expected_label] || incident.expected_label || "n/a")}</span></div>
    </div>

    <section class="section" aria-labelledby="evidence-title">
      <div class="section-head"><h3 id="evidence-title">Evidence</h3><span class="section-note">${evidence.length} citation${evidence.length === 1 ? "" : "s"}</span></div>
      <ul class="evidence-list">
        ${evidence.length ? evidence.map((item) => `
          <li class="evidence-item">
            <div class="evidence-top">
              <span class="evidence-id">${escapeHtml(item.evidence_id)}</span>
              <span class="badge">${escapeHtml(item.source)}</span>
            </div>
            <p class="evidence-quote">${escapeHtml(item.quote)}</p>
          </li>
        `).join("") : '<li class="evidence-item evidence-quote">No evidence citations.</li>'}
      </ul>
    </section>

    <section class="section" aria-labelledby="remediation-title">
      <div class="section-head"><h3 id="remediation-title">Remediation</h3><span class="section-note">${remediation.length} action${remediation.length === 1 ? "" : "s"}</span></div>
      <ul class="remediation-list">
        ${remediation.length ? remediation.map((item) => `
          <li class="remediation-item">
            <div class="remediation-top">
              <span class="remediation-target">${escapeHtml(item.target)}</span>
              <span class="badge">${escapeHtml(item.action)}</span>
            </div>
            <p class="remediation-rationale">${escapeHtml(item.rationale)}</p>
          </li>
        `).join("") : '<li class="remediation-item remediation-rationale">No remediation proposed.</li>'}
      </ul>
    </section>

    <section class="section ai-box" aria-labelledby="ai-title">
      <div class="section-head">
        <h3 id="ai-title">AI explanation</h3>
        <span class="section-note">language model · requires review</span>
      </div>
      <div id="ai-body" class="ai-body">${explanationBody(explanation, true)}</div>
      <div class="actions">
        <button class="button small" type="button" id="ai-run"${state.aiConfigured ? "" : " disabled"}>${explanation ? "Regenerate" : "Explain with AI"}</button>
      </div>
      <p class="ai-status" id="ai-status" role="status" aria-live="polite"></p>
    </section>

    <section class="section review-box" aria-labelledby="review-title">
      <h3 id="review-title">Review decision</h3>
      <p>Reviewer actions are written to the audit log. Escalations and closures remain human decisions.</p>
      <form id="review-form">
        <div class="field-grid">
          <div class="field">
            <label for="reviewer">Reviewer</label>
            <input id="reviewer" name="reviewer" maxlength="80" required value="${escapeHtml(latestReview?.reviewer || "")}" autocomplete="name">
          </div>
          <div class="field">
            <label for="review-note">Note</label>
            <input id="review-note" name="note" maxlength="2000" placeholder="Optional context">
          </div>
          <div class="field">
            <label for="edited-verdict">Change verdict</label>
            <select id="edited-verdict" name="edited_verdict">
              <option value="">No change</option>
              ${Object.entries(VERDICT_LABEL).map(([value, label]) => `<option value="${value}">${escapeHtml(label)}</option>`).join("")}
            </select>
          </div>
          <div class="field">
            <label for="edited-priority">Change priority</label>
            <select id="edited-priority" name="edited_priority">
              <option value="">No change</option>
              ${["critical", "high", "medium", "low"].map((value) => `<option value="${value}">${escapeHtml(value)}</option>`).join("")}
            </select>
          </div>
        </div>
        <div class="actions">
          <button class="button approve" type="button" data-action="approve">Approve decision</button>
          <button class="button" type="button" data-action="edit">Save edit</button>
          <button class="button reject" type="button" data-action="reject">Reject</button>
        </div>
        <p class="form-status" id="form-status" role="status" aria-live="polite"></p>
      </form>
    </section>

    <section class="section" aria-labelledby="timeline-title">
      <div class="section-head"><h3 id="timeline-title">Audit trail</h3><span class="section-note">${audit.length} event${audit.length === 1 ? "" : "s"}</span></div>
      <ul class="timeline">
        ${audit.length ? audit.slice().reverse().map((event) => `
          <li class="timeline-item">
            <div class="timeline-top">
              <span class="timeline-action">${escapeHtml(event.action)}</span>
              <span class="timeline-time">${fmtDate(event.created_at)}</span>
            </div>
            <span class="timeline-detail">${escapeHtml(event.actor)}${event.details?.note ? ` · ${escapeHtml(event.details.note)}` : ""}</span>
          </li>
        `).join("") : '<li class="timeline-item timeline-detail">No review actions yet.</li>'}
      </ul>
    </section>
  `;

  const form = document.querySelector("#review-form");
  form.addEventListener("submit", (event) => event.preventDefault());
  for (const button of form.querySelectorAll("[data-action]")) {
    button.addEventListener("click", () => submitReview(button.dataset.action, button));
  }

  const aiButton = document.querySelector("#ai-run");
  if (aiButton) aiButton.addEventListener("click", () => runExplanation(aiButton));
}

async function selectIncident(incidentId) {
  state.selectedId = incidentId;
  history.replaceState(null, "", `#${encodeURIComponent(incidentId)}`);
  renderQueue();
  els.detailContent.innerHTML = '<div class="skeleton">Loading decision and audit trail…</div>';
  els.detailEmpty.hidden = true;
  els.detailContent.hidden = false;
  try {
    const payload = await request(`/api/incidents/${encodeURIComponent(incidentId)}`);
    renderDetail(payload);
  } catch (error) {
    els.detailContent.innerHTML = `<div class="inline-error" role="alert">${escapeHtml(error.message)}</div>`;
  }
}

async function submitReview(action, button) {
  if (state.busy || !state.detail) return;
  const form = document.querySelector("#review-form");
  const status = document.querySelector("#form-status");
  const reviewer = form.querySelector("#reviewer").value.trim();
  const note = form.querySelector("#review-note").value.trim();
  const editedVerdict = form.querySelector("#edited-verdict").value;
  const editedPriority = form.querySelector("#edited-priority").value;

  if (!reviewer) {
    status.textContent = "Reviewer name is required.";
    status.className = "form-status is-bad";
    form.querySelector("#reviewer").focus();
    return;
  }
  if (action === "edit" && !editedVerdict && !editedPriority) {
    status.textContent = "Choose a verdict or priority change before saving an edit.";
    status.className = "form-status is-bad";
    form.querySelector("#edited-verdict").focus();
    return;
  }

  state.busy = true;
  const buttons = [...form.querySelectorAll("[data-action]")];
  buttons.forEach((item) => { item.disabled = true; });
  button.textContent = "Saving…";
  status.textContent = "Writing review and audit event…";
  status.className = "form-status";

  const body = {
    action,
    reviewer,
    note,
    edited_verdict: action === "edit" ? (editedVerdict || null) : null,
    edited_priority: action === "edit" ? (editedPriority || null) : null,
  };

  try {
    await request(`/api/incidents/${encodeURIComponent(state.selectedId)}/review`, {
      method: "POST",
      headers: { "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify(body),
    });
    await loadIncidents();
    await selectIncident(state.selectedId);
    const refreshed = document.querySelector("#form-status");
    if (refreshed) {
      refreshed.textContent = "Review recorded.";
      refreshed.className = "form-status is-ok";
    }
  } catch (error) {
    status.textContent = error.message;
    status.className = "form-status is-bad";
  } finally {
    state.busy = false;
    buttons.forEach((item) => { item.disabled = false; });
    button.textContent = action === "approve" ? "Approve decision" : action === "edit" ? "Save edit" : "Reject";
  }
}

function openTokenDialog() {
  els.tokenDialog.showModal();
  els.tokenInput.value = getToken();
  els.tokenInput.focus();
}

els.search.addEventListener("input", () => {
  state.query = els.search.value;
  renderQueue();
});

for (const segment of els.segments) {
  segment.addEventListener("click", async () => {
    state.status = segment.dataset.status;
    for (const item of els.segments) item.classList.toggle("is-active", item === segment);
    await loadIncidents({ keepSelection: false });
  });
}

els.tokenForm.addEventListener("submit", (event) => {
  event.preventDefault();
  if (event.submitter?.value === "cancel") {
    els.tokenDialog.close();
    return;
  }
  setToken(els.tokenInput.value.trim());
  els.tokenDialog.close();
  if (state.selectedId) selectIncident(state.selectedId);
  else loadIncidents();
});

els.tokenDialog.addEventListener("close", () => {
  if (els.tokenDialog.returnValue === "cancel") els.tokenInput.value = "";
});

async function init() {
  await checkHealth();
  if (!getToken()) setToken("demo-review-token");
  await loadIncidents();
  const hash = decodeURIComponent(location.hash.replace(/^#/, ""));
  if (hash) await selectIncident(hash);
}

init();
