// Vanilla JavaScript for Secure IoT Architecture Dashboard

let globalState = {
  devices: [],
  resources: [],
  revoked_devices: [],
  audit_logs: []
};

// --- DOM Initializer ---
document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initForms();
  initAttackButtons();
  initEvaluationButton();
  initRefresh();

  // Load initial state
  fetchState();
  // Poll state every 4 seconds to keep dashboard live
  setInterval(fetchState, 4000);
});

// --- Tab Navigation ---
function initTabs() {
  const tabs = document.querySelectorAll(".tab-btn");
  tabs.forEach(btn => {
    btn.addEventListener("click", () => {
      tabs.forEach(t => t.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      const targetContent = document.getElementById(targetId);
      if (targetContent) targetContent.classList.add("active");
    });
  });
}

function initRefresh() {
  document.getElementById("btn-refresh").addEventListener("click", fetchState);
  document.getElementById("btn-clear-logs").addEventListener("click", () => {
    document.getElementById("audit-log-box").innerHTML = "<div class='text-muted'>Log cleared from display.</div>";
  });
}

// --- Fetch and Render System State ---
async function fetchState() {
  try {
    const res = await fetch("/api/state");
    if (!res.ok) return;
    const data = await res.json();
    globalState = data;

    renderDevices(data.devices);
    renderSelectDropdowns(data.devices, data.resources);
    renderRevocationList(data.revoked_devices);
    renderAuditLogs(data.audit_logs);
  } catch (err) {
    console.error("Error fetching state:", err);
  }
}

// --- Render Devices Table ---
function renderDevices(devices) {
  const tbody = document.getElementById("devices-tbody");
  document.getElementById("device-count").textContent = `${devices.length} devices`;
  tbody.innerHTML = "";

  devices.forEach(dev => {
    const tr = document.createElement("tr");

    let statusBadge = "";
    if (dev.is_revoked) {
      statusBadge = '<span class="badge badge-danger">Revoked</span>';
    } else if (!dev.is_registered) {
      statusBadge = '<span class="badge badge-warning">Unregistered</span>';
    } else if (dev.has_valid_token) {
      statusBadge = '<span class="badge badge-success">Authenticated</span>';
    } else {
      statusBadge = '<span class="badge badge-neutral">Registered</span>';
    }

    tr.innerHTML = `
      <td><strong>${escapeHtml(dev.device_id)}</strong></td>
      <td><code>${escapeHtml(dev.role)}</code></td>
      <td>${escapeHtml(dev.network_zone)}</td>
      <td>v${dev.firmware_version}</td>
      <td>${dev.trust_score}/100</td>
      <td>${statusBadge}</td>
      <td>
        ${!dev.is_revoked ? `<button class="btn btn-danger btn-sm" onclick="quickRevoke('${dev.device_id}')">Revoke</button>` : `<span class="text-muted">Blocked</span>`}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

// --- Populate Dropdown Selects ---
function renderSelectDropdowns(devices, resources) {
  const authSelect = document.getElementById("auth-select-device");
  const accessDevSelect = document.getElementById("access-select-device");
  const revokeSelect = document.getElementById("revoke-select-device");
  const accessResSelect = document.getElementById("access-select-resource");

  const prevAuth = authSelect.value;
  const prevAccessDev = accessDevSelect.value;
  const prevRevoke = revokeSelect.value;
  const prevRes = accessResSelect.value;

  authSelect.innerHTML = "";
  accessDevSelect.innerHTML = "";
  revokeSelect.innerHTML = "";

  devices.forEach(dev => {
    const label = `${dev.device_id} (${dev.role}${dev.is_revoked ? " - REVOKED" : ""})`;
    const opt1 = new Option(label, dev.device_id);
    const opt2 = new Option(label, dev.device_id);
    const opt3 = new Option(label, dev.device_id);

    authSelect.add(opt1);
    accessDevSelect.add(opt2);
    if (!dev.is_revoked) revokeSelect.add(opt3);
  });

  if (prevAuth) authSelect.value = prevAuth;
  if (prevAccessDev) accessDevSelect.value = prevAccessDev;
  if (prevRevoke) revokeSelect.value = prevRevoke;

  // Resources
  accessResSelect.innerHTML = "";
  resources.forEach(r => {
    const opt = new Option(`${r.name} (${r.resource_id})`, r.resource_id);
    accessResSelect.add(opt);
  });
  if (prevRes) accessResSelect.value = prevRes;

  updateResourceInfoBox();
  accessResSelect.onchange = updateResourceInfoBox;
}

function updateResourceInfoBox() {
  const resId = document.getElementById("access-select-resource").value;
  const r = globalState.resources.find(item => item.resource_id === resId);
  const box = document.getElementById("resource-info-box");
  if (!r) {
    box.textContent = "Select a resource to inspect security policies.";
    return;
  }

  box.textContent = 
`Resource ID        : ${r.resource_id}
Name               : ${r.name}
Critical Resource  : ${r.is_critical ? "YES (Strict ABAC enforced)" : "No"}
Allowed Roles      : [${r.allowed_roles.join(", ")}]
Allowed Actions    : [${r.allowed_actions.join(", ")}]
Allowed Zones      : [${r.allowed_zones.join(", ")}]
Min Firmware Req   : v${r.min_firmware}
Min Trust Score    : ${r.min_trust_score}/100
Current State      : ${JSON.stringify(r.current_state)}`;
}

// --- Render Revocation List ---
function renderRevocationList(revoked) {
  const tbody = document.getElementById("revoked-tbody");
  const countBadge = document.getElementById("revoked-count");
  countBadge.textContent = `${revoked.length} Revoked`;

  if (revoked.length === 0) {
    tbody.innerHTML = `<tr><td colspan="3" class="text-center text-muted">No devices currently revoked.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  revoked.forEach(entry => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><strong>${escapeHtml(entry.device_id)}</strong></td>
      <td>${escapeHtml(entry.reason)}</td>
      <td><span class="text-muted">${escapeHtml(entry.timestamp)}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

// --- Render Audit Logs ---
function renderAuditLogs(logs) {
  const box = document.getElementById("audit-log-box");
  if (logs.length === 0) {
    box.innerHTML = "<div class='text-muted'>Awaiting gateway operations...</div>";
    return;
  }

  box.innerHTML = logs.map(l => `
    <div class="log-row">
      <span class="log-time">[${l.timestamp}]</span>
      <span class="log-cat">&lt;${l.category}&gt;</span>
      <span class="log-status-${l.status}">[${l.status}]</span>
      <span class="log-msg">${escapeHtml(l.message)}</span>
    </div>
  `).join("");
}

// --- Forms Initialization ---
function initForms() {
  // 1. Device Registration Form
  document.getElementById("form-register-device").addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      device_id: document.getElementById("reg-device-id").value,
      role: document.getElementById("reg-role").value,
      firmware_version: parseFloat(document.getElementById("reg-firmware").value),
      network_zone: document.getElementById("reg-zone").value,
      trust_score: parseInt(document.getElementById("reg-trust").value, 10),
      location: document.getElementById("reg-location").value
    };

    const res = await fetch("/api/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (data.success) {
      document.getElementById("reg-device-id").value = "";
      fetchState();
      alert(`Device '${payload.device_id}' registered successfully with cryptographic keys!`);
    } else {
      alert(`Registration failed: ${data.message}`);
    }
  });

  // 2. Authentication Handshake Form
  document.getElementById("form-auth").addEventListener("submit", async (e) => {
    e.preventDefault();
    const devId = document.getElementById("auth-select-device").value;
    const tamperSig = document.getElementById("auth-tamper-sig").checked;
    const tamperNonce = document.getElementById("auth-tamper-nonce").checked;

    const payload = {
      device_id: devId,
      tamper_signature: tamperSig ? "deadbeef_fake_signature_hash_00" : null,
      tamper_nonce: tamperNonce ? "replayed_nonce_12345" : null
    };

    const badge = document.getElementById("auth-badge-status");
    badge.className = "badge badge-warning";
    badge.textContent = "Verifying Handshake...";

    const res = await fetch("/api/auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json();

    const p1 = document.getElementById("auth-phase1");
    const p2 = document.getElementById("auth-phase2");
    const p3 = document.getElementById("auth-phase3");
    const p4 = document.getElementById("auth-phase4");
    const resultBox = document.getElementById("auth-result-box");

    if (data.success) {
      badge.className = "badge badge-success";
      badge.textContent = "AUTHENTICATED";

      p1.textContent = `Device Hello (${data.overhead.phase1_request_bytes} bytes)`;
      p2.textContent = `Random 128-bit Nonce Generated (${data.overhead.phase2_challenge_bytes} bytes)`;
      p3.textContent = `HMAC-SHA256 Signature Verified (${data.overhead.phase3_response_bytes} bytes)`;
      p4.textContent = `Capability Token Issued (${data.overhead.phase4_token_issue_bytes} bytes)`;

      resultBox.textContent = 
`[+] AUTHENTICATION SUCCESSFUL
Issued Token ID : ${data.token_id}
Assigned Role   : ${data.token_role}
Cryptographic Sig: ${data.token_signature}
Total Handshake Payload: ${data.overhead.total_auth_bytes} bytes`;
    } else {
      badge.className = "badge badge-danger";
      badge.textContent = "AUTH BLOCKED";

      p1.textContent = "Hello Sent";
      p2.textContent = "Challenge evaluated";
      p3.textContent = tamperSig ? "SIGNATURE REJECTED" : "Failed";
      p4.textContent = "No Token Issued";

      resultBox.textContent = 
`[-] AUTHENTICATION FAILED / BLOCKED
Reason : ${data.message}
Total Bytes Exchanged: ${data.overhead.total_auth_bytes} bytes`;
    }

    fetchState();
  });

  // 3. Access Request Form
  document.getElementById("form-access-request").addEventListener("submit", async (e) => {
    e.preventDefault();
    const devId = document.getElementById("access-select-device").value;
    const resId = document.getElementById("access-select-resource").value;
    const action = document.getElementById("access-select-action").value;

    const ctxZone = document.getElementById("ctx-zone").value;
    const ctxFw = document.getElementById("ctx-firmware").value;
    const ctxTrust = document.getElementById("ctx-trust").value;
    const tamperToken = document.getElementById("access-tamper-token").checked;

    const contextOverride = {};
    if (ctxZone) contextOverride.network_zone = ctxZone;
    if (ctxFw) contextOverride.firmware_version = parseFloat(ctxFw);
    if (ctxTrust) contextOverride.trust_score = parseInt(ctxTrust, 10);

    const payload = {
      device_id: devId,
      resource_id: resId,
      action: action,
      context_override: Object.keys(contextOverride).length > 0 ? contextOverride : null,
      tamper_token_role: tamperToken ? "gateway_admin" : null,
      params: { temp: 25.5, rpm: 1800, switch_state: "TRIPPED" }
    };

    const res = await fetch("/api/access", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await res.json();

    const decisionBox = document.getElementById("access-decision-result");
    const badge = document.getElementById("access-badge-status");
    const title = document.getElementById("decision-title");
    const reason = document.getElementById("decision-reason");

    if (data.allowed) {
      decisionBox.className = "decision-container allow";
      badge.className = "badge badge-success";
      badge.textContent = "ALLOW";
      title.innerHTML = `&#10004; Access Granted (${data.decision})`;
      reason.textContent = `${data.reason} Updated Resource State: ${JSON.stringify(data.resource_state)}`;
    } else {
      decisionBox.className = "decision-container deny";
      badge.className = "badge badge-danger";
      badge.textContent = "DENIED";
      title.innerHTML = `&#10008; Access Blocked (${data.decision})`;
      reason.textContent = data.reason;
    }

    fetchState();
  });

  // 4. Revocation Form
  document.getElementById("form-revoke").addEventListener("submit", async (e) => {
    e.preventDefault();
    const devId = document.getElementById("revoke-select-device").value;
    const reason = document.getElementById("revoke-reason").value;

    if (!confirm(`Are you sure you want to permanently blacklist device '${devId}'?`)) return;

    const res = await fetch("/api/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ device_id: devId, reason: reason })
    });
    const data = await res.json();
    if (data.success) {
      alert(`Device '${devId}' has been revoked immediately!`);
      fetchState();
    }
  });
}

// Quick revoke from table button
window.quickRevoke = async function(devId) {
  const reason = prompt(`Reason for revoking '${devId}':`, "Host compromised");
  if (!reason) return;

  await fetch("/api/revoke", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ device_id: devId, reason: reason })
  });
  fetchState();
};

// --- Attack Simulation Buttons ---
function initAttackButtons() {
  const btns = document.querySelectorAll("[data-attack]");
  btns.forEach(btn => {
    btn.addEventListener("click", async () => {
      const attackType = btn.getAttribute("data-attack");
      const res = await fetch("/api/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ attack_type: attackType })
      });
      const data = await res.json();
      if (!data.success) return;

      const r = data.result;
      const card = document.getElementById("attack-output-card");
      const title = document.getElementById("attack-title");
      const badge = document.getElementById("attack-badge");
      const details = document.getElementById("attack-details");

      card.style.display = "block";
      title.textContent = r.name;
      badge.className = r.blocked ? "badge badge-success" : "badge badge-danger";
      badge.textContent = r.blocked ? "DEFENSE SUCCESS (100% Blocked)" : "BREACH";

      details.textContent = 
`Threat Scenario: ${r.name}
Description    : ${r.description}
Gateway Defense: ${r.outcome}
Security Status: ${r.blocked ? "BLOCKED AT PEP GATEWAY (Zero Unauthorized Access)" : "BREACH"}`;

      fetchState();
    });
  });
}

// --- Benchmark Evaluator ---
function initEvaluationButton() {
  const btn = document.getElementById("btn-run-evaluation");
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    const loading = document.getElementById("eval-loading");
    const container = document.getElementById("eval-results-container");

    loading.style.display = "block";
    container.style.display = "none";

    try {
      const res = await fetch("/api/evaluate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ iterations: 500 })
      });
      const json = await res.json();
      if (!json.success) return;

      const d = json.data;

      // 1. Auth Latency
      document.getElementById("metric-mean-time").textContent = `${d.authentication_time.mean_ms.toFixed(4)} ms`;
      document.getElementById("metric-median-time").textContent = `${d.authentication_time.median_ms.toFixed(4)} ms`;
      document.getElementById("metric-p95-time").textContent = `${d.authentication_time.p95_ms.toFixed(4)} ms`;
      document.getElementById("metric-throughput").textContent = `${d.authentication_time.throughput_handshakes_per_sec.toFixed(0)} /sec`;

      // 2. Prevention Rate
      document.getElementById("metric-prevention-badge").textContent = `${d.unauthorized_access_prevention.prevention_rate_pct.toFixed(2)}% Blocked (0 Breaches)`;
      const pbody = document.getElementById("prevention-tbody");
      pbody.innerHTML = "";

      for (const [vecName, v] of Object.entries(d.unauthorized_access_prevention.vector_details)) {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${escapeHtml(vecName)}</td>
          <td>${v.trials}</td>
          <td><strong class="text-success">${v.blocked}</strong></td>
          <td>${v.allowed}</td>
          <td><span class="badge badge-success">${v.prevention_rate_pct.toFixed(1)}%</span></td>
        `;
        pbody.appendChild(tr);
      }

      // 3. Overhead
      const hs = d.communication_overhead.authentication_handshake;
      const acc = d.communication_overhead.resource_access;
      const base = d.communication_overhead.baseline_comparison;

      document.getElementById("oh-p1").textContent = hs.phase1_request_bytes;
      document.getElementById("oh-p2").textContent = hs.phase2_challenge_bytes;
      document.getElementById("oh-p3").textContent = hs.phase3_response_bytes;
      document.getElementById("oh-p4").textContent = hs.phase4_token_issue_bytes;
      document.getElementById("oh-hs-total").textContent = hs.total_handshake_bytes;

      document.getElementById("oh-acc-req").textContent = acc.request_bytes;
      document.getElementById("oh-acc-res").textContent = acc.response_bytes;
      document.getElementById("oh-base").textContent = base.insecure_baseline_bytes;
      document.getElementById("oh-premium").textContent = `+${base.additional_security_overhead_bytes}`;
      document.getElementById("oh-multiplier").textContent = base.overhead_multiplier.toFixed(2);

      loading.style.display = "none";
      container.style.display = "block";
    } catch (e) {
      alert("Error running evaluation benchmark: " + e.message);
      loading.style.display = "none";
    } finally {
      btn.disabled = false;
      fetchState();
    }
  });
}

function escapeHtml(str) {
  if (typeof str !== "string") return str;
  return str.replace(/[&<>"']/g, m => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[m]);
}
