const API_ORIGIN = "https://app.bdfz.net";

const form = document.getElementById("register-form");
const statusEl = document.getElementById("status");
const slugInput = document.getElementById("slug");
const nameInput = document.getElementById("displayName");

let timer = null;

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.style.color = isError ? "#ab3720" : "#665f55";
}

function normalizeSlug(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "")
    .replace(/--+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 30);
}

async function checkSlug() {
  const slug = normalizeSlug(slugInput.value);
  slugInput.value = slug;

  if (!slug) {
    setStatus("");
    return;
  }

  try {
    const response = await fetch(
      `${API_ORIGIN}/api/check-slug?slug=${encodeURIComponent(slug)}`
    );
    const payload = await response.json();

    if (payload.available) {
      setStatus(`可使用：${slug}.bdfz.net`);
      return;
    }

    setStatus(`不可使用（${payload.reason || "unknown"}）`, true);
  } catch {
    setStatus("暫時無法檢查 slug，請稍後再試", true);
  }
}

slugInput.addEventListener("input", () => {
  slugInput.value = normalizeSlug(slugInput.value);
  if (!nameInput.value.trim()) {
    nameInput.value = slugInput.value;
  }

  clearTimeout(timer);
  timer = setTimeout(checkSlug, 240);
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const payload = {
    slug: normalizeSlug(slugInput.value),
    displayName: nameInput.value.trim(),
    adminPassword: document.getElementById("adminPassword").value,
    inviteCode: document.getElementById("inviteCode").value.trim(),
    description: document.getElementById("description").value.trim(),
  };

  if (!payload.slug) {
    setStatus("請輸入有效的子域名", true);
    return;
  }

  setStatus("正在建立站點...");

  try {
    const response = await fetch(`${API_ORIGIN}/api/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const result = await response.json();
    if (!response.ok) {
      setStatus(result.error || "建立失敗", true);
      return;
    }

    setStatus("建立成功，跳轉中...");
    window.location.href = `${result.siteUrl}/admin`;
  } catch {
    setStatus("建立失敗，請稍後再試", true);
  }
});
