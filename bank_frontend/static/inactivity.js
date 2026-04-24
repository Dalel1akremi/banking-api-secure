/**
 * API Bank — Déconnexion automatique après inactivité
 * Timeout : 15 minutes. Avertissement : 60 secondes avant.
 */
(function () {
  const INACTIVITY_LIMIT_MS = 15 * 60 * 1000; // 15 min
  const WARNING_BEFORE_MS   = 60 * 1000;       // 60 sec avant
  const LOGOUT_URL = "/logout";

  let warningTimer = null;
  let logoutTimer  = null;
  let countdownInterval = null;

  // ─── Injection de la modale ───────────────────────────────────────────────
  function injectModal() {
    const modal = document.createElement("div");
    modal.id = "inactivity-modal";
    modal.style.cssText = `
      position:fixed; inset:0; z-index:99999;
      background:rgba(0,0,0,0.85); backdrop-filter:blur(8px);
      display:none; align-items:center; justify-content:center;
      font-family:'Inter','Segoe UI',sans-serif;
    `;
    modal.innerHTML = `
      <div style="
        background:#1e293b; border:1px solid rgba(248,113,113,.35);
        border-radius:20px; padding:40px 36px; max-width:420px; width:92%;
        text-align:center; box-shadow:0 25px 60px rgba(0,0,0,.6);
      ">
        <div style="font-size:48px; margin-bottom:14px;">⏳</div>
        <h2 style="color:#f87171; margin:0 0 10px; font-size:20px;">Session sur le point d'expirer</h2>
        <p style="color:#94a3b8; font-size:14px; margin:0 0 22px; line-height:1.6;">
          Vous avez été inactif pendant un moment.<br>
          Vous serez déconnecté dans <strong id="inactivity-countdown" style="color:#f59e0b; font-size:18px;">60</strong> secondes.
        </p>
        <div style="display:flex; gap:12px; justify-content:center;">
          <button id="inactivity-stay-btn" style="
            padding:12px 28px; border-radius:10px; border:none; cursor:pointer;
            background:linear-gradient(135deg,#6366f1,#8b5cf6); color:#fff;
            font-size:14px; font-weight:700; transition:opacity .2s;
          ">Rester connecté</button>
          <a href="${LOGOUT_URL}" style="
            padding:12px 28px; border-radius:10px; border:1px solid rgba(248,113,113,.4);
            color:#f87171; font-size:14px; font-weight:600; text-decoration:none;
            display:inline-flex; align-items:center;
          ">Se déconnecter</a>
        </div>
      </div>
    `;
    document.body.appendChild(modal);

    document.getElementById("inactivity-stay-btn").addEventListener("click", () => {
      hideModal();
      resetTimers();
    });
  }

  function showModal() {
    const modal = document.getElementById("inactivity-modal");
    if (modal) {
      modal.style.display = "flex";
      let secs = Math.round(WARNING_BEFORE_MS / 1000);
      document.getElementById("inactivity-countdown").textContent = secs;
      countdownInterval = setInterval(() => {
        secs--;
        const el = document.getElementById("inactivity-countdown");
        if (el) el.textContent = secs;
        if (secs <= 0) clearInterval(countdownInterval);
      }, 1000);
    }
  }

  function hideModal() {
    const modal = document.getElementById("inactivity-modal");
    if (modal) modal.style.display = "none";
    if (countdownInterval) clearInterval(countdownInterval);
  }

  // ─── Gestion des timers ───────────────────────────────────────────────────
  function resetTimers() {
    clearTimeout(warningTimer);
    clearTimeout(logoutTimer);

    warningTimer = setTimeout(() => {
      showModal();
      logoutTimer = setTimeout(() => {
        window.location.href = LOGOUT_URL;
      }, WARNING_BEFORE_MS);
    }, INACTIVITY_LIMIT_MS - WARNING_BEFORE_MS);
  }

  // ─── Écoute des événements utilisateur ───────────────────────────────────
  const ACTIVITY_EVENTS = ["mousemove", "mousedown", "keydown", "touchstart", "scroll", "click"];
  ACTIVITY_EVENTS.forEach(evt => {
    document.addEventListener(evt, resetTimers, { passive: true });
  });

  // ─── Init ─────────────────────────────────────────────────────────────────
  document.addEventListener("DOMContentLoaded", () => {
    injectModal();
    resetTimers();
  });
})();
