const API_BASE = "http://127.0.0.1:5000";

function googleAuth(type) {
  window.location.href = `${API_BASE}/auth/google/${type}`;
}

window.onload = function() {
  if (window.location.pathname.endsWith("dashboard.html")) {
    // Read user info from URL params after redirect from backend
    const params = new URLSearchParams(window.location.search);
    if (params.has("user")) {
      let user = {};
      try {
        user = JSON.parse(decodeURIComponent(params.get("user")));
      } catch {}
      // Save user for session
      window.localStorage.setItem("user", JSON.stringify(user));
      document.getElementById("username").textContent = user.name || "";
      document.getElementById("displayName").textContent = user.name || "";
      document.getElementById("displayEmail").textContent = user.email || "";
      document.getElementById("displayId").textContent = user.id || "";
      document.getElementById("userpic").src = user.picture || "";
    } else {
      // fallback to localStorage if present
      let user = JSON.parse(window.localStorage.getItem("user") || "null");
      if (!user) window.location.href = "index.html";
      else {
        document.getElementById("username").textContent = user.name || "";
        document.getElementById("displayName").textContent = user.name || "";
        document.getElementById("displayEmail").textContent = user.email || "";
        document.getElementById("displayId").textContent = user.id || "";
        document.getElementById("userpic").src = user.picture || "";
      }
    }
  }
};

function logout() {
  window.localStorage.clear();
  window.location.href = "index.html";
}
