const API_BASE = "http://127.0.0.1:5000";

// Debug helper
function debugLog(message, data) {
  console.log(`[DEBUG] ${message}`, data || '');
}

window.onload = async function () {
  if (window.location.pathname.endsWith("dashboard.html")) {
    const params = new URLSearchParams(window.location.search);
    
    // Store token and user if present in URL
    if (params.has("token")) {
      const token = params.get("token");
      debugLog("Storing token from URL", token.substring(0, 20) + "...");
      window.localStorage.setItem("access_token", token);
    }
    if (params.has("user")) {
      const userParam = params.get("user");
      debugLog("Storing user from URL", userParam);
      window.localStorage.setItem("user", userParam);
    }
    
    // Check what's in localStorage
    const storedToken = window.localStorage.getItem("access_token");
    const storedUser = window.localStorage.getItem("user");
    debugLog("Token in localStorage", storedToken ? storedToken.substring(0, 20) + "..." : "NONE");
    debugLog("User in localStorage", storedUser ? storedUser.substring(0, 50) + "..." : "NONE");
    
    // Get user from localStorage
    let user = null;
    try {
      const userStr = window.localStorage.getItem("user");
      if (userStr) {
        user = JSON.parse(decodeURIComponent(userStr));
        debugLog("Parsed user object", user);
      }
    } catch (e) {
      console.error("Error parsing user data:", e);
      window.localStorage.clear();
      window.location.href = "index.html";
      return;
    }
    
    if (!user) {
      console.log("No user found, redirecting to login");
      window.location.href = "index.html";
      return;
    }
    
    // Display user info
    document.getElementById("username").textContent = user.name || user.email || "";
    document.getElementById("userpic").src = user.picture || "";
    
    // Clean URL (remove token/user params for security)
    if (params.has("token") || params.has("user")) {
      window.history.replaceState({}, document.title, "dashboard.html");
    }

    // Load subjects
    await loadSubjects();

    // Subject form submission
    document.getElementById('subjectForm').onsubmit = async (e) => {
      e.preventDefault();
      const name = document.getElementById('subjectName').value;
      const color = document.getElementById('subjectColor').value;
      
      debugLog("Submitting subject", { name, color });
      
      const token = window.localStorage.getItem("access_token");
      if (!token) {
        alert("No access token found. Please login again.");
        window.location.href = "index.html";
        return;
      }
      
      debugLog("Using token for request", token.substring(0, 20) + "...");
      
      try {
        const response = await fetch(`${API_BASE}/api/subjects`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
          },
          body: JSON.stringify({ name, color }),
        });
        
        debugLog("Response status", response.status);
        debugLog("Response headers", Object.fromEntries(response.headers.entries()));
        
        if (response.status === 401) {
          const errorText = await response.text();
          debugLog("401 error response", errorText);
          alert("Session expired! Please login again.");
          window.localStorage.clear();
          window.location.href = "index.html";
          return;
        }
        
        if (!response.ok) {
          const errorData = await response.json().catch(() => ({ error: "Unknown error" }));
          debugLog("Error response", errorData);
          alert(`Add subject failed: ${errorData.error || response.statusText}`);
          return;
        }
        
        const result = await response.json();
        debugLog("Success response", result);
        
        await loadSubjects();
        document.getElementById('subjectForm').reset();
        alert("Subject added successfully!");
      } catch (error) {
        console.error("Error adding subject:", error);
        debugLog("Fetch error", error);
        alert("Failed to add subject. Please check your connection.");
      }
    };

    async function loadSubjects() {
      try {
        const token = window.localStorage.getItem("access_token");
        if (!token) {
          alert("No access token found. Please login again.");
          window.location.href = "index.html";
          return;
        }
        
        debugLog("Loading subjects with token", token.substring(0, 20) + "...");
        
        const res = await fetch(`${API_BASE}/api/subjects`, {
          method: 'GET',
          headers: { 
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
        });
        
        debugLog("Load subjects response status", res.status);
        
        if (res.status === 401) {
          const errorText = await res.text();
          debugLog("401 error on load", errorText);
          alert("Session expired! Please login again.");
          window.localStorage.clear();
          window.location.href = "index.html";
          return;
        }
        
        if (!res.ok) {
          console.error("Failed to fetch subjects:", res.status);
          const errorText = await res.text();
          debugLog("Error loading subjects", errorText);
          alert("Failed to fetch subjects.");
          return;
        }
        
        const data = await res.json();
        debugLog("Loaded subjects data", data);
        const subjects = data.subjects || [];
        const list = document.getElementById("subjectsList");
        list.innerHTML = "";
        
        if (subjects.length === 0) {
          list.innerHTML = "<li style='color: #999; font-style: italic;'>No subjects yet. Add one above!</li>";
          return;
        }
        
        subjects.forEach(sub => {
          const li = document.createElement("li");
          li.style.color = sub.color || "#CCCCCC";
          li.innerText = sub.name;
          // Add topic and review logic as you expand
          list.appendChild(li);
        });
      } catch (error) {
        console.error("Error loading subjects:", error);
        debugLog("Load subjects error", error);
        alert("Failed to load subjects. Please check your connection.");
      }
    }
  }
};

function googleAuth(type) {
  debugLog("Starting Google auth", type);
  window.location.href = `${API_BASE}/auth/google/${type}`;
}

function logout() {
  debugLog("Logging out");
  window.localStorage.clear();
  window.location.href = "index.html";
}