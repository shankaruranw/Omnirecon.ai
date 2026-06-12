/**
 * OmniRecon AI — Authentication & User Management
 * =================================================
 * Handles all user authentication using browser localStorage.
 * No server required — works in pure static (offline) mode.
 *
 * Data stored:
 *   reconx_auth_user  → current logged-in user session
 *   reconx_users      → all registered user accounts
 *   reconx_prefs      → user preferences (theme, animations)
 */

// ── Types ─────────────────────────────────────────────────────────────────────

/** Represents a logged-in user session */
export type User = {
  email: string;
  name: string;
  role?: "user" | "admin"; // "admin" gets access to Admin Dashboard
  loginAt: number;         // Unix timestamp of login
};

/** User account stored in localStorage */
type StoredUser = {
  email: string;
  name: string;
  password: string; // Plain text (localStorage only — no server)
  role?: string;
};

// ── Storage Keys ──────────────────────────────────────────────────────────────

const KEY       = "reconx_auth_user";  // Current session key
const USERS_KEY = "reconx_users";      // All users key

// ── Internal Helpers ──────────────────────────────────────────────────────────

/**
 * getUsers()
 * ----------
 * Reads all registered users from localStorage.
 * Returns an empty array if storage is empty or corrupted.
 */
function getUsers(): StoredUser[] {
  try {
    return JSON.parse(localStorage.getItem(USERS_KEY) || "[]");
  } catch {
    return [];
  }
}

/**
 * saveUsers(users)
 * ----------------
 * Writes the full users array back to localStorage.
 */
function saveUsers(u: StoredUser[]) {
  localStorage.setItem(USERS_KEY, JSON.stringify(u));
}

// ── Session Management ────────────────────────────────────────────────────────

/**
 * getCurrentUser()
 * ----------------
 * Returns the currently logged-in user from localStorage.
 * Returns null if no user is logged in or the session is invalid.
 */
export function getCurrentUser(): User | null {
  try {
    const u = JSON.parse(localStorage.getItem(KEY) || "null");
    // Validate that the stored object actually has an email field
    return u && u.email ? u : null;
  } catch {
    return null;
  }
}

/**
 * isAuthenticated()
 * -----------------
 * Quick check: is any user currently logged in?
 * Used by App.tsx to decide whether to show Login or Dashboard.
 */
export function isAuthenticated() {
  const u = getCurrentUser();
  return !!u && !!u.email;
}

/**
 * isAdmin()
 * ---------
 * Returns true if the currently logged-in user has the "admin" role.
 * Used by Layout.tsx to show/hide the Admin Dashboard link.
 */
export function isAdmin() {
  const u = getCurrentUser();
  return !!u && (u as any).role === "admin";
}

// ── Registration ──────────────────────────────────────────────────────────────

/**
 * signUp(name, email, password)
 * ------------------------------
 * Registers a new user account in localStorage.
 * Validates email format and minimum password length.
 * Returns { ok: true } on success or { ok: false, error: "..." } on failure.
 */
export function signUp(
  name: string,
  email: string,
  password: string
): { ok: boolean; error?: string } {
  email = email.trim().toLowerCase();

  // Validate email format
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { ok: false, error: "Enter a valid email." };
  }

  // Validate minimum password length
  if (password.length < 6) {
    return { ok: false, error: "Password must be at least 6 characters." };
  }

  const users = getUsers();

  // Check if account already exists
  if (users.some((u) => u.email === email)) {
    return { ok: false, error: "Account already exists." };
  }

  // Save new user to localStorage
  saveUsers([
    ...users,
    {
      email,
      name: name.trim() || email.split("@")[0], // Use email prefix if no name
      password,
      role: "user",
    },
  ]);

  return { ok: true };
}

// ── Login ─────────────────────────────────────────────────────────────────────

/**
 * login(email, password)
 * -----------------------
 * Authenticates a user against the localStorage user store.
 * If the user doesn't exist yet and password is valid (≥6 chars),
 * automatically creates the account (demo convenience).
 * On success, saves the session and dispatches "auth-changed" event.
 */
export function login(
  email: string,
  password: string
): { ok: boolean; error?: string } {
  email = email.trim().toLowerCase();

  // Validate email format
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { ok: false, error: "Enter a valid email." };
  }

  const users = getUsers();
  const user  = users.find((u) => u.email === email);

  if (!user) {
    // Auto-register for demo convenience
    if (password.length < 6) {
      return { ok: false, error: "Password must be at least 6 characters." };
    }
    const name = email.split("@")[0];
    saveUsers([...users, { email, name, password, role: "user" }]);
    setSession({ email, name, role: "user", loginAt: Date.now() });
    return { ok: true };
  }

  // Validate password against stored value
  if (user.password !== password) {
    return { ok: false, error: "Incorrect password." };
  }

  // Save session
  setSession({
    email:   user.email,
    name:    user.name,
    role:    (user.role as any) || "user",
    loginAt: Date.now(),
  });

  return { ok: true };
}

/**
 * setSession(user)
 * ----------------
 * Saves the user session to localStorage and fires
 * the "auth-changed" event so App.tsx re-renders.
 */
function setSession(u: User) {
  localStorage.setItem(KEY, JSON.stringify(u));
  window.dispatchEvent(new Event("auth-changed"));
}

/**
 * logout()
 * --------
 * Clears the current session from localStorage.
 * Fires "auth-changed" so App.tsx redirects to Login page.
 */
export function logout() {
  localStorage.removeItem(KEY);
  window.dispatchEvent(new Event("auth-changed"));
}

// ── Profile Management ────────────────────────────────────────────────────────

/**
 * updateProfile(name)
 * --------------------
 * Updates the display name for the currently logged-in user.
 * Saves to both the users list and the active session.
 */
export function updateProfile(name: string): { ok: boolean; error?: string } {
  const current = getCurrentUser();
  if (!current) return { ok: false, error: "Not signed in." };

  name = name.trim();
  if (!name) return { ok: false, error: "Name cannot be empty." };

  // Update in users list
  saveUsers(
    getUsers().map((u) => (u.email === current.email ? { ...u, name } : u))
  );

  // Update active session
  setSession({ ...current, name });

  return { ok: true };
}

/**
 * changePassword(oldPw, newPw)
 * ----------------------------
 * Changes password for the currently logged-in user.
 * Validates the current password before allowing the change.
 */
export function changePassword(
  oldPw: string,
  newPw: string
): { ok: boolean; error?: string } {
  const current = getCurrentUser();
  if (!current) return { ok: false, error: "Not signed in." };
  if (newPw.length < 6) return { ok: false, error: "New password must be at least 6 characters." };

  const users = getUsers();
  const user  = users.find((u) => u.email === current.email);

  if (!user)              return { ok: false, error: "Account not found." };
  if (user.password !== oldPw) return { ok: false, error: "Current password is incorrect." };

  // Save updated password
  saveUsers(
    users.map((u) =>
      u.email === current.email ? { ...u, password: newPw } : u
    )
  );

  return { ok: true };
}

// ── Preferences ───────────────────────────────────────────────────────────────

/** User preference shape */
export type Prefs = {
  accent: string;     // Accent color preference
  compact: boolean;   // Compact UI density toggle
  animations: boolean; // Enable/disable CSS animations
};

const PREFS_KEY = "reconx_prefs";

// Default preference values
const DEFAULT_PREFS: Prefs = {
  accent:     "teal",
  compact:    false,
  animations: true,
};

/**
 * getPrefs()
 * ----------
 * Reads user preferences from localStorage.
 * Merges with defaults so missing keys always have a value.
 */
export function getPrefs(): Prefs {
  try {
    return {
      ...DEFAULT_PREFS,
      ...JSON.parse(localStorage.getItem(PREFS_KEY) || "{}"),
    };
  } catch {
    return DEFAULT_PREFS;
  }
}

/**
 * setPrefs(prefs)
 * ---------------
 * Saves updated preferences to localStorage.
 * Dispatches "prefs-changed" event for any listeners.
 * Returns the merged preferences object.
 */
export function setPrefs(prefs: Partial<Prefs>) {
  const merged = { ...getPrefs(), ...prefs };
  localStorage.setItem(PREFS_KEY, JSON.stringify(merged));
  window.dispatchEvent(new Event("prefs-changed"));
  return merged;
}
