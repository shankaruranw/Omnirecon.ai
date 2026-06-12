/**
 * OmniRecon AI — Theme Manager
 * ==============================
 * Handles dark / light mode switching.
 * Stores preference in localStorage.
 * Applies 'light' class to <html> for light mode.
 */

const THEME_KEY = "omnirecon_theme";

export type Theme = "dark" | "light";

/** Read saved theme from localStorage (defaults to dark) */
export function getTheme(): Theme {
  try {
    const saved = localStorage.getItem(THEME_KEY) as Theme | null;
    return saved === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

/** Save theme and apply it to the document */
export function setTheme(theme: Theme) {
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch {}
  applyTheme(theme);
  window.dispatchEvent(new CustomEvent("theme-changed", { detail: { theme } }));
}

/** Toggle between dark and light */
export function toggleTheme(): Theme {
  const next = getTheme() === "dark" ? "light" : "dark";
  setTheme(next);
  return next;
}

/** Apply theme class to <html> element */
export function applyTheme(theme: Theme) {
  const root = document.documentElement;
  if (theme === "light") {
    root.classList.add("light");
    root.classList.remove("dark");
  } else {
    root.classList.remove("light");
    root.classList.add("dark");
  }
}

/** Called once on app load to restore saved theme */
export function initTheme() {
  applyTheme(getTheme());
}
