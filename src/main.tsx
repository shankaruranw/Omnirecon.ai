/**
 * OmniRecon AI — Application Entry Point
 * ========================================
 * This is the very first file that runs when the browser loads the app.
 *
 * It mounts the React application into the <div id="root"> element
 * defined in index.html.
 *
 * StrictMode is enabled to catch common React issues during development
 * (renders components twice in dev mode to detect side effects).
 */

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";          // Global styles with dark/light mode variables
import App from "./App.tsx";   // Root application component
import { initTheme } from "./lib/theme"; // Theme initializer

// Restore saved theme BEFORE rendering to avoid flash of wrong theme
initTheme();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>
);
