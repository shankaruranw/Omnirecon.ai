/**
 * OmniRecon AI — Root Application Component
 * ===========================================
 * This is the entry point of the React application.
 *
 * Responsibilities:
 *   1. Checks if the user is authenticated (logged in)
 *   2. Shows Login page if NOT authenticated
 *   3. Shows the full app with routing if authenticated
 *   4. Wraps everything in the ToastProvider for notifications
 *
 * Authentication:
 *   - Uses localStorage (no server needed)
 *   - Listens for "auth-changed" events from auth.ts
 *   - Re-checks auth state whenever the event fires (login/logout)
 *
 * Routing (HashRouter):
 *   - Uses hash-based URLs (#/module/viewdns/dns-lookup)
 *   - Works on any static host without server-side routing
 */

import { useEffect, useState } from "react";
import { HashRouter, Routes, Route } from "react-router-dom";
import { isAuthenticated } from "./lib/auth";
import { ToastProvider } from "./lib/toast";
import Layout   from "./components/Layout";
import Login    from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import ModulePage from "./pages/ModulePage";
import Search   from "./pages/Search";
import Settings from "./pages/Settings";
import About    from "./pages/About";
import Reports  from "./pages/Reports";

export default function App() {
  // Track whether the user is currently logged in
  const [authed, setAuthed] = useState(isAuthenticated());

  useEffect(() => {
    /**
     * Listen for authentication state changes.
     * The "auth-changed" event is dispatched by auth.ts
     * whenever a user logs in or logs out.
     */
    const update = () => setAuthed(isAuthenticated());
    window.addEventListener("auth-changed", update);

    // Cleanup listener when component unmounts
    return () => window.removeEventListener("auth-changed", update);
  }, []);

  return (
    /**
     * ToastProvider wraps the entire app so any component
     * can trigger toast notifications using useToast().
     */
    <ToastProvider>
      {!authed ? (
        /* ── Not logged in → Show Login Page ── */
        <Login onSuccess={() => setAuthed(true)} />
      ) : (
        /* ── Logged in → Show Full Application ── */
        <HashRouter>
          <Layout>
            <Routes>
              {/* Dashboard — main home page */}
              <Route path="/"                              element={<Dashboard />} />

              {/* Search — searches tools and opens web search */}
              <Route path="/search"                        element={<Search />} />

              {/* Settings — profile, password, preferences */}
              <Route path="/settings"                      element={<Settings />} />

              {/* About — FAQ and tech stack info */}
              <Route path="/about"                         element={<About />} />

              {/* Reports — scan history, report generation, export */}
              <Route path="/module/reports"                element={<Reports />} />

              {/* Module page — auto-selects first tool */}
              <Route path="/module/:moduleSlug"            element={<ModulePage />} />

              {/* Module + specific tool page */}
              <Route path="/module/:moduleSlug/:toolSlug"  element={<ModulePage />} />

              {/* Catch-all — redirect to Dashboard */}
              <Route path="*"                              element={<Dashboard />} />
            </Routes>
          </Layout>
        </HashRouter>
      )}
    </ToastProvider>
  );
}
