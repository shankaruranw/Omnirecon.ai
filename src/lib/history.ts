/**
 * OmniRecon AI — Scan History & Report Storage
 * ==============================================
 * Manages persistent storage for scan results and generated reports.
 * All data is stored in the browser's localStorage.
 *
 * Storage keys:
 *   osint_scan_history    → array of ScanRecord (max 200)
 *   reconx_report_history → array of ReportRecord (max 100)
 *
 * Every tool calls addHistory() after completing a scan.
 * The Reports page reads getHistory() and getReports().
 */

// ── Types ─────────────────────────────────────────────────────────────────────

/**
 * ScanRecord
 * ----------
 * Represents one completed tool execution.
 * Stored automatically every time a user runs a scan.
 */
export type ScanRecord = {
  id?:      string;   // Auto-generated random ID
  module:   string;   // e.g. "DNS / Domain Intel"
  tool:     string;   // e.g. "Port Scanner"
  target:   string;   // e.g. "example.com" or "8.8.8.8"
  summary:  string;   // Short description of the result
  risk?:    "Low" | "Medium" | "High" | "Critical" | "Info";
  timestamp: number;  // Unix timestamp (ms)
};

/**
 * ReportType
 * ----------
 * The four types of professional reports the system can generate.
 */
export type ReportType = "Executive" | "Technical" | "AI Summary" | "PDF";

/**
 * ReportRecord
 * ------------
 * Represents a generated report saved to history.
 * The full HTML content is stored so reports can be re-opened.
 */
export type ReportRecord = {
  id?:         string;
  title:       string;      // e.g. "Executive Report — All modules"
  type:        ReportType;
  scope:       string;      // Module scope (e.g. "All modules")
  recordCount: number;      // Number of scans included in report
  html:        string;      // Full rendered HTML of the report
  timestamp:   number;
};

// ── Storage Keys ──────────────────────────────────────────────────────────────

const KEY        = "osint_scan_history";
const REPORT_KEY = "reconx_report_history";

// ── Scan History Functions ────────────────────────────────────────────────────

/**
 * getHistory()
 * ------------
 * Returns all saved scan records from localStorage.
 * Sorted newest first (unshifted on save).
 */
export function getHistory(): ScanRecord[] {
  try {
    return JSON.parse(localStorage.getItem(KEY) || "[]");
  } catch {
    return [];
  }
}

/**
 * addHistory(record)
 * ------------------
 * Saves a new scan result to localStorage history.
 * Automatically generates a unique ID and timestamp.
 * Keeps only the latest 200 records to prevent storage overflow.
 * Fires "history-updated" event so the Reports page re-renders.
 *
 * Called by every tool component after a scan completes.
 */
export function addHistory(rec: Omit<ScanRecord, "id" | "timestamp">) {
  const list   = getHistory();
  const record: ScanRecord = {
    ...rec,
    id:        Math.random().toString(36).slice(2, 10), // 8-char random ID
    timestamp: Date.now(),
  };

  // Add to front of array (newest first)
  list.unshift(record);

  // Keep only latest 200 records
  localStorage.setItem(KEY, JSON.stringify(list.slice(0, 200)));

  // Notify any listening components (Reports page, Dashboard)
  window.dispatchEvent(new Event("history-updated"));

  return record;
}

/**
 * clearHistory()
 * --------------
 * Deletes all scan history from localStorage.
 * Called from Settings page "Clear Scans" button.
 */
export function clearHistory() {
  localStorage.removeItem(KEY);
  window.dispatchEvent(new Event("history-updated"));
}

/**
 * removeHistory(id)
 * -----------------
 * Deletes a single scan record by its ID.
 * Called when the user clicks the X button on a scan entry.
 */
export function removeHistory(id: string) {
  localStorage.setItem(
    KEY,
    JSON.stringify(getHistory().filter((r) => r.id !== id))
  );
  window.dispatchEvent(new Event("history-updated"));
}

// ── Report History Functions ──────────────────────────────────────────────────

/**
 * getReports()
 * ------------
 * Returns all saved generated reports from localStorage.
 */
export function getReports(): ReportRecord[] {
  try {
    return JSON.parse(localStorage.getItem(REPORT_KEY) || "[]");
  } catch {
    return [];
  }
}

/**
 * addReport(record)
 * -----------------
 * Saves a newly generated report to localStorage.
 * Keeps only the latest 100 reports.
 * Fires "history-updated" so the Reports page re-renders.
 *
 * Called from the Reports page when the user clicks "Generate".
 */
export function addReport(rec: Omit<ReportRecord, "id" | "timestamp">) {
  const list   = getReports();
  const record: ReportRecord = {
    ...rec,
    id:        Math.random().toString(36).slice(2, 10),
    timestamp: Date.now(),
  };

  list.unshift(record);

  // Keep only latest 100 reports
  localStorage.setItem(REPORT_KEY, JSON.stringify(list.slice(0, 100)));

  window.dispatchEvent(new Event("history-updated"));

  return record;
}

/**
 * removeReport(id)
 * ----------------
 * Deletes a single report by its ID.
 */
export function removeReport(id: string) {
  localStorage.setItem(
    REPORT_KEY,
    JSON.stringify(getReports().filter((r) => r.id !== id))
  );
  window.dispatchEvent(new Event("history-updated"));
}

/**
 * clearReports()
 * --------------
 * Deletes all saved reports from localStorage.
 * Called from Settings page "Clear Reports" button.
 */
export function clearReports() {
  localStorage.removeItem(REPORT_KEY);
  window.dispatchEvent(new Event("history-updated"));
}
