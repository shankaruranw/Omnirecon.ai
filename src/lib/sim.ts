/**
 * OmniRecon AI — Deterministic Simulation Engine
 * ================================================
 * Generates realistic, reproducible fake results when the Python
 * backend is offline. Used as a fallback for all tool components.
 *
 * Key design principle:
 *   The same input ALWAYS produces the same output.
 *   e.g. "google.com" → always shows the same fake IP address.
 *   This makes demonstrations reliable and repeatable.
 *
 * How it works:
 *   1. The input string (e.g. domain name) is hashed into a seed number.
 *   2. A seeded pseudo-random number generator (PRNG) is created.
 *   3. All fake data is generated from this PRNG — consistent every time.
 */

/**
 * seeded(str)
 * -----------
 * Creates a deterministic pseudo-random number generator seeded
 * by the input string. Uses a simple but effective hash function.
 *
 * Returns a function that produces a new number between 0 and 1
 * each time it is called (like Math.random(), but deterministic).
 *
 * Example:
 *   const rng = seeded("google.com");
 *   rng() → always 0.4231...
 *   rng() → always 0.8912...
 */
export function seeded(str: string) {
  // FNV-inspired hash to convert string to a numeric seed
  let h = 1779033703 ^ str.length;
  for (let i = 0; i < str.length; i++) {
    h = Math.imul(h ^ str.charCodeAt(i), 3432918353);
    h = (h << 13) | (h >>> 19);
  }
  // Finalize hash
  let seed = (h ^= h >>> 16) >>> 0;

  // Return LCG (Linear Congruential Generator) function
  return () => {
    // LCG parameters from Numerical Recipes
    seed = (seed * 1664525 + 1013904223) >>> 0;
    return seed / 4294967296; // Normalize to [0, 1)
  };
}

/**
 * pick(rng, array)
 * ----------------
 * Picks a random element from an array using the seeded RNG.
 * Ensures consistent selection for the same seed.
 *
 * Example:
 *   pick(rng, ["GoDaddy", "Namecheap", "Cloudflare"]) → "Namecheap"
 */
export function pick<T>(rng: () => number, arr: T[]): T {
  return arr[Math.floor(rng() * arr.length)];
}

/**
 * randInt(rng, min, max)
 * ----------------------
 * Generates a random integer between min and max (inclusive).
 *
 * Example:
 *   randInt(rng, 1, 100) → 47
 */
export function randInt(rng: () => number, min: number, max: number) {
  return Math.floor(rng() * (max - min + 1)) + min;
}

/**
 * randIp(rng)
 * -----------
 * Generates a realistic-looking fake IPv4 address.
 * First octet is limited to 1-223 (avoids reserved ranges).
 *
 * Example:
 *   randIp(rng) → "142.250.80.14"
 */
export function randIp(rng: () => number) {
  return `${randInt(rng, 1, 223)}.${randInt(rng, 0, 255)}.${randInt(rng, 0, 255)}.${randInt(rng, 1, 254)}`;
}

/**
 * delay(ms)
 * ---------
 * Returns a Promise that resolves after the specified milliseconds.
 * Used to simulate realistic network latency in tools.
 * Makes the loading spinner appear briefly even in offline mode.
 *
 * Example:
 *   await delay(700); // Wait 700ms to simulate a real API call
 */
export const delay = (ms: number) =>
  new Promise((resolve) => setTimeout(resolve, ms));
