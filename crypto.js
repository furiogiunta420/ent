const PBKDF2_ITERATIONS = 200_000;
const enc = new TextEncoder();
const dec = new TextDecoder();

// ─── Helpers ──────────────────────────────────────────────────────────────────

export function b64encode(buf) {
  const bytes = new Uint8Array(buf);
  const CHUNK_SIZE = 0x8000; // 32768 — safely under the ~65535 argument limit engines impose
  let binary = "";
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK_SIZE));
  }
  return btoa(binary);
}

export function b64decode(str) {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

// ─── Key derivation ───────────────────────────────────────────────────────────

async function importPassword(password) {
  return crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveKey", "deriveBits"]
  );
}

/**
 * Derives WRAP_KEY (AES-KW) from password + username.
 * Used to wrap/unwrap the GROUP_KEY — never leaves the browser.
 */
export async function deriveWrapKey(password, username) {
  const base = await importPassword(password);
  const salt = enc.encode(`${username}:WRAP:aspidac`);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    base,
    { name: "AES-KW", length: 256 },
    false,
    ["wrapKey", "unwrapKey"]
  );
}

/**
 * Derives AUTH_TOKEN (hex) from password + username.
 * This is what gets sent to the server — completely different from WRAP_KEY.
 */
export async function deriveAuthToken(password, username) {
  const base = await importPassword(password);
  const salt = enc.encode(`${username}:AUTH:aspidac`);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    base, 256
  );
  return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Convenience: derives both WRAP_KEY and AUTH_TOKEN in parallel.
 */
export async function deriveSessionKeys(password, username) {
  const [wrapKey, authToken] = await Promise.all([
    deriveWrapKey(password, username),
    deriveAuthToken(password, username),
  ]);
  return { wrapKey, authToken };
}

// ─── Group key management ─────────────────────────────────────────────────────

/**
 * Generates a fresh random AES-GCM-256 GROUP_KEY.
 * Called once when the very first user logs in.
 */
export async function generateGroupKey() {
  return crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,   // extractable so it can be wrapped for each user
    ["encrypt", "decrypt"]
  );
}

/**
 * Wraps GROUP_KEY with the user's WRAP_KEY → base64 string for server storage.
 */
export async function wrapGroupKey(groupKey, wrapKey) {
  const wrapped = await crypto.subtle.wrapKey("raw", groupKey, wrapKey, "AES-KW");
  return b64encode(wrapped);
}

/**
 * Unwraps a base64 bundle from the server → usable AES-GCM GROUP_KEY.
 */
export async function unwrapGroupKey(b64Bundle, wrapKey) {
  const wrapped = b64decode(b64Bundle);
  return crypto.subtle.unwrapKey(
    "raw", wrapped, wrapKey,
    "AES-KW",
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

/**
 * Exports GROUP_KEY to raw bytes → base64, for re-wrapping for new users.
 */
export async function exportGroupKey(groupKey) {
  const raw = await crypto.subtle.exportKey("raw", groupKey);
  return b64encode(raw);
}

/**
 * Imports a raw base64 GROUP_KEY back into a CryptoKey.
 */
export async function importGroupKey(b64Raw) {
  const raw = b64decode(b64Raw);
  return crypto.subtle.importKey(
    "raw", raw,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

// ─── Encrypt / decrypt ────────────────────────────────────────────────────────

/**
 * Encrypts a UTF-8 string with GROUP_KEY. Returns base64(iv + ciphertext).
 */
export async function encryptText(groupKey, plaintext) {
  const iv         = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, groupKey, enc.encode(plaintext)
  );
  const out = new Uint8Array(12 + ciphertext.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ciphertext), 12);
  return b64encode(out.buffer);
}

/**
 * Decrypts a base64(iv + ciphertext) string. Returns plaintext.
 */
export async function decryptText(groupKey, b64) {
  const buf  = b64decode(b64);
  const iv   = buf.slice(0, 12);
  const ct   = buf.slice(12);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, groupKey, ct);
  return dec.decode(plain);
}

/**
 * Encrypts a File with GROUP_KEY. Returns { b64, mimeType, originalName }.
 */
export async function encryptFile(groupKey, file) {
  const iv         = crypto.getRandomValues(new Uint8Array(12));
  const bytes      = await file.arrayBuffer();
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, groupKey, bytes);
  const out = new Uint8Array(12 + ciphertext.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ciphertext), 12);
  return { b64: b64encode(out.buffer), mimeType: file.type, originalName: file.name };
}

/**
 * Decrypts a base64 encrypted file. Returns a Blob.
 */
export async function decryptFile(groupKey, b64, mimeType) {
  const buf   = b64decode(b64);
  const iv    = buf.slice(0, 12);
  const ct    = buf.slice(12);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, groupKey, ct);
  return new Blob([plain], { type: mimeType });
}