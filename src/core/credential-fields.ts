import type { TaintLabel } from "./types.js";

// Exact field names only: tokenCount, passwordLength and hasTotp are metadata.
const API_FIELDS = new Set(["apikey", "accesstoken", "refreshtoken", "authorization"]);
const SECRET_FIELDS = new Set([
  "password", "passphrase", "secret", "token", "clientsecret", "privatekey",
  "otpsecret", "totpsecret", "recoverycode", "recoverycodes", "sessiontoken", "sessioncookie",
]);

/** Opaque credentials need not resemble any provider's token format. */
export function credentialFieldTaints(field: string, value: unknown): TaintLabel[] {
  if (typeof value !== "string" || !value.trim()) return [];
  const key = field.replace(/[_-]/g, "").toLowerCase();
  if (API_FIELDS.has(key)) return ["SECRET", "API_KEY"];
  return SECRET_FIELDS.has(key) ? ["SECRET"] : [];
}
