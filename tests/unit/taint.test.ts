import { describe, expect, it } from "vitest";
import {
  detectValueTaints,
  enrichArgumentTaints,
  inferKindFromTool,
  inferTaintsFromSource,
} from "../../src/core/taint.js";

describe("taint inference", () => {
  it.each(["accessToken", "refresh_token", "API-KEY", "authorization", "clientSecret", "privateKey", "otpSecret", "totp_secret", "recoveryCodes", "sessionCookie", "passphrase"])("detects opaque credentials in nested %s fields", field => {
    expect(detectValueTaints({ entries: [{ [field]: ["opaque-value"] }] })).toContain("SECRET");
    expect(enrichArgumentTaints({ entries: [{ [field]: "opaque-value" }] }, {}, {})[`entries[0].${field}`]).toContain("SECRET");
  });

  it.each(["accessToken", "refresh_token", "clientSecret", "privateKey", "otpSecret", "totp_secret", "recoveryCode", "sessionCookie", "passphrase"])("detects %s in serialized output", field => {
    expect(detectValueTaints(`${field}=opaque-value`)).toContain("SECRET");
  });

  it("labels OAuth tokens as API keys and recognizes TOTP provisioning URIs", () => {
    expect(detectValueTaints({ refreshToken: "opaque" })).toContain("API_KEY");
    expect(detectValueTaints("otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP")).toContain("SECRET");
  });

  it("does not infer credentials from unrelated summary fields", () => {
    expect(detectValueTaints({ tokenCount: 12, hasTotp: true, passwordLength: 20, privateKeyCount: 2, accessTokenExpiresAt: "tomorrow" })).toEqual([]);
    expect(detectValueTaints({ clientSecret: "", otpSecret: false, refreshToken: null })).toEqual([]);
  });

  it("bounds traversal of structured credentials", () => {
    let value: unknown = "opaque";
    for (let i = 0; i < 70; i++) value = { wrapper: value };
    expect(() => detectValueTaints(value)).toThrow(/depth/);
  });
  it("detects an API key", () => {
    expect(detectValueTaints("sk-abcdefghijklmnopqrstuvwxyz123456")).toContain("API_KEY");
  });

  it("detects a bearer token", () => {
    expect(detectValueTaints("Authorization: Bearer abc.def.ghi123456789")).toContain("API_KEY");
  });

  it("detects a key=value secret", () => {
    expect(detectValueTaints("api_key=supersecretvalue123")).toContain("SECRET");
  });

  it("detects common provider tokens and private-key headers", () => {
    expect(detectValueTaints("AKIAIOSFODNN7EXAMPLE")).toContain("API_KEY");
    expect(detectValueTaints("ghp_abcdefghijklmnopqrstuvwxyz123456")).toContain("API_KEY");
    expect(detectValueTaints("-----BEGIN OPENSSH PRIVATE KEY-----")).toContain("SECRET");
  });

  it("detects customer data", () => {
    expect(detectValueTaints("customer record for CUST-8842")).toContain("CUSTOMER_DATA");
  });

  it("detects PII email", () => {
    expect(detectValueTaints("contact alice@example.com")).toContain("PII");
  });

  it("detects financial data", () => {
    expect(detectValueTaints("bank account IBAN DE89 3704")).toContain("FINANCIAL_DATA");
  });

  it("detects patient data", () => {
    expect(detectValueTaints("patient diagnosis: hypertension")).toContain("PATIENT_DATA");
  });

  it("combines multiple taints additively", () => {
    const taints = detectValueTaints("customer alice@example.com api_key=secret123");
    expect(taints).toContain("CUSTOMER_DATA");
    expect(taints).toContain("PII");
    expect(taints).toContain("SECRET");
  });

  it("infers taints from a source id", () => {
    expect(inferTaintsFromSource("webpage_1")).toContain("UNTRUSTED_WEB");
    expect(inferTaintsFromSource("customer_data_3")).toContain("CUSTOMER_DATA");
  });

  it("infers a context kind from tool name + capability", () => {
    expect(inferKindFromTool("database_query", ["PRIVATE_ACCESS"])).toBe("tool_output");
    expect(inferKindFromTool("customer_database_query", ["PRIVATE_ACCESS"])).toBe("customer_data");
    expect(inferKindFromTool("web_fetch", ["EXTERNAL_INGESTION"])).toBe("untrusted_web");
    expect(inferKindFromTool("get_secret", ["CREDENTIAL_ACCESS"])).toBe("secret");
  });

  it("enriches argument taints additively", () => {
    const args = { body: "CUST-8842 balance 125000" };
    const provenance = { body: ["webpage_1"] };
    const base = { body: [] };
    const enriched = enrichArgumentTaints(args, provenance, base);
    expect(enriched.body).toContain("UNTRUSTED_WEB");
    expect(enriched.body).toContain("CUSTOMER_DATA");
  });
});
