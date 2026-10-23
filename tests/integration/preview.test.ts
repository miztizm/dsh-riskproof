import { describe, expect, it } from "vitest";
import { RiskProofRuntime } from "../../src/dsh/runtime.js";
import { resolveRiskProofConfig } from "../../src/config.js";
import { parsePreview, renderPreview } from "../../src/experience/preview.js";
import { ToolIdentityTracker } from "../../src/core/identity.js";
import { RuntimeState } from "../../src/dsh/runtime-state.js";
import { allowNext, makeExec, makeMockCtx, successResult } from "../dsh-mocks.js";

describe("policy previews", () => {
  it("uses live provenance and task limits without recording or dispatch", async () => {
    const runtime = new RiskProofRuntime(makeMockCtx({
      web_fetch: { description: "Fetch a web page" },
      bash: { description: "Execute a shell command" },
    }));
    const read = makeExec("web_fetch", {});
    await runtime.preExecute(read, allowNext);
    runtime.onResult(read, successResult("echo preview-origin-marker"));
    const before = runtime.report("session-1");
    const decision = runtime.preview("bash", { command: "echo preview-origin-marker" }, read.agent);
    expect(decision.decision).toBe("deny");
    expect(decision.matchedRules.map(r => r.id)).toContain("untrusted_code_execution");
    expect(runtime.report("session-1")).toEqual(before);
    runtime.setTaskMode("session-1", "read-only");
    expect(runtime.preview("bash", { command: "echo hello" }, read.agent).matchedRules.map(r => r.id)).toContain("task_scope_violation");
    expect(runtime.report("session-1").proofs).toHaveLength(1);
    expect(runtime.preview("bash", { command: "echo preview-origin-marker" }, makeExec("bash", {}, "other").agent).decision).toBe("allow");
  });

  it("neither creates nor replaces identity pins", async () => {
    const defs = { file_read: { description: "Read a local file" } };
    const runtime = new RiskProofRuntime(makeMockCtx(defs));
    const exec = makeExec("file_read", { path: "notes.txt" });
    runtime.preview(exec.name, exec.arguments as Record<string, unknown>, exec.agent);
    defs.file_read.description = "Read a local text file";
    runtime.onToolsChange();
    expect((await runtime.preExecute(exec, allowNext)).kind).toBe("allow");
    expect(runtime.listProofs()[0].identity?.status).toBe("first-seen");
    defs.file_read.description = "Read a different file";
    runtime.onToolsChange();
    expect(runtime.preview(exec.name, {}, exec.agent).decision).toBe("deny");
    defs.file_read.description = "Read a local text file";
    runtime.onToolsChange();
    expect(runtime.preview(exec.name, {}, exec.agent).decision).toBe("allow");
  });

  it("does not consume session or identity capacity", () => {
    const state = new RuntimeState(resolveRiskProofConfig());
    for (let i = 0; i < 300; i++) {
      expect(state.preview(`preview-${i}`).taskMode).toBe("standard");
      expect(state.peek(`preview-${i}`)).toBeUndefined();
    }
    expect(state.get("live")).toBe(state.preview("live"));
    const identity = new ToolIdentityTracker(1);
    expect(identity.inspect("a", "1")).toBe("first-seen");
    expect(identity.check("b", "2")).toBe("first-seen");
    expect(identity.inspect("a", "1")).toBe("capacity-exceeded");
    expect(identity.inspect("b", "2")).toBe("unchanged");
    expect(identity.inspect("b", "3")).toBe("changed");
  });

  it("rejects unknown tools and malformed or excessive input without echoing it", () => {
    expect(() => new RiskProofRuntime(makeMockCtx()).preview("missing", {})).toThrow(/registered/);
    expect(parsePreview('file_read {"path":"notes.txt"}')).toEqual({ name: "file_read", args: { path: "notes.txt" } });
    for (const input of ["", 'file_read []', 'file_read {"secret-marker":}', `file_read {"x":"${"a".repeat(33_000)}"}`]) {
      expect(() => parsePreview(input)).toThrow();
      try { parsePreview(input); } catch (error) { expect(String(error)).not.toContain("secret-marker"); }
    }
    expect(() => parsePreview(`file_read ${JSON.stringify({ x: Array(10_001).fill(1) })}`)).toThrow(/node count/);
    let deep: unknown = "x";
    for (let i = 0; i < 70; i++) deep = { x: deep };
    expect(() => parsePreview(`file_read ${JSON.stringify(deep)}`)).toThrow(/depth/);
  });

  it("renders bilingual advisory verdicts without supplied values or argument names", () => {
    const runtime = new RiskProofRuntime(makeMockCtx({ send_email: { description: "Send an email message" } }));
    const decision = runtime.preview("send_email", { to: "outside@example.com", body: { "private-marker": { refreshToken: "opaque-private-value" } } });
    expect(decision.decision).toBe("deny");
    for (const language of ["en", "zh-CN"] as const) {
      const rendered = renderPreview(decision, language, "observe");
      expect(rendered).toContain("deny");
      expect(rendered).toContain("API_KEY");
      expect(rendered).not.toMatch(/opaque-private-value|private-marker|outside@example.com/);
      expect(rendered).toContain(language === "en" ? "advisory" : "观察模式");
    }
    const allow = runtime.preview("send_email", { body: "hello" });
    expect(renderPreview(allow, "en", "enforce")).toContain("No matched rule");
    expect(renderPreview(allow, "zh-CN", "enforce")).toContain("不代表操作安全");
  });
});
