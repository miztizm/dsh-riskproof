import type { SecurityDecision } from "../core/types.js";
import { argumentLeaves } from "../core/arguments.js";
import { displayText, RULE_GUIDANCE } from "./report.js";

export const PREVIEW_USAGE = '/riskproof test <tool> {"argument":"synthetic value"}';

/** Fixed errors deliberately exclude JSON parser excerpts and supplied values. */
export function parsePreview(input: string): { name: string; args: Record<string, unknown> } {
  if (Buffer.byteLength(input, "utf8") > 32_768) throw new RangeError("preview input exceeds 32 KiB");
  const match = input.match(/^([A-Za-z0-9_.:-]{1,256})\s+(\{[\s\S]*\})$/);
  if (!match) throw new TypeError("expected a tool name and a JSON object");
  let args: unknown;
  try { args = JSON.parse(match[2]); }
  catch { throw new TypeError("invalid JSON object"); }
  if (!args || typeof args !== "object" || Array.isArray(args)) throw new TypeError("expected a JSON object");
  argumentLeaves(args as Record<string, unknown>);
  return { name: match[1], args: args as Record<string, unknown> };
}

/** Never echo argument values, paths, source ids, or free-form engine evidence. */
export function renderPreview(decision: SecurityDecision, language: "zh-CN" | "en", mode: "observe" | "enforce"): string {
  const zh = language === "zh-CN";
  const verdict = decision.decision === "require_approval" ? "ask" : decision.decision;
  const taints = [...new Set(Object.values(decision.taints).flat())];
  return [
    zh ? "🛡 RiskProof · 执行前试算" : "🛡 RiskProof · Policy preview",
    `${zh ? "规则结论" : "Policy verdict"}: ${verdict} · ${zh ? "风险级别" : "Risk level"}: ${decision.riskLevel}`,
    ...(mode === "observe" ? [zh ? "观察模式：此结论仅为建议，RiskProof 不会据此拦截。" : "Observe mode: this verdict is advisory; RiskProof will not enforce it."] : []),
    `${zh ? "敏感标签" : "Labels"}: ${taints.join(", ") || "—"}`,
    ...decision.matchedRules.flatMap(rule => [
      `${rule.id}${zh && RULE_GUIDANCE[rule.id] ? ` · ${RULE_GUIDANCE[rule.id][0]}` : ""}`,
      ...(rule.remediation ? [displayText(zh && RULE_GUIDANCE[rule.id] ? RULE_GUIDANCE[rule.id][1] : rule.remediation)] : []),
    ]),
    ...(!decision.matchedRules.length ? [zh ? "未触发规则不代表操作安全。" : "No matched rule does not establish safety."] : []),
    "",
    zh ? "仅试算当前会话的 RiskProof 执行前规则；不执行工具、不增加账单、不更新身份基线。其他插件、宿主审批及实际输出未纳入试算。"
      : "Pre-execution RiskProof rules for this session only. No dispatch, receipts or identity pin updates. Other plugins, host approvals and actual output are not evaluated.",
  ].join("\n");
}
