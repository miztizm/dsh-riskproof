# Preview a tool call before execution

Enter a direct command in the DSH composer:

```text
/riskproof test file_read {"path":"notes.txt"}
/riskproof test send_email {"to":"outside@example.com","body":{"refreshToken":"synthetic-example"}}
```

Use tool names registered in your current session; the examples require those
tools to be installed. Use synthetic values. The command accepts a JSON object
up to 32 KiB, 64 levels and 10,000 traversal nodes. Invalid input returns a fixed
usage message without echoing parser excerpts or arguments.

The result shows `allow`, `ask` or `deny`, risk level, detected labels, matched
rule IDs and remediation. It uses the current RiskProof configuration, task scope,
retained provenance and tool identity baseline. `observe` mode explicitly labels
the verdict as advisory.

Preview never invokes the proposed tool or other plugins' execution hooks. It
does not create receipts, add session state, pin tool metadata, request approval,
or change task scope. It cannot predict host approval, another plugin's decision,
an actual result, or changes made after the preview. An `allow` verdict does not
establish safety or grant permission to a future invocation.

The command declares `recordInput: false` to DSH. Its result contains no supplied
argument names, values, paths or raw rule evidence. DSH can retain the displayed
result in command history. Do not paste real credentials into the composer.

## Credential fields

RiskProof detects non-empty string credentials in nested objects and arrays by
exact field name, ignoring case, underscores and hyphens:

- `apiKey`, `accessToken`, `refreshToken`, `authorization`: `SECRET` and `API_KEY`.
- `password`, `passphrase`, `secret`, `token`, `clientSecret`, `privateKey`,
  `otpSecret`, `totpSecret`, `recoveryCode`, `recoveryCodes`, `sessionToken`,
  `sessionCookie`: `SECRET`.

Opaque values in these fields need no provider-specific prefix. The same labels
apply to execution arguments and output payloads. Assignment text for the listed
credential names and `otpauth://totp/` / `otpauth://hotp/` URIs is also detected.
Output gating blocks `SECRET` and `API_KEY` by default. A configured declassifier
cannot remove labels detected in its actual output.

Summary fields such as `hasTotp`, `tokenCount` and `passwordLength` do not acquire
credential labels merely because of their names. Empty and non-string field
values are not credentials under the structured field detector. These are
bounded deterministic heuristics, not semantic DLP: arbitrary renamed, encoded,
split or numeric secrets may not be detected. Tool-source labels remain additive;
vault-named tools are still classified conservatively, including summary tools.
There is no automatic exemption for dsh-vault or permission-rule tools.

## 中文用法

在输入框直接运行 `/riskproof test 工具名 {"参数":"合成数据"}`，可以检查当前
会话的规则结论、标签、命中规则和处理建议。试算使用实际配置、任务范围和已保留的
来源信息，但不会调用目标工具、请求审批、增加账单或更新工具身份基线。

观察模式中的结论仅为建议；其他插件、宿主审批与执行后输出均不在试算范围内。
请使用合成数据，结果不回显参数内容，错误也不包含 JSON 解析器回显。
