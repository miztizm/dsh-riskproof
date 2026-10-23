import type { Context } from "@deepseek-ai/cordis";
import type { Agent } from "@deepseek-ai/dsh-agent";
import type { SecurityCapability } from "../core/types.js";
import { classifyTool } from "../classification/classifier.js";
import type { CapabilityOverrides } from "../classification/overrides.js";

/** Cached capability resolution, invalidated on `tools/change`. */
export class CapabilityResolver {
  private readonly globalCache = new Map<string, SecurityCapability[]>();
  private scopedCache = new WeakMap<Agent, Map<string, SecurityCapability[]>>();

  constructor(
    private readonly ctx: Context,
    private readonly overrides: CapabilityOverrides,
  ) {}

  resolve(name: string, agent?: Agent): SecurityCapability[] {
    if (Object.hasOwn(this.overrides, name)) return [...this.overrides[name]];
    let cache = this.globalCache;
    if (agent) {
      cache = this.scopedCache.get(agent) ?? new Map<string, SecurityCapability[]>();
      this.scopedCache.set(agent, cache);
    }
    const cached = cache.get(name);
    if (cached) return [...cached];

    const capabilities = this.inspect(name, agent);
    cache.set(name, capabilities);
    return [...capabilities];
  }

  /** Preview metadata without warming a cache later used by real execution. */
  inspect(name: string, agent?: Agent): SecurityCapability[] {
    if (Object.hasOwn(this.overrides, name)) return [...this.overrides[name]];
    let definition = this.ctx.tools.get(name);
    if (agent) definition = this.ctx.tools.get(name, agent) ?? definition;

    return classifyTool({
      name,
      description: definition?.description,
      inputSchema: definition?.parameters,
    });
  }

  invalidate(): void {
    this.globalCache.clear();
    this.scopedCache = new WeakMap<Agent, Map<string, SecurityCapability[]>>();
  }
}

