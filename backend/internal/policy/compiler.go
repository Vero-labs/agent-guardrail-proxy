package policy

import (
	"fmt"
	"strings"
)

// Compile converts a GuardrailPolicy into Cedar policy text.
// The output is a valid Cedar policy string that can be loaded by cedar.Engine.
func Compile(p *GuardrailPolicy) (string, error) {
	var b strings.Builder

	b.WriteString("// Auto-generated from guardrail.yaml — DO NOT EDIT DIRECTLY\n")
	b.WriteString(fmt.Sprintf("// Policy version: %s\n\n", p.Version))

	// ── Section 1: Default Permit ──
	compileSectionHeader(&b, "1", "FAIL-OPEN DEFAULT")
	b.WriteString(`permit(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.pii.isEmpty()
};

`)

	// ── Section 2: Global Safety ──
	compileSectionHeader(&b, "2", "GLOBAL SAFETY")
	compileSafety(&b, &p.Safety)

	// ── Section 3: Intent Thresholds ──
	compileSectionHeader(&b, "3", "INTENT RISK CONTROLS")
	compileIntents(&b, p.Intents)

	// ── Section 3b: User Intent Overrides ──
	if len(p.UserIntentOverrides) > 0 {
		b.WriteString("// User-intent stricter thresholds\n")
		compileUserIntentOverrides(&b, p.UserIntentOverrides)
	}

	// ── Section 4: PII Controls ──
	compileSectionHeader(&b, "4", "PII CONTROLS")
	compilePII(&b, &p.Pii)

	// ── Section 5: Capabilities ──
	compileSectionHeader(&b, "5", "CAPABILITY CONTROLS")
	compileCapabilities(&b, &p.Capabilities)

	// ── Section 6: Fail-Safe ──
	compileSectionHeader(&b, "6", "FAIL-SAFE CATCH-ALL")
	compileFailSafe(&b, &p.Safety)

	// ── Section 7: Agentic Limits ──
	compileSectionHeader(&b, "7", "AGENTIC WORKFLOW CONTROLS")
	compileAgentLimits(&b, &p.AgentLimits)

	// ── Section 7b: Source Trust ──
	if len(p.SourceTrust) > 0 {
		b.WriteString("// Source trust restrictions\n")
		compileSourceTrust(&b, p.SourceTrust)
	}

	// ── Section 8: Roles ──
	if len(p.Roles) > 0 {
		compileSectionHeader(&b, "8", "ROLE-BASED GUARDRAILS")
		compileRoles(&b, p.Roles)
	}

	return b.String(), nil
}

func compileSectionHeader(b *strings.Builder, num, title string) {
	b.WriteString(fmt.Sprintf("// ═══ SECTION %s: %s ═══\n", num, title))
}

// ── Safety ──────────────────────────────────────────────────────────────────

func compileSafety(b *strings.Builder, s *SafetyConfig) {
	if s.PromptInjection == "block" {
		b.WriteString(`forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.prompt_injection == true
};

`)
	}

	toxInt := int(s.ToxicityThreshold * 100)
	b.WriteString(fmt.Sprintf(`forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.toxicity > %d
};

`, toxInt))
}

// ── Intents ─────────────────────────────────────────────────────────────────

func compileIntents(b *strings.Builder, intents map[string]IntentRule) {
	for name, rule := range intents {
		if rule.Action != "block" {
			continue // only block rules generate forbid policies
		}

		condParts := []string{
			fmt.Sprintf(`(context.intent == "%s" || context.user_intent == "%s")`, name, name),
			fmt.Sprintf(`context.confidence > %d`, rule.Threshold),
		}

		if rule.When != nil && rule.When.Sensitivity != "" {
			condParts = append([]string{
				fmt.Sprintf(`resource.sensitivity == "%s"`, rule.When.Sensitivity),
			}, condParts...)
		}

		condition := strings.Join(condParts, " &&\n    ")

		b.WriteString(fmt.Sprintf(`// %s (threshold: %d)
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    %s
};

`, name, rule.Threshold, condition))
	}
}

// ── User Intent Overrides ───────────────────────────────────────────────────

func compileUserIntentOverrides(b *strings.Builder, overrides map[string]IntentOverride) {
	for name, override := range overrides {
		b.WriteString(fmt.Sprintf(`// user_%s (stricter: %d)
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.user_intent == "%s" &&
    context.confidence > %d
};

`, name, override.Threshold, name, override.Threshold))
	}
}

// ── PII ─────────────────────────────────────────────────────────────────────

func compilePII(b *strings.Builder, pii *PIIConfig) {
	if len(pii.Block) > 0 {
		conditions := make([]string, len(pii.Block))
		for i, p := range pii.Block {
			conditions[i] = fmt.Sprintf(`context.pii.contains("%s")`, p)
		}
		b.WriteString(fmt.Sprintf(`// Block PII: %s
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    %s
};

`, strings.Join(pii.Block, ", "), strings.Join(conditions, " ||\n    ")))
	}

	if len(pii.Redact) > 0 {
		// Build the containsAny check
		redactQuoted := make([]string, len(pii.Redact))
		for i, r := range pii.Redact {
			redactQuoted[i] = fmt.Sprintf(`"%s"`, r)
		}

		// Build the "not blocked" condition
		blockChecks := make([]string, len(pii.Block))
		for i, p := range pii.Block {
			blockChecks[i] = fmt.Sprintf(`context.pii.contains("%s")`, p)
		}
		notBlocked := ""
		if len(blockChecks) > 0 {
			notBlocked = fmt.Sprintf(" &&\n    !(%s)", strings.Join(blockChecks, " || "))
		}

		b.WriteString(fmt.Sprintf(`// Redact PII: %s
@obligation("REDACT")
@fields("%s")
permit(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.pii.containsAny([%s])%s
};

`, strings.Join(pii.Redact, ", "),
			strings.Join(pii.Redact, ","),
			strings.Join(redactQuoted, ", "),
			notBlocked))
	}

	// Block PII queries from user messages
	if len(pii.Block) > 0 {
		blockQuoted := make([]string, len(pii.Block))
		for i, p := range pii.Block {
			blockQuoted[i] = fmt.Sprintf(`"%s"`, p)
		}
		b.WriteString(fmt.Sprintf(`// Block user PII queries
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.user_intent == "info.query.pii" &&
    (context.pii.containsAny([%s]) || context.confidence > 30)
};

`, strings.Join(blockQuoted, ", ")))
	}
}

// ── Capabilities ────────────────────────────────────────────────────────────

func compileCapabilities(b *strings.Builder, cap *CapabilitiesConfig) {
	if len(cap.Block) == 0 {
		return
	}

	// Group in pairs for readability
	for i := 0; i < len(cap.Block); i += 2 {
		conditions := []string{
			fmt.Sprintf(`context.capabilities.contains("%s")`, cap.Block[i]),
		}
		if i+1 < len(cap.Block) {
			conditions = append(conditions,
				fmt.Sprintf(`context.capabilities.contains("%s")`, cap.Block[i+1]))
		}

		b.WriteString(fmt.Sprintf(`forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    %s
};

`, strings.Join(conditions, " ||\n    ")))
	}
}

// ── Fail-Safe ───────────────────────────────────────────────────────────────

func compileFailSafe(b *strings.Builder, s *SafetyConfig) {
	riskInt := int(s.MaxRiskScore * 100)
	b.WriteString(fmt.Sprintf(`forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.risk_score > %d &&
    context.intent != "conv.greeting" &&
    context.intent != "conv.other" &&
    context.intent != "info.query" &&
    context.intent != "info.summarize"
};

`, riskInt))
}

// ── Agent Limits ────────────────────────────────────────────────────────────

func compileAgentLimits(b *strings.Builder, al *AgentLimitsConfig) {
	// Step budget
	b.WriteString(`// Step budget enforcement
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.agent_state.max_steps > 0 &&
    context.agent_state.current_step > context.agent_state.max_steps
};

`)

	// Token budget
	b.WriteString(`// Token budget enforcement
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.agent_state.token_budget > 0 &&
    context.agent_state.total_tokens > context.agent_state.token_budget
};

`)

	// Tighten after step
	if al.TightenAfterStep > 0 {
		b.WriteString(fmt.Sprintf(`// Tighten thresholds after step %d
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.agent_state.current_step > %d &&
    (context.intent == "file.write" || context.intent == "sys.control") &&
    context.confidence > %d
};

`, al.TightenAfterStep, al.TightenAfterStep, al.TightenedThreshold))
	}
}

// ── Source Trust ─────────────────────────────────────────────────────────────

func compileSourceTrust(b *strings.Builder, sources map[string]SourceRule) {
	for source, rule := range sources {
		if len(rule.BlockIntents) == 0 {
			continue
		}

		intentChecks := make([]string, len(rule.BlockIntents))
		for i, intent := range rule.BlockIntents {
			intentChecks[i] = fmt.Sprintf(`context.intent == "%s"`, intent)
		}

		originField := "origin"
		trustedCheck := ""
		if source == "untrusted_web" {
			trustedCheck = fmt.Sprintf(`    context.source_data.trusted == false &&
    context.source_data.%s == "%s" &&
`, originField, source)
		} else {
			trustedCheck = fmt.Sprintf(`    context.source_data.%s == "%s" &&
`, originField, source)
		}

		b.WriteString(fmt.Sprintf(`// Source: %s
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
%s    (%s)
};

`, source, trustedCheck, strings.Join(intentChecks, " || ")))
	}
}

// ── Roles ───────────────────────────────────────────────────────────────────

func compileRoles(b *strings.Builder, roles map[string]RoleConfig) {
	for name, role := range roles {
		// 1. Intent Allowlist: block any intent not in allow_intents
		if len(role.AllowIntents) > 0 {
			allowChecks := make([]string, len(role.AllowIntents))
			for i, intent := range role.AllowIntents {
				allowChecks[i] = fmt.Sprintf(`context.intent == "%s"`, intent)
			}

			b.WriteString(fmt.Sprintf(`// Role: %s — %s
// Block any intent not in allowlist
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.role == "%s" &&
    !(%s)
};

`, name, role.Description, name, strings.Join(allowChecks, " || \n      ")))
		}

		// 2. Explicit Intent Blocks
		if len(role.BlockIntents) > 0 {
			blockChecks := make([]string, len(role.BlockIntents))
			for i, intent := range role.BlockIntents {
				blockChecks[i] = fmt.Sprintf(`context.intent == "%s"`, intent)
			}

			b.WriteString(fmt.Sprintf(`// Role: %s — explicit blocks
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.role == "%s" &&
    (%s)
};

`, name, name, strings.Join(blockChecks, " || ")))
		}

		// 3. Topic Allowlist: block any topic not in allowed_topics
		if len(role.AllowedTopics) > 0 {
			topicChecks := make([]string, len(role.AllowedTopics))
			for i, topic := range role.AllowedTopics {
				topicChecks[i] = fmt.Sprintf(`context.topic == "%s"`, topic)
			}

			b.WriteString(fmt.Sprintf(`// Role: %s — topic allowlist
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.role == "%s" &&
    context.topic != "" &&
    !(%s)
};

`, name, name, strings.Join(topicChecks, " || ")))
		}

		// 4. Explicit Topic Blocks
		if len(role.BlockTopics) > 0 {
			blockTopics := make([]string, len(role.BlockTopics))
			for i, topic := range role.BlockTopics {
				blockTopics[i] = fmt.Sprintf(`context.topic == "%s"`, topic)
			}

			b.WriteString(fmt.Sprintf(`// Role: %s — explicit topic blocks
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.role == "%s" &&
    (%s)
};

`, name, name, strings.Join(blockTopics, " || ")))
		}
	}
}
