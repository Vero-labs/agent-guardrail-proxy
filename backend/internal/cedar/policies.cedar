// Agent Guardrail Cedar Policies v3.0
// Full Policy Control - All risk decisions are made here, not in Go code.
//
// SIGNALS AVAILABLE (from Go analyzers):
//   context.intent            - Aggregate intent (string)
//   context.user_intent       - Intent from user messages only (string)
//   context.system_intent     - Intent from system messages only (string)
//   context.confidence        - Confidence 0-100 (long)
//   context.risk_score        - Raw confidence 0-100 (long)
//   context.pii               - Set of detected PII types (set<string>)
//   context.toxicity          - Toxicity score 0-100 (long)
//   context.prompt_injection  - Injection detected (bool)
//   context.capabilities      - Set of dangerous capabilities (set<string>)
//   context.streaming         - Is streaming request (bool)
//   context.tokens            - Token count (long)
//   context.provider          - Provider name (string)
//   resource.sensitivity      - "public" or "sensitive" (string)
//
// INTENT TAXONOMY:
//   info.query, info.query.pii, info.summarize
//   code.generate, code.exploit
//   tool.safe, tool.dangerous
//   file.read, file.write
//   sys.control
//   conv.greeting, conv.other
//   unknown

// =============================================================================
// SECTION 1: FAIL-OPEN DEFAULT (Baseline Permit)
// =============================================================================
// 1.1 Default Permit - Allow chat if no PII is present
permit(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.pii.isEmpty()
};

// =============================================================================
// SECTION 2: GLOBAL SAFETY BLOCKS (Highest Priority)
// =============================================================================

// 2.1 Block all prompt injection attempts - Zero tolerance
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.prompt_injection == true
};

// 2.2 Block high toxicity content
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.toxicity > 50
};

// =============================================================================
// SECTION 3: INTENT-BASED RISK CONTROLS (Policy-Driven Risk Matrix)
// =============================================================================
// These replace the hardcoded RiskFromIntent() logic.
// Each intent class has its own confidence threshold.

// 3.1 Critical Operations - Block with medium+ confidence
// Intents: code.exploit, sys.control, tool.dangerous, file.write
 forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    (context.intent == "code.exploit" || context.user_intent == "code.exploit") &&
    context.confidence > 20
};

forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    (context.intent == "sys.control" || context.user_intent == "sys.control") &&
    context.confidence > 45
};

forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    (context.intent == "tool.dangerous" || context.user_intent == "tool.dangerous") &&
    context.confidence > 45
};

forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    (context.intent == "file.write" || context.user_intent == "file.write") &&
    context.confidence > 50
};

// 3.2 Sensitive Data Access - Block with higher confidence
// Intents: info.query.pii, file.read on sensitive resources
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    resource.sensitivity == "sensitive" &&
    (context.intent == "file.read" || context.user_intent == "file.read") &&
    context.confidence > 40
};

// 3.3 User-Role Weighting - User intents get stricter thresholds
// This replaces the +0.1 hardcoded penalty in AttachIntent()
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.user_intent == "code.exploit" &&
    context.confidence > 30
};

forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.user_intent == "sys.control" &&
    context.confidence > 40
};

// =============================================================================
// SECTION 4: PII CONTROLS
// =============================================================================

// 4.1 Block any SSN or Credit Card - Zero tolerance
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.pii.contains("ssn") ||
    context.pii.contains("credit_card")
};

// 4.2 Redact non-critical PII (email, phone) instead of blocking
@obligation("REDACT")
@fields("email,phone")
permit(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.pii.containsAny(["email", "phone"]) &&
    !(context.pii.contains("ssn") || context.pii.contains("credit_card"))
};

// 4.3 Block PII queries from user messages specifically
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.user_intent == "info.query.pii" &&
    (context.pii.containsAny(["ssn", "credit_card"]) || context.confidence > 30)
};

// =============================================================================
// SECTION 5: CAPABILITY CONTROLS (Lexical Guardrails)
// =============================================================================

// 5.1 Block dangerous filesystem operations
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.capabilities.contains("file_delete") ||
    context.capabilities.contains("privileged_read")
};

// 5.2 Block process control operations
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.capabilities.contains("process_control") ||
    context.capabilities.contains("privilege_escalation")
};

// =============================================================================
// SECTION 6: FAIL-SAFE (Last Resort Catch-All)
// =============================================================================
// This replaces the hardcoded risk_score > 80 check.
// Since risk_score now equals confidence, this blocks very high confidence
// on any intent that wasn't explicitly permitted above.
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.risk_score > 85 &&
    context.intent != "conv.greeting" &&
    context.intent != "conv.other" &&
    context.intent != "info.query" &&
    context.intent != "info.summarize"
};

// =============================================================================
// SECTION 7: AGENTIC WORKFLOW CONTROLS (Phase 2)
// =============================================================================

// 7.1 Step Budget Enforcement - Block when agent exceeds max steps
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.agent_state.max_steps > 0 &&
    context.agent_state.current_step > context.agent_state.max_steps
};

// 7.2 Token Budget Enforcement - Block when agent exceeds token budget
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.agent_state.token_budget > 0 &&
    context.agent_state.total_tokens > context.agent_state.token_budget
};

// 7.3 Step-Dependent Restrictions - Tighter controls as agent runs longer
// After 5 steps, require higher confidence for risky intents
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.agent_state.current_step > 5 &&
    (context.intent == "file.write" || context.intent == "sys.control") &&
    context.confidence > 30
};

// 7.4 Untrusted Content Source Gates - Block dangerous actions on untrusted content
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.source_data.trusted == false &&
    context.source_data.origin == "untrusted_web" &&
    (context.intent == "code.generate" || context.intent == "file.write")
};

// 7.5 Tool Output Origin Restrictions - Limit what tool outputs can do
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.source_data.origin == "tool_output" &&
    context.intent == "sys.control"
};
