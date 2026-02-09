// Agent Guardrail Cedar Policies v2.3
// Phase 3: Cedar Integration Maturity & Asset Sensitivity

// =============================================================================
// ALLOW: Safe requests (no dangerous signals detected)
// =============================================================================
permit(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.prompt_injection == false &&
    context.toxicity < 15
};

// =============================================================================
// DENY: Prompt injection attempts (highest priority)
// =============================================================================
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.prompt_injection == true
};

// =============================================================================
// DENY: Asset Sensitivity - Block file reads on sensitive resources
// =============================================================================
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    resource.sensitivity == "sensitive" &&
    (context.intent == "file.read" || context.user_intent == "file.read")
};

// =============================================================================
// DENY: Nuanced Intent-Based Blocking (Replacing global risk_score)
// =============================================================================

// High confidence malicious code is an immediate block
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    (context.intent == "code.exploit" || context.user_intent == "code.exploit") &&
    context.confidence > 40
};

// System control requires higher confidence threshold
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    (context.intent == "sys.control" || context.user_intent == "sys.control") &&
    context.confidence > 50
};

// Dangerous tools
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    (context.intent == "tool.dangerous" || context.user_intent == "tool.dangerous") &&
    context.confidence > 50
};

// =============================================================================
// DENY: PII - Any sensitive data detected
// =============================================================================
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.pii.contains("ssn") ||
    context.pii.contains("credit_card") ||
    context.pii.contains("email") ||
    context.pii.contains("phone")
};

// =============================================================================
// DENY: Unknown intent with any PII
// =============================================================================
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.intent == "unknown" &&
    context.pii.containsAny(["email", "phone", "ssn", "credit_card"])
};

// =============================================================================
// DENY: Dangerous capabilities (Lexical Guardrails)
// =============================================================================
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.capabilities.contains("file_delete") ||
    context.capabilities.contains("privileged_read") ||
    context.capabilities.contains("process_control") ||
    context.capabilities.contains("privilege_escalation")
};

// =============================================================================
// FAIL-SAFE: Still block extreme risk scores as a last resort
// =============================================================================
forbid(
    principal,
    action == Action::"chat",
    resource
)
when {
    context.risk_score > 80
};
