# Agent Guardrail — Security Model

## Overview

Agent Guardrail is a **Zero-Trust AI Control Plane** that sits between clients and LLM providers, enforcing security policies on every request.

---

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│ UNTRUSTED ZONE                                              │
│   • User prompts                                            │
│   • LLM responses                                           │
│   • External API calls                                      │
└──────────────────────────┬──────────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │  GUARDRAIL  │  ← Enforcement Boundary
                    │    PROXY    │
                    └──────┬──────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│ TRUSTED ZONE                                                │
│   • Cedar Policy Engine (sole decision authority)           │
│   • Deterministic signals (PII, Injection, Toxicity)        │
│   • Capability scanner (lexical guardrails)                 │
└─────────────────────────────────────────────────────────────┘
```

---

## Security Guarantees

| Guarantee | Implementation |
|-----------|----------------|
| **Fail-Closed** | Any error → `403 Forbidden`. No silent pass-through. |
| **Pre-Stream Block** | Cedar runs ONCE before any SSE tokens are forwarded. |
| **Policy-Only Decisions** | Cedar is the sole authority. No in-line logic. |
| **Write-Once Context** | Intent/risk cannot be overwritten after first classification. |
| **Deterministic Signals** | PII, Injection, Toxicity, Capabilities use regex — no ML drift. |
| **Provider-Agnostic** | Works with Ollama, OpenAI, Claude, Gemini, or any OpenAI-compatible API. |

---

## Non-Goals

This system **does not**:

- ❌ Make risk decisions based on LLM outputs
- ❌ Allow heuristic "smart" allow rules
- ❌ Perform content moderation on responses
- ❌ Act as an LLM-as-judge
- ❌ Support mutable policies at runtime

---

## Known Limitations

| Limitation | Mitigation |
|------------|------------|
| Semantic intent can misclassify ambiguous prompts | Capability Layer (lexical) catches destructive keywords |
| BART model has ~300ms latency per request | MiniLM drop-in available for lower latency |
| Policy changes require proxy restart | Policy versioning header for audit trail |
| No response-side guardrails | Out of scope for v1 (request-side only) |

---

## Attack Surface

| Vector | Defense |
|--------|---------|
| Prompt Injection | InjectionDetector (regex patterns) |
| PII Exfiltration | PIIDetector (SSN, credit card, email, phone) |
| Toxic Content | ToxicityDetector (keyword scoring) |
| Destructive Operations | CapabilityScanner (rm, kill, sudo, /etc/*) |
| Semantic Bypass | IntentAnalyzer (BART zero-shot) + high-risk threshold |

---

## Audit Trail Headers

Every response includes:

| Header | Purpose |
|--------|---------|
| `X-Guardrail-Request-ID` | Unique request identifier |
| `X-Guardrail-PreStream-Enforced` | Confirms Cedar ran before streaming |
| `X-Guardrail-Policy-Version` | SHA256 hash of active policy file |
| `X-Guardrail-Blocked` | Present if request was denied |

---

## Policy Authority

Cedar policies are the **only** source of allow/deny decisions.

- Signals (PII, Intent, Toxicity) are **inputs** to Cedar
- Cedar evaluates **all signals together**
- No signal alone can allow or deny a request

This separation ensures **auditability** and **determinism**.
