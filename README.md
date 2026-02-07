# Agent Guardrail

A transparent proxy layer that sits between your applications and LLM providers, applying configurable guardrails to prevent hallucinations, enforce policies, and ensure safe AI interactions.

![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-MIT-green)

## 🚀 Features

### Input Guardrails

- **Prompt Injection Detection** - Blocks attempts to manipulate LLM behavior through malicious prompts
- **PII Detection & Redaction** - Identifies and redacts email, phone, SSN, credit cards, and more
- **Topic Boundary Enforcement** - Restricts conversations to approved topics, blocks harmful content
- **Toxicity Filtering** - Detects and blocks toxic, abusive, or threatening language

### Output Guardrails

- **Hallucination Detection** - Flags potential hallucinations using heuristic analysis
- **Content Moderation** - Filters inappropriate content from responses
- **Format Validation** - Validates responses against JSON schemas

### Additional Features

- **Multi-Provider Support** - Route requests to OpenAI, Anthropic, Ollama, and more
- **YAML-based Policies** - Easy-to-configure policy files with hot-reload support
- **Request/Response Logging** - Complete audit trail with request IDs
- **Developer-Friendly** - Drop-in proxy with OpenAI-compatible API

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/blackrose-blackhat/agent-guardrail.git
cd agent-guardrail

# Install dependencies
go mod tidy

# Build
go build -o agent-guardrail ./backend/cmd/proxy
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Provider Configuration
PROVIDER_URL=http://localhost:11434  # Ollama, OpenAI, etc.
PROVIDER_KEY=your-api-key            # Optional for Ollama

# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8080

# Policy Configuration
POLICY_DIR=configs/policies
POLICY_DEFAULT_ID=default

# Logging
LOG_LEVEL=info
```

### Policy Configuration

Policies are defined in YAML files in the `configs/policies/` directory:

```yaml
# configs/policies/default.yaml
id: default
name: Default Security Policy
version: "1.0.0"

guardrails:
  input:
    prompt_injection:
      enabled: true
      sensitivity: medium # low, medium, high
      action: block

    pii_detection:
      enabled: true
      types: [email, phone, ssn, credit_card]
      action: redact

    topic_boundary:
      enabled: true
      blocked_topics: [violence, illegal_activity]
      action: block

    toxicity:
      enabled: true
      threshold: 0.7
      action: block

  output:
    hallucination_detection:
      enabled: true
      action: warn

    content_moderation:
      enabled: true
      categories: [hate, violence, self_harm]
      action: filter

actions:
  block:
    type: reject
    message: "Request blocked due to policy violation"
  redact:
    type: modify
  warn:
    type: pass
    add_warning: true
```

## 🚀 Usage

### Start the Proxy

```bash
# Run directly
go run backend/cmd/proxy/main.go

# Or use the built binary
./agent-guardrail
```

### Making Requests

Use the proxy just like you would use your LLM provider directly:

```bash
# Health check
curl http://localhost:8080/health

# Status check
curl http://localhost:8080/api/status

# Chat request (OpenAI-compatible)
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama2",
    "messages": [
      {"role": "user", "content": "Hello, how are you?"}
    ]
  }'

# Ollama-style chat request
curl -X POST http://localhost:8080/api/chat \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama2",
    "messages": [
      {"role": "user", "content": "Hello!"}
    ]
  }'
```

### Response Headers

The proxy adds custom headers to responses:

- `X-Guardrail-Request-ID` - Unique request identifier for auditing
- `X-Guardrail-Warnings` - Set to "true" if any warnings were generated
- `X-Guardrail-Blocked` - Set to "true" if request was blocked

### Blocked Response Format

When a request is blocked by guardrails:

```json
{
  "error": "guardrail_blocked",
  "code": "guardrail_blocked",
  "message": "Prompt injection attempt detected and blocked",
  "violations": [
    {
      "guardrail_name": "prompt_injection",
      "type": "prompt_injection",
      "message": "Potential prompt injection detected",
      "severity": "high",
      "action": "block"
    }
  ],
  "request_id": "abc123"
}
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Agent Guardrail Proxy                     │
├─────────────────────────────────────────────────────────────┤
│  Request In ──▶ Input Guardrails ──▶ Provider ──▶ Output   │
│                                                  Guardrails │
│                     │                                │      │
│                     ▼                                ▼      │
│              ┌───────────┐                    ┌───────────┐ │
│              │ • Prompt  │                    │ • Halluc. │ │
│              │   Inject. │                    │   Detect. │ │
│              │ • PII     │                    │ • Content │ │
│              │ • Topic   │                    │   Moder.  │ │
│              │ • Toxicity│                    │ • Format  │ │
│              └───────────┘                    └───────────┘ │
│                                                             │
│  Response Out ◀────────────────────────────────────────────│
└─────────────────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
agent-guardrail/
├── backend/
│   ├── cmd/
│   │   └── proxy/
│   │       └── main.go           # Entry point
│   └── internal/
│       ├── chain/                # Guardrail chain executor
│       │   ├── chain.go
│       │   └── context.go
│       ├── config/               # Configuration
│       │   └── config.go
│       ├── guardrails/
│       │   ├── input/            # Input guardrails
│       │   │   ├── prompt_injection.go
│       │   │   ├── pii_detection.go
│       │   │   ├── topic_boundary.go
│       │   │   └── toxicity.go
│       │   └── output/           # Output guardrails
│       │       ├── hallucination.go
│       │       ├── content_moderation.go
│       │       └── format_validation.go
│       ├── policy/               # Policy engine
│       │   ├── policy.go
│       │   └── loader.go
│       ├── provider/             # LLM providers
│       │   ├── provider.go
│       │   ├── ollama.go
│       │   ├── openai.go
│       │   └── router.go
│       └── proxy/                # HTTP handler
│           └── handler.go
├── configs/
│   └── policies/
│       └── default.yaml          # Default policy
├── go.mod
├── go.sum
└── README.md
```

The Agent Guardrail proxy is designed to be a "drop-in" replacement for any OpenAI-compatible client. Simply override the `base_url` to point to your proxy instance.

---

## 🤖 MCP Support (Model Context Protocol)

The system now acts as an **MCP Server**, allowing you to plug it directly into IDEs (like Cursor or Windsurf) and agents (like Claude Desktop).

### Why use MCP?

Instead of just being a proxy, the guardrail system becomes a **Tool** that agents can call to:

- Verify if their own planned response is safe.
- Inspect the current security policies.
- Audit a user's prompt before processing.

### Setup for Claude Desktop

Add this to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "agent-guardrail": {
      "command": "go",
      "args": ["run", "backend/cmd/mcp/main.go"],
      "cwd": "/absolute/path/to/agent-guardrail"
    }
  }
}
```

### Available Tools

- `check_prompt`: Validates any string against input guardrails (PII, Injection, etc.).
- `check_response`: Validates any string against output guardrails (Hallucinations, etc.).

---

## 🔌 Integrating with Your Application

### Python (OpenAI SDK)

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/v1",
    api_key="your-key"  # Passed to the provider
)

response = client.chat.completions.create(
    model="llama3",
    messages=[{"role": "user", "content": "Hello!"}]
)
```

### TypeScript (Vercel AI SDK)

```typescript
import { createOpenAI } from "@ai-sdk/openai";
import { generateText } from "ai";

const internalProxy = createOpenAI({
  baseURL: "http://localhost:8080/v1",
  apiKey: "proxy-key",
});

const { text } = await generateText({
  model: internalProxy("gpt-4o"),
  prompt: "Write a poem about safety.",
});
```

### LangChain (Python)

```python
from langchain_openai import ChatOpenAI

model = ChatOpenAI(
    base_url="http://localhost:8080/v1",
    api_key="anything",
    model="llama3"
)

model.invoke("Who are you?")
```

---

## ❓ FAQ

### 1. Is it provider independent?

**Yes.** The system uses an internal normalization layer. You can send OpenAI-formatted requests to the proxy, and it can translate and route them to **Ollama**, **Anthropic**, **Gemini**, or any **OpenAI-compatible** API.

### 2. How are "attacks" defined?

Attacks are defined using a multi-layer approach:

- **Deterministic Controls**: Hard limits (Rate limits, Payload size) with 0% false positives.
- **Risk Signals**: Heuristic detection (Regex, Keywords) that flag _potential_ issues like PII or Injection.
- **Policy Engine**: You decide which signals constitute a violation in your YAML config.

### 3. What if an attack bypasses the Regex?

Regex is our "First Line of Defense" for speed. For more creative attacks, the architecture supports **LLM-as-a-Judge** (Semantic Detection). You can plug in a specialized safety model to check the user's _intent_ rather than just their _words_.

### 4. Can it handle streaming?

Yes. The proxy is designed to support Server-Sent Events (SSE) for streaming responses, allowing you to intercept and block streaming output if it violates policy mid-sentence.

### 5. Why use this instead of native provider safety tools?

- **Unified Policy**: Apply the same rules across 10 different providers.
- **Privacy**: Redact PII _before_ it leaves your internal network.
- **Operational Control**: Enforce your own rate limits and circuit breakers independent of the provider's limits.
- **Intellectual Honesty**: Get transparent signals and audit trails for every block.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Agent Guardrail Proxy                     │
├─────────────────────────────────────────────────────────────┤
│  Request In ──▶ Input Guardrails ──▶ Provider ──▶ Output   │
│                                                  Guardrails │
│                     │                                │      │
│                     ▼                                ▼      │
│              ┌───────────┐                    ┌───────────┐ │
│              │ • Prompt  │                    │ • Halluc. │ │
│              │   Inject. │                    │   Detect. │ │
│              │ • PII     │                    │ • Content │ │
│              │ • Topic   │                    │   Moder.  │ │
│              │ • Toxicity│                    │ • Format  │ │
│              └───────────┘                    └───────────┘ │
│                                                             │
│  Response Out ◀────────────────────────────────────────────│
└─────────────────────────────────────────────────────────────┘
```

## 🛡️ Security Considerations

- The proxy does not store API keys - they are passed through to providers
- Consider running behind a reverse proxy (nginx, traefik) in production
- Enable TLS/HTTPS for production deployments
- Review and customize policies for your specific use case

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## 📞 Support

- GitHub Issues: For bug reports and feature requests
- Discussions: For questions and community support
