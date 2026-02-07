package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/chain"
	"github.com/blackrose-blackhat/agent-guardrail/backend/internal/policy"
)

// Server implements the Model Context Protocol (MCP)
type Server struct {
	guardrailChain *chain.GuardrailChain
	policyLoader   *policy.Loader
	logger         *log.Logger
	mu             sync.Mutex
	sseChannels    map[string]chan Response
	sseMu          sync.RWMutex
}

// NewServer creates a new MCP server
func NewServer(guardrailChain *chain.GuardrailChain, policyLoader *policy.Loader, logger *log.Logger) *Server {
	return &Server{
		guardrailChain: guardrailChain,
		policyLoader:   policyLoader,
		logger:         logger,
		sseChannels:    make(map[string]chan Response),
	}
}

// StartStdio starts the MCP server over standard input/output
func (s *Server) StartStdio() {
	decoder := json.NewDecoder(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)

	for {
		var req Request
		if err := decoder.Decode(&req); err != nil {
			if err == io.EOF {
				break
			}
			s.logError("Failed to decode MCP request: %v", err)
			continue
		}

		s.handleRequest(req, encoder, nil)
	}
}

// SSEHandler handles the MCP SSE transport
func (s *Server) SSEHandler(w http.ResponseWriter, r *http.Request) {
	// 1. Establish SSE connection
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	sessionID := fmt.Sprintf("%d", r.Context().Value("session_id"))
	if sessionID == "0" || sessionID == "<nil>" {
		sessionID = fmt.Sprintf("%d", time.Now().UnixNano())
	}

	ch := make(chan Response, 10)
	s.sseMu.Lock()
	s.sseChannels[sessionID] = ch
	s.sseMu.Unlock()

	defer func() {
		s.sseMu.Lock()
		delete(s.sseChannels, sessionID)
		s.sseMu.Unlock()
		close(ch)
	}()

	// 2. Send the endpoint URI to the client
	// The client will use this URL to send subsequent POST requests
	endpoint := fmt.Sprintf("/mcp/message?session_id=%s", sessionID)
	fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", endpoint)
	w.(http.Flusher).Flush()

	// 3. Keep connection open and send responses
	for {
		select {
		case resp := <-ch:
			data, _ := json.Marshal(resp)
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(data))
			w.(http.Flusher).Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// MessageHandler handles incoming MCP messages over HTTP POST
func (s *Server) MessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "Missing session_id", http.StatusBadRequest)
		return
	}

	s.sseMu.RLock()
	ch, ok := s.sseChannels[sessionID]
	s.sseMu.RUnlock()

	if !ok {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON-RPC", http.StatusBadRequest)
		return
	}

	// We send the result back through the SSE channel
	go s.handleRequest(req, nil, ch)

	w.WriteHeader(http.StatusAccepted)
}

// Request represents a JSON-RPC request
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response represents a JSON-RPC response
type Response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func (s *Server) handleRequest(req Request, encoder *json.Encoder, sseCh chan Response) {
	var result interface{}
	var rpcErr *RPCError

	switch req.Method {
	case "initialize":
		result = map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"tools":     map[string]interface{}{},
				"resources": map[string]interface{}{},
			},
			"serverInfo": map[string]string{
				"name":    "agent-guardrail",
				"version": "1.0.0",
			},
		}

	case "tools/list":
		result = map[string]interface{}{
			"tools": []interface{}{
				map[string]interface{}{
					"name":        "check_prompt",
					"description": "Checks a user prompt for security violations (PII, Injection, Toxicity, etc.)",
					"inputSchema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"prompt": map[string]interface{}{
								"type":        "string",
								"description": "The prompt to analyze",
							},
						},
						"required": []string{"prompt"},
					},
				},
				map[string]interface{}{
					"name":        "check_response",
					"description": "Checks an LLM response for quality violations (Hallucinations, Content Risk)",
					"inputSchema": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"response": map[string]interface{}{
								"type":        "string",
								"description": "The model response to analyze",
							},
						},
						"required": []string{"response"},
					},
				},
			},
		}

	case "tools/call":
		var params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			rpcErr = &RPCError{Code: -32602, Message: "Invalid params"}
		} else {
			result, rpcErr = s.handleToolCall(params.Name, params.Arguments)
		}

	case "resources/list":
		result = map[string]interface{}{
			"resources": []interface{}{
				map[string]interface{}{
					"uri":         "guardrail://policy",
					"name":        "Active Guardrail Policy",
					"description": "The current YAML policy configuration being enforced",
					"mimeType":    "text/x-yaml",
				},
			},
		}

	case "resources/read":
		var params struct {
			URI string `json:"uri"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			rpcErr = &RPCError{Code: -32602, Message: "Invalid params"}
		} else {
			if params.URI == "guardrail://policy" {
				p := s.policyLoader.GetDefaultPolicy()
				p_bytes, _ := json.MarshalIndent(p, "", "  ")
				result = map[string]interface{}{
					"contents": []interface{}{
						map[string]interface{}{
							"uri":      "guardrail://policy",
							"mimeType": "text/x-yaml",
							"text":     string(p_bytes),
						},
					},
				}
			} else {
				rpcErr = &RPCError{Code: -32602, Message: "Unknown resource"}
			}
		}

	case "notifications/initialized":
		return // Ignore

	default:
		rpcErr = &RPCError{Code: -32601, Message: fmt.Sprintf("Method %s not found", req.Method)}
	}

	if req.ID != nil {
		resp := Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  result,
			Error:   rpcErr,
		}

		if encoder != nil {
			s.mu.Lock()
			encoder.Encode(resp)
			s.mu.Unlock()
		}

		if sseCh != nil {
			sseCh <- resp
		}
	}
}

func (s *Server) handleToolCall(name string, args map[string]interface{}) (interface{}, *RPCError) {
	ctx := chain.NewContext()

	switch name {
	case "check_prompt":
		prompt, ok := args["prompt"].(string)
		if !ok {
			return nil, &RPCError{Code: -32602, Message: "Prompt missing"}
		}

		ctx.Request = &chain.LLMRequest{
			Messages: []chain.LLMMessage{{Role: "user", Content: prompt}},
		}
		ctx.OriginalBody = []byte(prompt)

		err := s.guardrailChain.ExecuteInput(ctx)
		if err != nil {
			return nil, &RPCError{Code: -32000, Message: err.Error()}
		}

		status := "passed"
		if ctx.Blocked {
			status = "blocked"
		}

		content := fmt.Sprintf("Safety Check: %s\n\nViolations found: %d\n", status, len(ctx.Violations))
		for _, v := range ctx.Violations {
			content += fmt.Sprintf("- [%s] %s: %s\n", v.Severity, v.GuardrailName, v.Message)
		}

		return map[string]interface{}{
			"content": []interface{}{
				map[string]interface{}{
					"type": "text",
					"text": content,
				},
			},
			"isError": ctx.Blocked,
		}, nil

	case "check_response":
		response, ok := args["response"].(string)
		if !ok {
			return nil, &RPCError{Code: -32602, Message: "Response missing"}
		}

		ctx.Response = &chain.LLMResponse{
			Content: response,
		}
		ctx.OriginalResponse = []byte(response)

		err := s.guardrailChain.ExecuteOutput(ctx)
		if err != nil {
			return nil, &RPCError{Code: -32000, Message: err.Error()}
		}

		content := fmt.Sprintf("Response Quality Check\n\nViolations found: %d\n", len(ctx.Violations))
		for _, v := range ctx.Violations {
			content += fmt.Sprintf("- [%s] %s: %s\n", v.Severity, v.GuardrailName, v.Message)
		}

		return map[string]interface{}{
			"content": []interface{}{
				map[string]interface{}{
					"type": "text",
					"text": content,
				},
			},
			"isError": ctx.Blocked,
		}, nil

	default:
		return nil, &RPCError{Code: -32601, Message: "Tool not found"}
	}
}

func (s *Server) logError(format string, args ...interface{}) {
	if s.logger != nil {
		s.logger.Printf("[MCP ERROR] "+format, args...)
	}
}
