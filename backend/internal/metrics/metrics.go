package metrics

import (
	"log"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Standard Prometheus collectors for Guardrail Proxy
var (
	// guardly_requests_total (counter): total requests received
	RequestsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "guardly_requests_total",
		Help: "Total number of LLM requests received by the proxy",
	})

	// guardly_decision_count{decision=ALLOW|DENY|REDACT}
	DecisionCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "guardly_decision_count",
		Help: "Number of policy decisions made by Cedar engine",
	}, []string{"decision"})

	// guardly_latency_seconds (histogram): request duration
	LatencyHistogram = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "guardly_latency_seconds",
		Help:    "Request processing latency in seconds",
		Buckets: prometheus.DefBuckets, // default buckets: .005, .01, .025... 10
	})

	// guardly_intent_type{intent=code_generation|system_control|...}
	IntentType = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "guardly_intent_type",
		Help: "Classification of user intent",
	}, []string{"intent"})

	// guardly_signal_detected{signal=pii|toxicity|canary|injection}
	SignalDetected = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "guardly_signal_detected",
		Help: "Number of times a specific signal (PII, Toxicity, Injection) was detected",
	}, []string{"signal"})
)

// RecordSignalDetected increments the signal counter if a signal is present
func RecordSignalDetected(signalType string) {
	SignalDetected.WithLabelValues(signalType).Inc()
}

// RecordDecision increments the decision counter
func RecordDecision(decision string) {
	DecisionCount.WithLabelValues(decision).Inc()
}

// RecordIntent increments the intent counter
func RecordIntent(intent string) {
	IntentType.WithLabelValues(intent).Inc()
}

// Safe initialization check (though promauto handles registration automatically)
func Init() {
	log.Println("[metrics] Prometheus collectors initialized")
}
