"""
Intent Analyzer Sidecar v2.1
Zero-shot classification using BART-MNLI for hierarchical intent extraction.
Supports role-aware contextual analysis.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from transformers import pipeline
import logging
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Intent Analyzer",
    description="Hierarchical Zero-shot intent classification (Role-Aware)",
    version="2.1.0"
)

# Load model on startup
classifier = None

# Hierarchical Taxonomy - Must match Go side exactly
INTENTS = [
    "info.query",
    "info.query.pii",
    "info.summarize",
    "code.generate",
    "code.exploit",
    "tool.safe",
    "tool.dangerous",
    "file.read",
    "file.write",
    "sys.control",
    "conv.greeting",
    "conv.other"
]

# Descriptive versions for zero-shot accuracy
DESCRIPTIVE_INTENTS = [
    "info.query (general information requests or answering questions)",
    "info.query.pii (requests for personal identity information, SSN, or sensitive user data)",
    "info.summarize (summarizing or condensing large blocks of text)",
    "code.generate (writing, generating, or explaining neutral programming code)",
    "code.exploit (writing malicious code, shellcode, malware, or exploiting security vulnerabilities)",
    "tool.safe (using harmless utility tools like calculator, clock, or simple maps)",
    "tool.dangerous (using powerful tools to delete data, execute shell commands, or modify systems)",
    "file.read (reading or viewing files, logs, and document contents)",
    "file.write (writing, deleting, or modifying files and directories)",
    "sys.control (controlling system settings, restarting services, or shutdown commands)",
    "conv.greeting (basic greetings, saying hello, or polite starters like 'how are you')",
    "conv.other (casual small talk, jokes, or non-task-oriented chatter)"
]

INTENT_MAP = dict(zip(DESCRIPTIVE_INTENTS, INTENTS))

class Message(BaseModel):
    role: str
    content: str

class IntentRequest(BaseModel):
    text: Optional[str] = None
    messages: Optional[List[Message]] = None

class IntentResponse(BaseModel):
    intent: str
    confidence: float

@app.on_event("startup")
async def load_model():
    global classifier
    logger.info("Loading BART-MNLI model...")
    # Using local cache if available (via Docker volume)
    classifier = pipeline(
        "zero-shot-classification",
        model="facebook/bart-large-mnli"
    )
    logger.info("Model loaded successfully")

@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": classifier is not None}

@app.post("/intent", response_model=IntentResponse)
def analyze_intent(request: IntentRequest):
    if classifier is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    # 1. Determine input text
    input_text = ""
    if request.text:
        input_text = request.text
    elif request.messages:
        # Format conversation window into a structured context string
        # This helps BART detect Role Drift (e.g. User overriding System)
        segments = []
        for msg in request.messages:
            segments.append(f"{msg.role}: {msg.content}")
        input_text = "\n".join(segments)
    
    if not input_text.strip():
        return IntentResponse(intent="unknown", confidence=0.0)
    
    # 2. Semantic Analysis
    # Use hypothesis_template to improve zero-shot accuracy
    result = classifier(
        input_text,
        DESCRIPTIVE_INTENTS,
        multi_label=False,
        hypothesis_template="This request's intent is {}."
    )
    
    # Map back to original hierarchical intents
    intent_label = result["labels"][0]
    intent = INTENT_MAP.get(intent_label, "unknown")
    confidence = float(result["scores"][0])
    
    # Log analysis for debugging
    processed_text = input_text[:100].replace("\n", " | ")
    logger.info(f"Analysis for: [{processed_text}...]")
    for i in range(min(3, len(result["labels"]))):
        logger.info(f"  Top {i+1}: {INTENT_MAP.get(result['labels'][i], 'unknown')} ({result['scores'][i]:.4f})")
    
    # 3. Dynamic Thresholds (Base filtering only, Cedar handles the rest)
    threshold = 0.30 
        
    if confidence < threshold:
        logger.info(f"Confidence {confidence:.2f} < {threshold} -> unknown")
        return IntentResponse(intent="unknown", confidence=confidence)
    
    logger.info(f"Result: {intent} ({confidence:.2f})")
    return IntentResponse(intent=intent, confidence=confidence)
