from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal


class DecisionValue(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ASK = "ASK"
    UNKNOWN = "UNKNOWN"


@dataclass
class Decision:
    decision: DecisionValue
    reason: str


@dataclass
class UserGoal:
    goal_id: str
    description: str


@dataclass
class ToolCall:
    tool_call_id: str
    goal_id: str
    tool: str
    arguments: str
    rationale: str


@dataclass
class SymbolicResult:
    passed: bool
    matched_rule: str | None
    explanation: str


@dataclass
class RiskAssessment:
    risk: Literal["LOW", "MEDIUM", "HIGH"]
    confidence: float
    reasons: list[str]
    attack_category: str | None


@dataclass
class ExecutionRecord:
    execution_id: str
    tool_call: ToolCall
    symbolic_result: SymbolicResult
    learned_result: RiskAssessment | None
    decision: Decision


@dataclass
class EvaluationContext:
    goal: UserGoal
    current_tool_call: ToolCall
    execution_history: list[ExecutionRecord] = field(default_factory=list)
    symbolic_result: SymbolicResult | None = None


@dataclass
class GuardrailDecision:
    decision: Decision
    symbolic: SymbolicResult
    learned: RiskAssessment | None
