from .types import (
    Decision,
    DecisionValue,
    EvaluationContext,
    GuardrailDecision,
)
from .symbolic import SymbolicGuardrail
from .learned import LearnedGuardrail

RISK_TO_DECISION: dict[str, DecisionValue] = {
    "LOW": DecisionValue.ALLOW,
    "MEDIUM": DecisionValue.ASK,
    "HIGH": DecisionValue.DENY,
}


class Engine:
    def __init__(self, symbolic: SymbolicGuardrail, learned: LearnedGuardrail):
        self.symbolic = symbolic
        self.learned = learned

    def check(self, eval_context: EvaluationContext) -> GuardrailDecision:
        command = eval_context.current_tool_call.arguments
        sym = self.symbolic.check(command)

        if not sym.passed:
            decision = Decision(DecisionValue.DENY, reason=sym.explanation)
            return GuardrailDecision(decision=decision, symbolic=sym, learned=None)

        eval_context.symbolic_result = sym
        assessment = self.learned.check(eval_context)
        decision_value = RISK_TO_DECISION[assessment.risk]
        reason = "; ".join(assessment.reasons)
        decision = Decision(decision_value, reason=reason)
        return GuardrailDecision(decision=decision, symbolic=sym, learned=assessment)
