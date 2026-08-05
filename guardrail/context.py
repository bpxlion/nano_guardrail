from .types import EvaluationContext, ExecutionRecord, ToolCall, UserGoal


class ContextBuilder:
    def build(
        self,
        goal: UserGoal,
        tool_call: ToolCall,
        execution_history: list[ExecutionRecord],
    ) -> EvaluationContext:
        relevant_history = [
            record
            for record in execution_history
            if record.tool_call.goal_id == tool_call.goal_id
        ]
        return EvaluationContext(
            goal=goal,
            current_tool_call=tool_call,
            execution_history=relevant_history,
        )
