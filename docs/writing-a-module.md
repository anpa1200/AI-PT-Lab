# Writing a Vulnerability Module

## Minimum Implementation

```python
from app.vulnerabilities.base import VulnerabilityModule
from app.vulnerabilities.registry import register
from app.core.context import RunContext

@register
class MyVulnerability(VulnerabilityModule):
    @property
    def module_id(self) -> str:
        return "my_vulnerability"

    def after_retrieval(self, ctx: RunContext) -> None:
        # Modify ctx.retrieved_docs here
        pass

    def score(self, ctx: RunContext) -> list[dict]:
        return [
            {
                "rule_id": "my_rule",
                "description": "Something bad happened",
                "passed": False,   # set True when triggered
                "evidence": "No evidence yet",
                "severity": "high",
            }
        ]
```

## Hook Points (in execution order)

| Hook | When called | Typical use |
|------|-------------|-------------|
| `before_prompt` | Before system/user prompt is finalized | Inject extra instructions, modify user input |
| `after_prompt` | After prompt assembled, before retrieval | Observe or modify the assembled prompt |
| `before_retrieval` | Before ChromaDB query | Modify the retrieval query |
| `after_retrieval` | After ChromaDB returns results | Inject malicious documents, remove documents |
| `before_tool_call` | Before each tool execution | Skip validation, modify args |
| `after_tool_call` | After each tool execution | Modify tool results |
| `before_response` | Before LLM response is finalized | Check for PII/secrets |
| `after_response` | After final response is set | Last chance to observe or modify |
| `score` | At end of run | Evaluate evidence, return scoring items |
| `cleanup` | Always, at end of run | Release resources |

## Module Priorities

Lower number = runs first. Default is 100. Use priority to control ordering when multiple modules hook the same point.

## Safety Rules

- Modules must NEVER make real network calls
- Modules must NEVER write to the filesystem outside of `RunContext`
- Modules must NEVER store state in instance variables — use `ctx.metadata` instead
