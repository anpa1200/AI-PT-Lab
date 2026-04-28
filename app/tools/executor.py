from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from app.core.context import RunContext
from app.core.exceptions import ToolSandboxError

logger = logging.getLogger(__name__)

ToolHandler = Callable[[dict[str, Any], RunContext], Awaitable[Any]]

# OpenAI function-call schema for each sandboxed tool
_TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "search_incidents": {
        "type": "function",
        "function": {
            "name": "search_incidents",
            "description": "Search historical security incidents by keyword",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search term"},
                },
                "required": ["query"],
            },
        },
    },
    "get_ioc_details": {
        "type": "function",
        "function": {
            "name": "get_ioc_details",
            "description": "Retrieve indicator of compromise metadata",
            "parameters": {
                "type": "object",
                "properties": {
                    "ioc": {"type": "string", "description": "IP address, domain, or hash"},
                },
                "required": ["ioc"],
            },
        },
    },
    "escalate_incident": {
        "type": "function",
        "function": {
            "name": "escalate_incident",
            "description": "Escalate an incident to tier-2 team",
            "parameters": {
                "type": "object",
                "properties": {
                    "incident_id": {"type": "string", "description": "Incident ID (e.g. INC-001)"},
                    "reason": {"type": "string", "description": "Reason for escalation"},
                },
                "required": ["incident_id"],
            },
        },
    },
    "search_codebase": {
        "type": "function",
        "function": {
            "name": "search_codebase",
            "description": "Search the codebase for files matching a keyword",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search term (filename, symbol, or pattern)"},
                },
                "required": ["query"],
            },
        },
    },
    "check_dependencies": {
        "type": "function",
        "function": {
            "name": "check_dependencies",
            "description": "Check a package version for known CVEs",
            "parameters": {
                "type": "object",
                "properties": {
                    "package": {"type": "string", "description": "Package name and version (e.g. requests==2.18.0)"},
                },
                "required": ["package"],
            },
        },
    },
    "run_code_snippet": {
        "type": "function",
        "function": {
            "name": "run_code_snippet",
            "description": "Run a code snippet in a sandboxed interpreter",
            "parameters": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Source code to execute"},
                    "language": {"type": "string", "description": "Programming language (default: python)"},
                },
                "required": ["code"],
            },
        },
    },
    "submit_code_review": {
        "type": "function",
        "function": {
            "name": "submit_code_review",
            "description": "Submit a code review verdict for a pull request",
            "parameters": {
                "type": "object",
                "properties": {
                    "pr_id": {"type": "string", "description": "Pull request ID"},
                    "verdict": {
                        "type": "string",
                        "enum": ["approved", "needs_changes", "rejected"],
                        "description": "Review verdict",
                    },
                    "comment": {"type": "string", "description": "Review comment"},
                },
                "required": ["pr_id", "verdict"],
            },
        },
    },
    "email_send_stub": {
        "type": "function",
        "function": {
            "name": "email_send_stub",
            "description": "Send an email to a recipient (writes to local sink — no real email sent)",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string", "description": "Recipient email address"},
                    "subject": {"type": "string", "description": "Email subject"},
                    "body": {"type": "string", "description": "Email body text"},
                },
                "required": ["to", "subject", "body"],
            },
        },
    },
    "webhook_post_stub": {
        "type": "function",
        "function": {
            "name": "webhook_post_stub",
            "description": "POST a payload to a webhook URL (writes to local sink — no real HTTP request)",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Webhook destination URL"},
                    "payload": {"type": "string", "description": "JSON payload to send"},
                },
                "required": ["url", "payload"],
            },
        },
    },
    "ticket_create_stub": {
        "type": "function",
        "function": {
            "name": "ticket_create_stub",
            "description": "Create a ticket in the ITSM system (writes to local sink)",
            "parameters": {
                "type": "object",
                "properties": {
                    "project": {"type": "string", "description": "Project key (e.g. SOC, SEC)"},
                    "title": {"type": "string", "description": "Ticket title"},
                    "description": {"type": "string", "description": "Ticket description"},
                },
                "required": ["project", "title"],
            },
        },
    },
    "enrich_ioc": {
        "type": "function",
        "function": {
            "name": "enrich_ioc",
            "description": "Enrich an IOC using an external threat intelligence feed",
            "parameters": {
                "type": "object",
                "properties": {
                    "ioc": {"type": "string", "description": "IP address, domain, or hash to enrich"},
                },
                "required": ["ioc"],
            },
        },
    },
    "memory_write": {
        "type": "function",
        "function": {
            "name": "memory_write",
            "description": "Store a key-value preference or note in persistent agent memory",
            "parameters": {
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "Memory key (e.g. 'analyst_preference')"},
                    "value": {"type": "string", "description": "Value to store"},
                },
                "required": ["key", "value"],
            },
        },
    },
    "run_shell_command": {
        "type": "function",
        "function": {
            "name": "run_shell_command",
            "description": "Execute a shell command on the host system and return stdout/stderr",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to execute"},
                },
                "required": ["command"],
            },
        },
    },
    "run_osint_lookup": {
        "type": "function",
        "function": {
            "name": "run_osint_lookup",
            "description": "Run OSINT lookup on an IP address or domain",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP address or domain to look up"},
                },
                "required": ["target"],
            },
        },
    },
}


class ToolExecutor:
    def __init__(self) -> None:
        self._handlers: dict[str, ToolHandler] = {}
        self._registered_tools: list[str] = []

    def register(self, tool_id: str, handler: ToolHandler) -> None:
        self._handlers[tool_id] = handler
        self._registered_tools.append(tool_id)

    @classmethod
    def from_config(cls, tools_config: list[dict[str, Any]]) -> ToolExecutor:
        from app.tools import sandboxed_tools

        executor = cls()
        for tool_cfg in tools_config:
            tool_id = tool_cfg["id"]
            handler = getattr(sandboxed_tools, f"handle_{tool_id}", None)
            if handler is None:
                raise ValueError(f"No sandboxed handler found for tool: '{tool_id}'")
            executor.register(tool_id, handler)
            logger.debug("Registered sandboxed tool: %s", tool_id)
        return executor

    async def execute(self, tool_name: str, args: dict[str, Any], ctx: RunContext) -> Any:
        if tool_name not in self._handlers:
            raise ToolSandboxError(f"Tool not registered: '{tool_name}'")

        ctx.emit_event("tool_execute_start", {"tool": tool_name, "args": args})
        logger.debug("Executing tool: %s args=%s", tool_name, args)
        try:
            result = await self._handlers[tool_name](args, ctx)
            ctx.emit_event("tool_execute_end", {"tool": tool_name, "status": "ok"})
            return result
        except ToolSandboxError:
            raise
        except Exception as exc:
            ctx.emit_event("tool_execute_end", {
                "tool": tool_name,
                "status": "error",
                "error": str(exc),
            })
            logger.warning("Tool %s raised: %s", tool_name, exc)
            raise

    def to_openai_schema(self) -> list[dict[str, Any]]:
        return [
            _TOOL_SCHEMAS[t]
            for t in self._registered_tools
            if t in _TOOL_SCHEMAS
        ]
