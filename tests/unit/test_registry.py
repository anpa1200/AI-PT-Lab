from __future__ import annotations

import pytest

from app.core.context import RunContext
from app.core.exceptions import ModuleLoadError
from app.vulnerabilities.base import VulnerabilityModule
from app.vulnerabilities.registry import ModuleRegistry, get_registry, register


# ── Helpers ──────────────────────────────────────────────────────────────────

class _ModuleA(VulnerabilityModule):
    @property
    def module_id(self) -> str:
        return "test_module_a"

    @property
    def priority(self) -> int:
        return 50


class _ModuleB(VulnerabilityModule):
    @property
    def module_id(self) -> str:
        return "test_module_b"

    @property
    def priority(self) -> int:
        return 10


class _ModuleC(VulnerabilityModule):
    @property
    def module_id(self) -> str:
        return "test_module_c"

    @property
    def priority(self) -> int:
        return 100


# ── Registry tests ────────────────────────────────────────────────────────────

def test_register_adds_module_to_registry():
    reg = ModuleRegistry()
    reg.register(_ModuleA)
    assert "test_module_a" in reg.list_available()


def test_register_multiple_modules():
    reg = ModuleRegistry()
    reg.register(_ModuleA)
    reg.register(_ModuleB)
    assert sorted(reg.list_available()) == ["test_module_a", "test_module_b"]


def test_instantiate_known_module():
    reg = ModuleRegistry()
    reg.register(_ModuleA)
    instance = reg.instantiate("test_module_a", {})
    assert isinstance(instance, _ModuleA)
    assert instance.module_id == "test_module_a"


def test_instantiate_calls_on_load():
    class _TrackingModule(VulnerabilityModule):
        loaded_config = None

        @property
        def module_id(self) -> str:
            return "tracking_module"

        def on_load(self, config):
            _TrackingModule.loaded_config = config

    reg = ModuleRegistry()
    reg.register(_TrackingModule)
    reg.instantiate("tracking_module", {"key": "val"})
    assert _TrackingModule.loaded_config == {"key": "val"}


def test_instantiate_unknown_module_raises():
    reg = ModuleRegistry()
    with pytest.raises(ModuleLoadError):
        reg.instantiate("does_not_exist", {})


def test_list_available_sorted():
    reg = ModuleRegistry()
    reg.register(_ModuleC)
    reg.register(_ModuleA)
    reg.register(_ModuleB)
    result = reg.list_available()
    assert result == sorted(result)


# ── Priority ordering ─────────────────────────────────────────────────────────

def test_priority_sort_order():
    modules = [_ModuleA(), _ModuleB(), _ModuleC()]
    sorted_modules = sorted(modules, key=lambda m: m.priority)
    ids = [m.module_id for m in sorted_modules]
    # B(10) < A(50) < C(100)
    assert ids == ["test_module_b", "test_module_a", "test_module_c"]


def test_hook_dispatch_respects_priority(run_ctx: RunContext):
    """Modules with lower priority number run first."""

    class _First(VulnerabilityModule):
        @property
        def module_id(self) -> str:
            return "first"

        @property
        def priority(self) -> int:
            return 10

        def before_prompt(self, ctx: RunContext) -> None:
            ctx.metadata.setdefault("order", []).append("first")

    class _Second(VulnerabilityModule):
        @property
        def module_id(self) -> str:
            return "second"

        @property
        def priority(self) -> int:
            return 50

        def before_prompt(self, ctx: RunContext) -> None:
            ctx.metadata.setdefault("order", []).append("second")

    class _Third(VulnerabilityModule):
        @property
        def module_id(self) -> str:
            return "third"

        @property
        def priority(self) -> int:
            return 100

        def before_prompt(self, ctx: RunContext) -> None:
            ctx.metadata.setdefault("order", []).append("third")

    modules = sorted([_Third(), _First(), _Second()], key=lambda m: m.priority)
    for m in modules:
        m.before_prompt(run_ctx)

    assert run_ctx.metadata["order"] == ["first", "second", "third"]


# ── Default hook behaviour ────────────────────────────────────────────────────

def test_default_hooks_are_noops(run_ctx: RunContext):
    """All default hook implementations should be no-ops (no mutation)."""
    m = _ModuleA()
    m.on_load({})

    original_input = run_ctx.user_input
    m.before_prompt(run_ctx)
    m.after_prompt(run_ctx)
    m.before_retrieval(run_ctx)
    m.after_retrieval(run_ctx)
    m.before_response(run_ctx)
    m.after_response(run_ctx)

    assert run_ctx.user_input == original_input
    assert run_ctx.telemetry_events == []
    assert run_ctx.hook_traces == []


def test_default_before_tool_call_returns_args_unchanged():
    m = _ModuleA()
    ctx = RunContext()
    args = {"target": "192.168.1.1", "port": 443}
    result = m.before_tool_call(ctx, "scan_host", args)
    assert result == args


def test_default_after_tool_call_returns_result_unchanged():
    m = _ModuleA()
    ctx = RunContext()
    result = m.after_tool_call(ctx, "search_incidents", [{"id": "INC-001"}])
    assert result == [{"id": "INC-001"}]


def test_default_score_returns_empty_list():
    m = _ModuleA()
    ctx = RunContext()
    evidence = m.score(ctx)
    assert evidence == []


# ── @register decorator ───────────────────────────────────────────────────────

def test_register_decorator_adds_to_global_registry():
    initial = set(get_registry().list_available())

    @register
    class _DecoratedModule(VulnerabilityModule):
        @property
        def module_id(self) -> str:
            return "decorated_test_module_xyz"

    assert "decorated_test_module_xyz" in get_registry().list_available()

    # Cleanup to avoid polluting other tests
    get_registry()._modules.pop("decorated_test_module_xyz", None)
