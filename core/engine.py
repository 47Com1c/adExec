"""
core/engine.py — Walk the step registry and execute each step.

For every step the engine:
  1. checks the required tool is on PATH (else records 'no_tool'),
  2. checks every `requires` condition (else records 'skipped'),
  3. builds the command, runs it through the Runner,
  4. runs the step's parser to extract findings + table rows,
  5. records a StepResult on the Context and echoes findings to the terminal.
"""

import time

from core.runner import Runner
from core.steps  import StepResult, steps_for_phase, _LOUD
from core.env    import tool_available


class Engine:
    def __init__(self, ctx):
        self.ctx    = ctx
        self.runner = Runner(ctx.term)

    def run_phase(self, phase: int):
        for step in steps_for_phase(phase):
            self.run_step(step)

    # ------------------------------------------------------------------ #

    def run_step(self, step):
        ctx  = self.ctx
        term = ctx.term
        term.section(step.name)

        # 1. tool availability
        if step.tool and not tool_available(step.tool):
            reason = f"{step.tool} not installed"
            term.skip(reason)
            ctx.add_result(self._blank(step, "no_tool", reason))
            return

        # 2. preconditions
        for cond in step.requires:
            if not cond(ctx):
                term.skip(cond.reason)
                ctx.add_result(self._blank(step, "skipped", cond.reason))
                return

        # 3. build command
        try:
            cmd = step.build_cmd(ctx)
        except Exception as e:           # noqa: BLE001 - never let one step abort the run
            reason = f"could not build command: {e}"
            term.warn(reason)
            ctx.add_result(self._blank(step, "skipped", reason))
            return

        if not cmd:
            reason = "command not applicable for current context"
            term.skip(reason)
            ctx.add_result(self._blank(step, "skipped", reason))
            return

        # 4. run it
        save = (ctx.target_dir / step.save_name) if step.save_name else None
        cwd  = step.cwd(ctx) if step.cwd else None
        start = time.time()
        rc, output = self.runner.run(cmd, save_to=save, timeout=step.timeout, cwd=cwd)
        duration = round(time.time() - start, 2)

        # 5. parse
        findings, rows, columns = [], [], []
        if step.parse:
            try:
                findings, rows, columns = step.parse(output, ctx)
            except Exception as e:       # noqa: BLE001
                term.warn(f"parser error in {step.id}: {e}")

        status = self._classify(rc, output)
        result = StepResult(
            id         = step.id,
            name       = step.name,
            category   = step.category,
            phase      = step.phase,
            command    = " ".join(cmd),
            status     = status,
            returncode = rc,
            duration   = duration,
            raw_output = output,
            findings   = findings,
            rows       = rows,
            columns    = columns,
        )
        ctx.add_result(result)

        # 6. echo findings
        for f in findings:
            if f.severity in _LOUD:
                term.finding(f"[{f.severity.upper()}] {f.text}")
            else:
                term.info(f.text)
            if f.hint:
                term.info(f"  → {f.hint}")

    # ------------------------------------------------------------------ #

    @staticmethod
    def _classify(rc: int, output: str) -> str:
        """Distinguish a real failure from a tool/version flag mismatch."""
        if rc == 0:
            return "ok"
        low = output.lower()
        if "unrecognized arguments" in low or "no such option" in low \
                or "invalid choice" in low:
            return "unsupported"
        return "error"

    @staticmethod
    def _blank(step, status: str, note: str) -> StepResult:
        return StepResult(
            id       = step.id,
            name     = step.name,
            category = step.category,
            phase    = step.phase,
            command  = "",
            status   = status,
            note     = note,
        )
