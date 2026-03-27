"""
core/runner.py — Execute shell commands, stream output to terminal,
                 optionally save to a file, and return captured output.
"""

import subprocess
import shlex
from pathlib import Path


class Runner:
    def __init__(self, term):
        self.term = term

    def run(self, cmd: list | str, save_to: Path = None,
            env=None, timeout=300) -> tuple[int, str]:
        """
        Run a command.
        - Prints the command before executing.
        - Streams stdout+stderr live to terminal.
        - Captures combined output.
        - Optionally saves output to save_to path.

        Returns (returncode, output_str).
        """
        if isinstance(cmd, str):
            cmd = shlex.split(cmd)

        self.term.cmd(" ".join(cmd))

        output_lines = []
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
            )
            for line in proc.stdout:
                stripped = line.rstrip()
                self.term.raw(stripped)
                output_lines.append(stripped)

            proc.wait(timeout=timeout)
            rc = proc.returncode

        except FileNotFoundError:
            msg = f"[!] Command not found: {cmd[0]}"
            self.term.error(msg)
            output_lines.append(msg)
            rc = 127
        except subprocess.TimeoutExpired:
            proc.kill()
            msg = f"[!] Command timed out after {timeout}s: {cmd[0]}"
            self.term.error(msg)
            output_lines.append(msg)
            rc = -1
        except Exception as e:
            msg = f"[!] Unexpected error running {cmd[0]}: {e}"
            self.term.error(msg)
            output_lines.append(msg)
            rc = -1

        output = "\n".join(output_lines)

        if save_to:
            try:
                Path(save_to).parent.mkdir(parents=True, exist_ok=True)
                Path(save_to).write_text(output)
                self.term.info(f"Saved → {save_to}")
            except Exception as e:
                self.term.warn(f"Could not save output: {e}")

        return rc, output
