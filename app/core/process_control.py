"""
Shared lifecycle control for the ``python main.py daemon`` process.

The web UI and the CLI both drive the same daemon through this controller.
The PID file is the single source of truth: either front end can inspect,
stop or restart a daemon started by the other one, including after the web
process has been restarted. The daemon runs in a new session so it survives
the request that spawned it and never receives the web process's signals.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

from app.core.logging import logger

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PID_FILE = "/tmp/stoscanner-daemon.pid"
DEFAULT_LOG_FILE = PROJECT_ROOT / "logs" / "daemon.log"
FALLBACK_LOG_FILE = Path("/tmp/stoscanner-daemon.log")
DAEMON_ENTRYPOINT = "main.py"
DAEMON_COMMAND = "daemon"
STOP_TIMEOUT_SECONDS = 30.0
KILL_TIMEOUT_SECONDS = 5.0
POLL_INTERVAL_SECONDS = 0.2


def parse_pid(text: str) -> Optional[int]:
    """Return the PID stored in the first line of a PID file, or ``None``."""
    first_line = text.strip().splitlines()[0].strip() if text.strip() else ""
    try:
        pid = int(first_line)
    except ValueError:
        return None
    return pid if pid > 0 else None


class ProcessController:
    """Own the daemon PID file and its start/stop lifecycle.

    ``STOSCANNER_PID_FILE`` and ``STOSCANNER_DAEMON_LOG`` override the default
    paths so the web UI and CLI resolve the same files. ``verifier`` and
    ``popen`` are injection points for tests; production callers keep the
    defaults.
    """

    def __init__(
        self,
        pid_file: Optional[Path] = None,
        log_file: Optional[Path] = None,
        project_root: Optional[Path] = None,
        verifier: Optional[Callable[[int], bool]] = None,
        popen: Optional[Callable[..., Any]] = None,
    ) -> None:
        self.pid_file = Path(
            pid_file or os.environ.get("STOSCANNER_PID_FILE", DEFAULT_PID_FILE)
        )
        self.log_file = Path(
            log_file or os.environ.get("STOSCANNER_DAEMON_LOG", str(DEFAULT_LOG_FILE))
        )
        self.project_root = Path(project_root) if project_root else PROJECT_ROOT
        self._verifier = verifier
        self._popen = popen or subprocess.Popen
        self._last_log_file: Optional[Path] = None
        self._thread_lock = threading.RLock()

    # ------------------------------------------------------------------
    # PID file
    # ------------------------------------------------------------------

    def read_pid(self) -> Optional[int]:
        """Read the PID file; malformed content is treated as no PID."""
        try:
            text = self.pid_file.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError as exc:
            logger.warning("daemon: cannot read PID file %s: %s", self.pid_file, exc)
            return None
        return parse_pid(text)

    def write_pid(self, pid: int) -> None:
        """Atomically replace the PID file with ``pid``."""
        self.pid_file.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=f"{self.pid_file.name}.",
            suffix=".tmp",
            dir=str(self.pid_file.parent),
        )
        try:
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(f"{pid}\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.pid_file)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def remove_pid_file(self) -> None:
        """Remove the PID file, ignoring a file that is already gone."""
        try:
            self.pid_file.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            logger.warning("daemon: cannot remove PID file %s: %s", self.pid_file, exc)

    # ------------------------------------------------------------------
    # Identity and liveness
    # ------------------------------------------------------------------

    def _read_cmdline(self, pid: int) -> Optional[str]:
        """Return ``/proc/<pid>/cmdline`` or ``None`` when /proc is unavailable."""
        try:
            return (Path("/proc") / str(pid) / "cmdline").read_bytes().decode(
                "utf-8", "replace"
            )
        except OSError:
            return None

    def verify_process(self, pid: int) -> bool:
        """Confirm ``pid`` is a live ``main.py daemon`` process.

        Linux exposes the command line through /proc. Where /proc is
        unavailable (or unreadable) only liveness can be checked, so the
        controller falls back to ``os.kill(pid, 0)`` rather than declaring a
        running daemon stopped.
        """
        cmdline = self._read_cmdline(pid)
        if cmdline is None:
            return self._process_is_alive(pid)

        args = [arg for arg in cmdline.split("\0") if arg]
        for index, arg in enumerate(args[:-1]):
            if Path(arg).name == DAEMON_ENTRYPOINT and args[index + 1] == DAEMON_COMMAND:
                return True
        return False

    @staticmethod
    def _is_zombie(pid: int) -> bool:
        try:
            stat = (Path("/proc") / str(pid) / "stat").read_text(encoding="utf-8")
            state = stat.rsplit(")", 1)[1].split()[0]
        except (OSError, IndexError):
            return False
        return state == "Z"

    def _process_is_alive(self, pid: int) -> bool:
        """Liveness check that does not consider zombies to be running."""
        if pid <= 0:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            self._reap(pid)
            return False
        except PermissionError:
            return True
        except OSError:
            return False
        if self._is_zombie(pid):
            self._reap(pid)
            return False
        return True

    def _verify(self, pid: int) -> bool:
        if self._verifier is not None:
            return bool(self._verifier(pid))
        return self.verify_process(pid)

    def _reap(self, pid: int) -> None:
        """Reap a child we spawned so an exited daemon cannot linger as a zombie."""
        try:
            os.waitpid(pid, os.WNOHANG)
        except (ChildProcessError, OSError):
            pass

    # ------------------------------------------------------------------
    # Cross-process serialization
    # ------------------------------------------------------------------

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        """Serialize start/stop across threads and processes with a file lock."""
        with self._thread_lock:
            lock_fd: Optional[int] = None
            try:
                lock_fd = os.open(
                    f"{self.pid_file}.lock", os.O_CREAT | os.O_RDWR, 0o644
                )
                try:
                    import fcntl

                    fcntl.flock(lock_fd, fcntl.LOCK_EX)
                except ImportError:
                    pass
            except OSError as exc:
                logger.debug("daemon: cannot take PID lock: %s", exc)
            try:
                yield
            finally:
                if lock_fd is not None:
                    try:
                        os.close(lock_fd)
                    except OSError:
                        pass

    # ------------------------------------------------------------------
    # State helpers
    # ------------------------------------------------------------------

    def _resolve_pid(self) -> Optional[int]:
        """Return the verified running PID, cleaning up stale or foreign files."""
        pid = self.read_pid()
        if pid is None:
            if self.pid_file.exists():
                logger.warning(
                    "daemon: removing malformed PID file %s", self.pid_file
                )
                self.remove_pid_file()
            return None
        if self._verify(pid):
            return pid
        logger.warning(
            "daemon: removing stale PID file %s (pid %s is not main.py daemon)",
            self.pid_file,
            pid,
        )
        self._reap(pid)
        self.remove_pid_file()
        return None

    def _started_at(self) -> Optional[datetime]:
        try:
            stamp = self.pid_file.stat().st_mtime
        except OSError:
            return None
        return datetime.fromtimestamp(stamp, tz=timezone.utc)

    def _prepare_log_file(self) -> Path:
        candidates = [self.log_file]
        if self.log_file != FALLBACK_LOG_FILE:
            candidates.append(FALLBACK_LOG_FILE)
        last_error: Optional[OSError] = None
        for path in candidates:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("ab"):
                    pass
                return path
            except OSError as exc:
                last_error = exc
                logger.warning("daemon: cannot use log file %s: %s", path, exc)
        raise OSError(f"Cannot open daemon log file: {last_error}")

    def _effective_log_file(self) -> Path:
        """Report the log path start would use, or the fallback it fell back to."""
        return self._last_log_file or self.log_file

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Return the shared daemon status payload."""
        pid = self._resolve_pid()
        started_at = self._started_at() if pid is not None else None
        uptime: Optional[int] = None
        if started_at is not None:
            uptime = max(0, int(time.time() - started_at.timestamp()))
        log_file = self._effective_log_file()
        running = pid is not None
        return {
            "running": running,
            "status": "running" if running else "stopped",
            "message": (
                f"Daemon is running (PID {pid})" if running else "Daemon is stopped"
            ),
            "pid": pid,
            "started_at": started_at.isoformat() if started_at else None,
            "uptime_seconds": uptime,
            "log_file": str(log_file),
            "pid_file": str(self.pid_file),
        }

    def start(self) -> dict[str, Any]:
        """Spawn a detached daemon; refuse if one is already running."""
        with self._exclusive():
            running_pid = self._resolve_pid()
            if running_pid is not None:
                return {
                    "success": False,
                    "message": "Daemon is already running",
                    "pid": running_pid,
                    "log_file": str(self._effective_log_file()),
                    "pid_file": str(self.pid_file),
                }

            try:
                log_path = self._prepare_log_file()
            except OSError as exc:
                return {"success": False, "message": str(exc)}

            env = os.environ.copy()
            env.setdefault("PYTHONUNBUFFERED", "1")
            command = [
                sys.executable,
                str(self.project_root / DAEMON_ENTRYPOINT),
                DAEMON_COMMAND,
            ]

            try:
                log_handle = open(log_path, "ab", buffering=0)
            except OSError as exc:
                return {"success": False, "message": f"Cannot open log file: {exc}"}

            try:
                process = self._popen(
                    command,
                    cwd=str(self.project_root),
                    stdin=subprocess.DEVNULL,
                    stdout=log_handle,
                    stderr=subprocess.STDOUT,
                    env=env,
                    start_new_session=True,
                    close_fds=True,
                )
            except Exception as exc:
                logger.error("daemon: failed to spawn daemon: %s", exc)
                return {"success": False, "message": f"Failed to start daemon: {exc}"}
            finally:
                # The child holds its own duplicate of the descriptor.
                log_handle.close()

            pid = getattr(process, "pid", None)
            if not isinstance(pid, int) or pid <= 0:
                try:
                    process.terminate()
                except Exception:
                    pass
                return {"success": False, "message": "Daemon process has no PID"}

            try:
                self.write_pid(pid)
            except OSError as exc:
                logger.error("daemon: cannot write PID file %s: %s", self.pid_file, exc)
                try:
                    process.terminate()
                except Exception:
                    pass
                return {"success": False, "message": f"Cannot write PID file: {exc}"}

            self._last_log_file = log_path
            started_at = self._started_at()
            logger.info(
                "daemon: started pid=%s log=%s pid_file=%s",
                pid,
                log_path,
                self.pid_file,
            )
            return {
                "success": True,
                "message": "Daemon started",
                "pid": pid,
                "started_at": started_at.isoformat() if started_at else None,
                "log_file": str(log_path),
                "pid_file": str(self.pid_file),
            }

    def _signal(self, pid: int, signum: int) -> None:
        os.kill(pid, signum)

    def stop(
        self,
        timeout: float = STOP_TIMEOUT_SECONDS,
        kill_timeout: float = KILL_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        """SIGTERM the daemon, escalating to SIGKILL after ``timeout`` seconds."""
        with self._exclusive():
            pid = self._resolve_pid()
            if pid is None:
                return {
                    "success": False,
                    "message": "Daemon is not running",
                    "pid": None,
                    "log_file": str(self._effective_log_file()),
                    "pid_file": str(self.pid_file),
                }

            logger.info("daemon: stopping pid=%s", pid)
            try:
                self._signal(pid, signal.SIGTERM)
            except ProcessLookupError:
                self.remove_pid_file()
                self._reap(pid)
                return {
                    "success": True,
                    "message": "Daemon is not running",
                    "pid": pid,
                    "log_file": str(self._effective_log_file()),
                    "pid_file": str(self.pid_file),
                }
            except PermissionError as exc:
                return {
                    "success": False,
                    "message": f"Not permitted to stop daemon (PID {pid}): {exc}",
                    "pid": pid,
                }

            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if not self._process_is_alive(pid):
                    break
                time.sleep(POLL_INTERVAL_SECONDS)
            else:
                logger.warning(
                    "daemon: pid %s did not exit after %.0fs; sending SIGKILL",
                    pid,
                    timeout,
                )
                try:
                    self._signal(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except PermissionError as exc:
                    return {
                        "success": False,
                        "message": f"Not permitted to kill daemon (PID {pid}): {exc}",
                        "pid": pid,
                    }
                kill_deadline = time.monotonic() + kill_timeout
                while kill_deadline > time.monotonic():
                    if not self._process_is_alive(pid):
                        break
                    time.sleep(POLL_INTERVAL_SECONDS)
                if self._process_is_alive(pid):
                    return {
                        "success": False,
                        "message": "Daemon did not stop and is still running",
                        "pid": pid,
                    }

            self.remove_pid_file()
            self._reap(pid)
            logger.info("daemon: stopped pid=%s", pid)
            return {
                "success": True,
                "message": "Daemon stopped",
                "pid": pid,
                "log_file": str(self._effective_log_file()),
                "pid_file": str(self.pid_file),
            }


# Shared by the web manager and the CLI.
process_controller = ProcessController()
