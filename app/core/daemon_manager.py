"""
Web-facing supervisor for the scanner daemon.

The web process and the daemon are separate processes that only share
PostgreSQL and the PID file. All lifecycle work is delegated to
:class:`app.core.process_control.ProcessController`, so the web UI and the CLI
see and control the same daemon: a daemon started from the command line shows
up in the web status, and either side can stop or restart it.

The daemon is spawned detached in a new session, so it is not tied to the
request or signal lifetime of the web process. Use systemd/Docker for
always-on supervision.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

from app.core.config import settings
from app.core.logging import logger
from app.core.process_control import ProcessController, process_controller


def _daemon_settings() -> Dict[str, Any]:
    """Settings the dashboard displays next to the daemon controls."""
    return {
        "daemon_sleep_seconds": getattr(settings, "DAEMON_SLEEP_SECONDS", None),
        "active_discovery_enabled": getattr(settings, "ACTIVE_DISCOVERY_ENABLED", False),
        "daemon_max_iterations": getattr(settings, "DAEMON_MAX_ITERATIONS", None),
    }


class DaemonManager:
    """Start, stop and inspect the single shared daemon process."""

    def __init__(self, controller: Optional[ProcessController] = None) -> None:
        self._controller = controller or process_controller
        self._lock = asyncio.Lock()
        self._autostart_attempted = False

    async def get_status(self) -> Dict[str, Any]:
        status = await asyncio.to_thread(self._controller.status)
        status["settings"] = _daemon_settings()
        return status

    async def start_daemon(self) -> Dict[str, Any]:
        async with self._lock:
            return await asyncio.to_thread(self._controller.start)

    async def stop_daemon(self) -> Dict[str, Any]:
        async with self._lock:
            return await asyncio.to_thread(self._controller.stop)

    async def restart_daemon(self) -> Dict[str, Any]:
        async with self._lock:
            stop_result = await asyncio.to_thread(self._controller.stop)
            if not stop_result.get("success"):
                current = await asyncio.to_thread(self._controller.status)
                if current.get("running"):
                    return {
                        "success": False,
                        "message": "Could not stop daemon; restart aborted",
                    }
            start_result = await asyncio.to_thread(self._controller.start)

        if not start_result.get("success"):
            return start_result
        message = (
            "Daemon restarted"
            if stop_result.get("success")
            else "Daemon started (it was not running before)"
        )
        return {**start_result, "message": message}

    async def autostart_if_enabled(self) -> bool:
        """Start the daemon at web startup only when explicitly opted in.

        The attempt is recorded so a single web process can never spawn twice;
        the shared PID file additionally makes a second worker or a reloaded
        process see the daemon as already running.
        """
        if self._autostart_attempted:
            return False
        self._autostart_attempted = True

        if not getattr(settings, "DAEMON_AUTOSTART", False):
            return False

        result = await self.start_daemon()
        if result.get("success"):
            logger.info(
                "daemon: autostarted at web startup (pid=%s, log=%s)",
                result.get("pid"),
                result.get("log_file"),
            )
            return True
        if "already running" in str(result.get("message", "")).lower():
            logger.info("daemon: autostart skipped; daemon is already running")
        else:
            logger.error("daemon: autostart failed: %s", result.get("message"))
        return False


# Global instance used by the web API.
daemon_manager = DaemonManager()
