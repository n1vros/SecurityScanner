"""Tests for the shared daemon process controller and web autostart policy."""

import os
import signal
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.core import daemon_manager as daemon_manager_module
from app.core.daemon_manager import DaemonManager
from app.core.process_control import ProcessController, parse_pid


class FakeController:
    """Synchronous stand-in for ProcessController used by manager tests."""

    def __init__(self, running: bool = False) -> None:
        self.start_calls = 0
        self.stop_calls = 0
        self.running = running
        self.last_stop_success = True

    def start(self):
        self.start_calls += 1
        self.running = True
        return {
            "success": True,
            "message": "Daemon started",
            "pid": 4321,
            "log_file": "/tmp/test-daemon.log",
            "pid_file": "/tmp/test-daemon.pid",
        }

    def stop(self):
        self.stop_calls += 1
        if not self.last_stop_success:
            return {"success": False, "message": "Cannot stop", "pid": 4321}
        self.running = False
        return {"success": True, "message": "Daemon stopped", "pid": 4321}

    def status(self):
        return {
            "running": self.running,
            "status": "running" if self.running else "stopped",
            "message": "running" if self.running else "stopped",
            "pid": 4321 if self.running else None,
            "started_at": None,
            "uptime_seconds": None,
            "log_file": "/tmp/test-daemon.log",
            "pid_file": "/tmp/test-daemon.pid",
        }


@pytest.fixture
def controller(tmp_path: Path) -> ProcessController:
    return ProcessController(pid_file=tmp_path / "daemon.pid")


class FakeProcess:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.terminated = False

    def terminate(self) -> None:
        self.terminated = True


# ---------------------------------------------------------------------------
# PID file
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("1234\n", 1234),
        ("  1234  ", 1234),
        ("", None),
        ("\n\n", None),
        ("not-a-pid\n", None),
        ("0\n", None),
        ("-5\n", None),
        ("12 34\n", None),
    ],
)
def test_parse_pid(text: str, expected):
    assert parse_pid(text) == expected


def test_write_and_read_pid_is_atomic(controller: ProcessController):
    controller.write_pid(4321)

    assert controller.read_pid() == 4321
    assert controller.pid_file.read_text(encoding="ascii") == "4321\n"
    assert list(controller.pid_file.parent.glob("*.tmp")) == []


def test_pid_file_env_override(tmp_path: Path, monkeypatch):
    target = tmp_path / "custom.pid"
    monkeypatch.setenv("STOSCANNER_PID_FILE", str(target))

    assert ProcessController().pid_file == target


def test_malformed_pid_file_is_cleaned_up(controller: ProcessController):
    controller.pid_file.write_text("garbage\n", encoding="utf-8")

    status = controller.status()

    assert status["running"] is False
    assert status["pid"] is None
    assert not controller.pid_file.exists()


def test_stale_pid_file_is_cleaned_up(controller: ProcessController):
    controller.write_pid(999_999)
    controller._read_cmdline = lambda pid: None
    controller._process_is_alive = lambda pid: False

    status = controller.status()

    assert status["running"] is False
    assert not controller.pid_file.exists()


def test_identity_mismatch_is_cleaned_up(controller: ProcessController):
    # The test process is alive but its command line is not `main.py daemon`.
    controller.write_pid(os.getpid())

    status = controller.status()

    assert status["running"] is False
    assert not controller.pid_file.exists()


@pytest.mark.parametrize(
    ("cmdline", "expected"),
    [
        ("/usr/bin/python\0/repo/main.py\0daemon\0", True),
        ("/usr/bin/python\0main.py\0daemon\0", True),
        ("/usr/bin/python\0/repo/main.py\0web\0", False),
        ("/usr/bin/python\0/repo/other.py\0daemon\0", False),
        ("", False),
    ],
)
def test_verify_process_checks_cmdline(controller: ProcessController, cmdline, expected):
    controller._read_cmdline = lambda pid: cmdline

    assert controller.verify_process(1234) is expected


# ---------------------------------------------------------------------------
# Start / stop
# ---------------------------------------------------------------------------


def test_start_refuses_when_any_daemon_is_running(controller: ProcessController):
    controller._verifier = lambda pid: True
    controller.write_pid(os.getpid())

    def exploding_popen(*args, **kwargs):
        raise AssertionError("start must not spawn when a daemon is running")

    controller._popen = exploding_popen

    result = controller.start()

    assert result["success"] is False
    assert "already running" in result["message"].lower()
    assert result["pid"] == os.getpid()


def test_start_spawns_detached_daemon_and_records_pid(tmp_path: Path):
    calls = {}

    def fake_popen(args, **kwargs):
        calls["args"] = args
        calls.update(kwargs)
        return FakeProcess(5678)

    controller = ProcessController(
        pid_file=tmp_path / "daemon.pid",
        log_file=tmp_path / "logs" / "daemon.log",
        project_root=tmp_path,
        popen=fake_popen,
    )

    result = controller.start()

    assert result["success"] is True
    assert result["pid"] == 5678
    assert controller.read_pid() == 5678
    assert calls["start_new_session"] is True
    assert calls["cwd"] == str(tmp_path)
    assert calls["args"][-2:] == [str(tmp_path / "main.py"), "daemon"]
    assert result["log_file"] == str(tmp_path / "logs" / "daemon.log")
    assert (tmp_path / "logs" / "daemon.log").is_file()


def test_start_failure_does_not_write_pid(tmp_path: Path):
    def failing_popen(*args, **kwargs):
        raise OSError("boom")

    controller = ProcessController(
        pid_file=tmp_path / "daemon.pid",
        log_file=tmp_path / "daemon.log",
        popen=failing_popen,
    )

    result = controller.start()

    assert result["success"] is False
    assert not controller.pid_file.exists()


def test_stop_terminates_and_removes_pid(controller: ProcessController):
    controller._verifier = lambda pid: True
    controller.write_pid(4242)
    signals = []
    controller._signal = lambda pid, signum: signals.append(signum)
    controller._process_is_alive = lambda pid: False

    result = controller.stop(timeout=0.01)

    assert result["success"] is True
    assert result["message"] == "Daemon stopped"
    assert signals == [signal.SIGTERM]
    assert not controller.pid_file.exists()


def test_stop_escalates_to_sigkill(controller: ProcessController):
    controller._verifier = lambda pid: True
    controller.write_pid(4242)
    alive = {"value": True}
    signals = []

    def fake_signal(pid, signum):
        signals.append(signum)
        if signum == signal.SIGKILL:
            alive["value"] = False

    controller._signal = fake_signal
    controller._process_is_alive = lambda pid: alive["value"]

    result = controller.stop(timeout=0.01, kill_timeout=0.1)

    assert result["success"] is True
    assert signals == [signal.SIGTERM, signal.SIGKILL]


def test_stop_when_not_running(controller: ProcessController):
    result = controller.stop()

    assert result["success"] is False
    assert result["pid"] is None
    assert "not running" in result["message"].lower()


def test_stop_permission_error_does_not_crash(controller: ProcessController):
    controller._verifier = lambda pid: True
    controller.write_pid(4242)
    controller._signal = lambda pid, signum: (_ for _ in ()).throw(
        PermissionError("not mine")
    )

    result = controller.stop()

    assert result["success"] is False
    assert result["pid"] == 4242
    assert "permitted" in result["message"].lower()
    assert controller.pid_file.exists()


def test_status_payload_shape(controller: ProcessController):
    controller._verifier = lambda pid: True
    controller.write_pid(4242)

    status = controller.status()

    assert status["running"] is True
    assert status["status"] == "running"
    assert status["pid"] == 4242
    assert status["started_at"] is not None
    assert isinstance(status["uptime_seconds"], int)
    assert status["log_file"].endswith("daemon.log")
    assert status["pid_file"] == str(controller.pid_file)
    assert "message" in status


# ---------------------------------------------------------------------------
# Manager and autostart
# ---------------------------------------------------------------------------


async def test_manager_status_includes_dashboard_settings(monkeypatch):
    monkeypatch.setattr(
        daemon_manager_module,
        "settings",
        SimpleNamespace(
            DAEMON_SLEEP_SECONDS=30,
            ACTIVE_DISCOVERY_ENABLED=True,
            DAEMON_MAX_ITERATIONS=7,
        ),
    )
    manager = DaemonManager(controller=FakeController())

    status = await manager.get_status()

    assert status["settings"] == {
        "daemon_sleep_seconds": 30,
        "active_discovery_enabled": True,
        "daemon_max_iterations": 7,
    }


async def test_autostart_is_off_without_setting(monkeypatch):
    monkeypatch.setattr(daemon_manager_module, "settings", SimpleNamespace())
    fake = FakeController()
    manager = DaemonManager(controller=fake)

    assert await manager.autostart_if_enabled() is False
    assert fake.start_calls == 0


async def test_autostart_starts_at_most_once(monkeypatch):
    monkeypatch.setattr(
        daemon_manager_module,
        "settings",
        SimpleNamespace(DAEMON_AUTOSTART=True),
    )
    fake = FakeController()
    manager = DaemonManager(controller=fake)

    assert await manager.autostart_if_enabled() is True
    assert await manager.autostart_if_enabled() is False
    assert fake.start_calls == 1


async def test_restart_aborts_when_stop_fails():
    fake = FakeController(running=True)
    fake.last_stop_success = False
    manager = DaemonManager(controller=fake)

    result = await manager.restart_daemon()

    assert result["success"] is False
    assert fake.start_calls == 0


async def test_restart_starts_when_daemon_was_stopped():
    fake = FakeController(running=False)
    fake.last_stop_success = False
    manager = DaemonManager(controller=fake)

    result = await manager.restart_daemon()

    assert result["success"] is True
    assert fake.start_calls == 1
    assert "not running before" in result["message"]


async def test_api_startup_does_not_spawn_by_default(monkeypatch):
    from app.db import session as db_session
    from app.web import api as api_module

    async def fake_create_tables():
        return None

    monkeypatch.setattr(db_session, "create_tables", fake_create_tables)
    monkeypatch.setattr(daemon_manager_module, "settings", SimpleNamespace())
    fake = FakeController()
    monkeypatch.setattr(api_module, "daemon_manager", DaemonManager(controller=fake))

    await api_module.startup_event()

    assert fake.start_calls == 0


async def test_api_startup_autostarts_when_enabled(monkeypatch):
    from app.db import session as db_session
    from app.web import api as api_module

    async def fake_create_tables():
        return None

    monkeypatch.setattr(db_session, "create_tables", fake_create_tables)
    monkeypatch.setattr(
        daemon_manager_module,
        "settings",
        SimpleNamespace(DAEMON_AUTOSTART=True),
    )
    fake = FakeController()
    monkeypatch.setattr(api_module, "daemon_manager", DaemonManager(controller=fake))

    await api_module.startup_event()

    assert fake.start_calls == 1
