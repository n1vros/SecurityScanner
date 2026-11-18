"""Pure and fake-session tests for platform scope/program reconciliation."""

from app.db.db_models import ProgramPlatform, SubdomainState
from app.programs.base import (
    PlatformBase,
    ScopeState,
    diff_scope_listing,
    missing_program_ids,
)


class _Scalars:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return list(self._rows)


class _Result:
    def __init__(self, *, rows=None, scalars=None):
        self._rows = list(rows or [])
        self._scalars = list(scalars or [])

    def all(self):
        return list(self._rows)

    def scalars(self):
        return _Scalars(self._scalars)


class _FakeSession:
    """Minimal AsyncSession stand-in: queued results plus statement capture."""

    def __init__(self, results=None):
        self._results = list(results or [])
        self.executed = []
        self.added = []
        self.commits = 0

    async def execute(self, statement):
        self.executed.append(statement)
        if self._results:
            return self._results.pop(0)
        return _Result()

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.commits += 1


class _ScopeRow:
    def __init__(self, scope_id, domain, *, is_active=True, manual=False):
        self.id = scope_id
        self.domain = domain
        self.is_active = is_active
        self.manually_deactivated = manual


class _ProgramRow:
    id = 1
    name = "Example"


class _StubPlatform(PlatformBase):
    platform = ProgramPlatform.HACKERONE

    async def fetch_programs(self, session, cookie_file=None):
        return []

    async def authenticate(self, cookie_file=None):
        return {"authenticated": True}


def _subdomain_updates(session):
    return [
        statement
        for statement in session.executed
        if getattr(statement, "table", None) is not None
        and statement.table.name == "subdomains"
    ]


def _compiled(statement):
    return str(statement.compile(compile_kwargs={"literal_binds": True}))


def test_diff_adds_reactivates_removes_and_never_touches_manual_scopes():
    existing = [
        ScopeState("keep.example.com", True, False),
        ScopeState("gone.example.com", True, False),
        ScopeState("back.example.com", False, False),
        ScopeState("manual.example.com", False, True),
        ScopeState("manual-listed.example.com", True, True),
    ]
    incoming = [
        "keep.example.com",
        "back.example.com",
        "manual.example.com",
        "manual-listed.example.com",
        "new.example.com",
    ]

    diff = diff_scope_listing(existing, incoming)

    assert diff.added == ("new.example.com",)
    assert diff.reactivated == ("back.example.com",)
    assert diff.deactivated == ("gone.example.com",)
    assert diff.manually_kept == (
        "manual.example.com",
        "manual-listed.example.com",
    )


def test_diff_skips_removals_for_partial_listing():
    existing = [ScopeState("gone.example.com", True, False)]
    diff = diff_scope_listing(existing, [], allow_deactivation=False)
    assert diff.deactivated == ()


def test_missing_program_ids_returns_only_absent_active_programs():
    assert missing_program_ids([1, 2, 3], {2, 3}) == (1,)
    assert missing_program_ids([], {1}) == ()


async def test_scope_sync_deactivates_removed_scope_and_children():
    session = _FakeSession([
        _Result(scalars=[
            _ScopeRow(10, "gone.example.com"),
            _ScopeRow(11, "keep.example.com"),
            _ScopeRow(12, "manual.example.com", is_active=False, manual=True),
        ])
    ])
    platform = _StubPlatform()

    added = await platform._sync_scopes_with_deduplication(
        session, _ProgramRow(), ["keep.example.com"]
    )

    assert added == 0
    updates = _subdomain_updates(session)
    assert len(updates) == 1
    sql = _compiled(updates[0])
    assert "UPDATE subdomains" in sql
    assert f"state='{SubdomainState.DEAD.value}'" in sql
    assert "scope_id IN (10)" in sql
    assert session.commits == 1


async def test_scope_sync_reactivates_and_respects_manual_deactivation():
    scope_back = _ScopeRow(20, "back.example.com", is_active=False)
    scope_manual = _ScopeRow(21, "manual.example.com", is_active=False, manual=True)
    session = _FakeSession([_Result(scalars=[scope_back, scope_manual])])

    added = await _StubPlatform()._sync_scopes_with_deduplication(
        session,
        _ProgramRow(),
        ["back.example.com", "manual.example.com"],
    )

    assert added == 1
    assert scope_back.is_active is True
    # Operator exclusion survives even though the platform re-listed it.
    assert scope_manual.is_active is False

    # DEAD children of the re-listed scope re-enter the scan queue; children of
    # the operator-excluded scope are untouched.
    updates = _subdomain_updates(session)
    assert len(updates) == 1
    sql = _compiled(updates[0])
    assert f"state='{SubdomainState.DISCOVERED.value}'" in sql
    assert "scope_id IN (20)" in sql
    assert "last_scanned_at=NULL" in sql.replace(" ", "")


async def test_scope_sync_adds_new_scope_as_active():
    session = _FakeSession([_Result(scalars=[])])
    added = await _StubPlatform()._sync_scopes_with_deduplication(
        session, _ProgramRow(), ["new.example.com"]
    )
    assert added == 1
    assert len(session.added) == 1
    new_scope = session.added[0]
    assert new_scope.domain == "new.example.com"
    assert new_scope.is_active is True


async def test_program_removal_deactivates_scopes_and_child_subdomains():
    session = _FakeSession([
        _Result(rows=[(1,), (2,)]),      # active programs
        _Result(rows=[(10,), (11,)]),    # scopes of removed program 1
    ])
    platform = _StubPlatform()

    removed = await platform._deactivate_missing_programs(session, {2})

    assert removed == 1
    compiled = [_compiled(statement) for statement in session.executed]

    assert any(
        "UPDATE subdomains" in sql and f"state='{SubdomainState.DEAD.value}'" in sql
        for sql in compiled
    )
    assert any(
        "UPDATE scopes" in sql and "is_active=false" in sql.lower()
        for sql in compiled
    )
    assert any(
        "UPDATE programs" in sql and "is_active=false" in sql.lower()
        for sql in compiled
    )
    assert session.commits == 1
