"""
app/programs/platforms/manual.py

Manual program import from a JSON file.

Usage (CLI):
    python3 main.py programs-add programs.json
    python3 main.py programs-add programs.json --dry-run

JSON format:
  [
    {
      "name":        "Example Corp",           # required
      "scopes":      ["example.com", "*.example.com"],  # required
      "platform":    "manual",                 # optional, default "manual"
      "url":         "https://example.com/security",    # optional
      "external_id": "example-corp",           # optional, derived from name if omitted
      "metadata":    { "contact": "..." }      # optional, freeform
    },
    ...
  ]

Scopes accept any format that extract_domains() understands:
  - bare domains:     "example.com"
  - wildcards:        "*.example.com"  → example.com
  - full URLs:        "https://api.example.com/v1"  → api.example.com
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.db.db_models import Program, ProgramPlatform, Scope
from app.programs.domain_utils import extract_domains


class ManualPlatform:
    """
    Import programs and scopes from a JSON file.

    Not a full PlatformBase subclass — manual imports are file-driven,
    not credential-driven, so authenticate() and sync_programs() are
    intentionally omitted.
    """

    @staticmethod
    def parse_file(path: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        Parse and validate a programs JSON file.

        Returns (valid_programs, errors).
        Does not touch the database — safe to call for dry-run validation.

        Validation rules:
          - File must exist and contain valid JSON
          - Top-level must be a list
          - Each entry must have non-empty "name" and non-empty "scopes"
          - Entries with no extractable domains after processing are skipped
        """
        if not path.exists():
            return [], [f"File not found: {path}"]

        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            return [], [f"Invalid JSON: {e}"]

        if not isinstance(raw, list):
            return [], ["JSON root must be an array of program objects"]

        valid:  List[Dict[str, Any]] = []
        errors: List[str]            = []

        for i, entry in enumerate(raw):
            label = f"Entry {i}"

            name = (entry.get("name") or "").strip()
            if not name:
                errors.append(f"{label}: missing or empty 'name' — skipped")
                continue
            label = name

            raw_scopes = entry.get("scopes") or []
            if not raw_scopes:
                errors.append(f"{label}: 'scopes' is missing or empty — skipped")
                continue

            domains: List[str] = []
            for s in raw_scopes:
                for d in extract_domains(str(s).strip(), name):
                    if d not in domains:
                        domains.append(d)

            if not domains:
                errors.append(f"{label}: no valid domains could be extracted from scopes — skipped")
                continue

            platform_raw = (entry.get("platform") or "manual").strip().lower()
            try:
                platform_enum = ProgramPlatform(platform_raw)
            except ValueError:
                errors.append(
                    f"{label}: unknown platform '{platform_raw}' — defaulting to 'manual'"
                )
                platform_enum = ProgramPlatform.MANUAL

            valid.append({
                "name":          name,
                "platform":      platform_enum,
                "url":           (entry.get("url") or "").strip() or None,
                "external_id":   (entry.get("external_id") or "").strip()
                                 or name.lower().replace(" ", "-"),
                "scopes":        domains,
                "metadata":      entry.get("metadata") or {},
            })

        return valid, errors

    @staticmethod
    async def import_programs(
        session: AsyncSession,
        programs: List[Dict[str, Any]],
    ) -> Tuple[int, int]:
        """
        Upsert a list of validated program dicts into the database.

        Returns (new_programs_count, new_scopes_count).

        Duplicate programs (same name + platform) are matched and their
        scopes merged — re-running the same file is idempotent.
        """
        new_programs = 0
        new_scopes   = 0

        for p in programs:
            # ── Upsert program ───────────────────────────────────────────────
            result  = await session.execute(
                select(Program).where(
                    Program.name     == p["name"],
                    Program.platform == p["platform"],
                )
            )
            program = result.scalar_one_or_none()

            if not program:
                program = Program(
                    name=p["name"],
                    platform=p["platform"],
                    external_id=p["external_id"],
                    url=p["url"],
                    is_active=True,
                    created_at=datetime.utcnow(),
                )
                session.add(program)
                await session.flush()
                new_programs += 1
                logger.info("ManualImport: created program '%s'", p["name"])
            else:
                if p["url"] and not program.url:
                    program.url = p["url"]
                if p["external_id"] and not program.external_id:
                    program.external_id = p["external_id"]

            # ── Upsert scopes ────────────────────────────────────────────────
            result   = await session.execute(
                select(Scope).where(
                    Scope.program_id == program.id,
                    Scope.is_active  == True,
                )
            )
            existing = {s.domain for s in result.scalars().all()}

            added = set(p["scopes"]) - existing
            for domain in added:
                session.add(Scope(
                    program_id=program.id,
                    domain=domain,
                    added_at=datetime.utcnow(),
                ))
            new_scopes += len(added)

            if added:
                logger.info(
                    "ManualImport: added %d scope(s) to '%s': %s",
                    len(added), p["name"], sorted(added),
                )

        await session.commit()
        return new_programs, new_scopes