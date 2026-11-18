"""
app/takeover/ip_hunter/cleaner.py

CloudIPCleaner — release / delete all reserved IPs created by the scanner
across AWS, Azure, GCP, and DigitalOcean.

Used by the `clear-all-ip` CLI command.  Can also be imported and awaited
programmatically.

Provider detection notes
------------------------
AWS EIPs:
  boto3's AllocateAddress does not support naming EIPs.  The cleaner therefore
  targets ALL unassociated EIPs in every configured region and warns the user.
  Tagged mode is also supported if you have previously tagged your EIPs with
  Key="sto-scanner" Value="true" — pass ``sto_only=True`` to enable it.
  dry_run lists what would be released without touching anything.

Azure PIPs:
  All Public IP resources whose name starts with ``sto-hunt-`` in the
  configured resource group are deleted.  Only scanner-created resources
  are touched.

GCP static addresses:
  All addresses whose name starts with ``sto-hunt-`` in every configured
  region of the project are deleted.

DigitalOcean Reserved IPs:
  All UNASSIGNED Reserved IPs (no Droplet attached) across every configured
  datacenter are released.  Like AWS, DO does not support resource naming, so
  the filter is ``droplet == None``.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import aiohttp

from app.core.config import settings
from app.core.logging import logger


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class ResourceInfo:
    """One reserved IP resource found in the cloud."""
    region:   str
    name:     str          # resource name / allocation ID / IP itself
    ip:       str
    attached: bool         # True = still in use (will be skipped)

    def __str__(self) -> str:
        state = "IN USE" if self.attached else "free"
        return f"  [{state}] {self.ip}  ({self.region})  name={self.name}"


@dataclass
class CleanResult:
    provider:  str
    found:     List[ResourceInfo] = field(default_factory=list)
    released:  List[ResourceInfo] = field(default_factory=list)
    skipped:   List[ResourceInfo] = field(default_factory=list)   # attached / in use
    errors:    List[str]          = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def summary(self) -> str:
        lines = [
            f"{self.provider.upper()}",
            f"  found   : {len(self.found)}",
            f"  released: {len(self.released)}",
            f"  skipped : {len(self.skipped)}  (in use)",
            f"  errors  : {len(self.errors)}",
        ]
        if self.errors:
            for e in self.errors:
                lines.append(f"  ✗ {e}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# CloudIPCleaner
# ---------------------------------------------------------------------------

VALID_PROVIDERS = ("aws", "azure", "gcp", "do")


class CloudIPCleaner:
    """
    Release all scanner-created cloud IP resources for the requested providers.

    Usage::

        cleaner = CloudIPCleaner()
        results = await cleaner.clean(["aws", "do"], dry_run=False)
        for r in results.values():
            print(r.summary())
    """

    def __init__(self) -> None:
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    # ── Public API ─────────────────────────────────────────────────────────

    async def clean(
        self,
        providers: List[str],
        dry_run: bool = False,
        sto_only: bool = True,
    ) -> Dict[str, CleanResult]:
        """
        Clean IP resources for each requested provider concurrently.

        Parameters
        ----------
        providers : list of provider keys, e.g. ["aws", "azure", "gcp", "do"]
        dry_run   : if True, only list resources — do not release anything
        sto_only  : AWS/DO only — when True restrict AWS to EIPs tagged
                    ``sto-scanner=true`` (requires tagging at allocation time).
                    When False, releases ALL unassociated EIPs (with extra warning).
                    Has no effect on Azure/GCP which always filter by ``sto-hunt-`` name.

        Returns
        -------
        dict mapping provider key → CleanResult
        """
        self._loop = asyncio.get_running_loop()

        # Validate + deduplicate
        requested = []
        for p in providers:
            p = p.lower().strip()
            if p not in VALID_PROVIDERS:
                logger.warning("cleaner: unknown provider %r — skipping", p)
                continue
            if p not in requested:
                requested.append(p)

        if not requested:
            return {}

        dispatch = {
            "aws":   self._clean_aws,
            "azure": self._clean_azure,
            "gcp":   self._clean_gcp,
            "do":    self._clean_do,
        }

        tasks = {p: asyncio.create_task(dispatch[p](dry_run=dry_run, sto_only=sto_only))
                 for p in requested}

        results: Dict[str, CleanResult] = {}
        for p, task in tasks.items():
            try:
                results[p] = await task
            except Exception as exc:
                r = CleanResult(provider=p)
                r.errors.append(f"Unhandled error: {exc}")
                results[p] = r

        return results

    # ── AWS ────────────────────────────────────────────────────────────────

    async def _clean_aws(self, dry_run: bool = False, sto_only: bool = True) -> CleanResult:
        result = CleanResult(provider="aws")

        key_id = getattr(settings, "AWS_ACCESS_KEY_ID",     None)
        secret = getattr(settings, "AWS_SECRET_ACCESS_KEY", None)
        if not key_id or not secret:
            result.errors.append("AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY not configured")
            return result

        try:
            import boto3
            import botocore.exceptions
        except ImportError:
            result.errors.append("boto3 not installed — run: pip install boto3")
            return result

        raw_regions = getattr(settings, "AWS_EIP_REGIONS",
                              "us-east-1,us-west-2,eu-west-1,ap-southeast-1")
        regions = [r.strip() for r in raw_regions.split(",") if r.strip()]

        for region in regions:
            def _list(r=region):
                ec2 = boto3.client(
                    "ec2", region_name=r,
                    aws_access_key_id=key_id,
                    aws_secret_access_key=secret,
                )
                filters: List[Dict] = [{"Name": "domain", "Values": ["vpc"]}]
                if sto_only:
                    filters.append({"Name": "tag:sto-scanner", "Values": ["true"]})
                return ec2.describe_addresses(Filters=filters).get("Addresses", []), ec2

            try:
                addrs, ec2_client = await self._loop.run_in_executor(None, _list)
            except Exception as exc:
                result.errors.append(f"{region}: describe_addresses failed — {exc}")
                continue

            for addr in addrs:
                ip    = addr.get("PublicIp", "?")
                alloc = addr.get("AllocationId", "?")
                assoc = addr.get("AssociationId")
                info  = ResourceInfo(region=region, name=alloc, ip=ip, attached=bool(assoc))
                result.found.append(info)

                if info.attached:
                    result.skipped.append(info)
                    continue

                if dry_run:
                    result.released.append(info)
                    continue

                def _release(aid=alloc, ec2=ec2_client):
                    ec2.release_address(AllocationId=aid)

                try:
                    await self._loop.run_in_executor(None, _release)
                    result.released.append(info)
                    logger.info("cleaner: aws released %s (%s) in %s", ip, alloc, region)
                except botocore.exceptions.ClientError as exc:
                    result.errors.append(f"{region}: release {ip} failed — {exc}")

        return result

    # ── Azure ──────────────────────────────────────────────────────────────

    async def _clean_azure(self, dry_run: bool = False, **_) -> CleanResult:
        result = CleanResult(provider="azure")

        tenant     = getattr(settings, "AZURE_TENANT_ID",       None)
        client_id  = getattr(settings, "AZURE_CLIENT_ID",       None)
        secret_val = getattr(settings, "AZURE_CLIENT_SECRET",   None)
        sub        = getattr(settings, "AZURE_SUBSCRIPTION_ID", None)
        rg         = getattr(settings, "AZURE_RESOURCE_GROUP",  None)

        if not all([tenant, client_id, secret_val, sub, rg]):
            result.errors.append(
                "AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET / "
                "AZURE_SUBSCRIPTION_ID / AZURE_RESOURCE_GROUP not all configured"
            )
            return result

        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.network import NetworkManagementClient
            import logging as _logging
            _logging.getLogger("azure").setLevel(_logging.WARNING)
        except ImportError:
            result.errors.append(
                "azure-mgmt-network / azure-identity not installed — "
                "run: pip install azure-identity azure-mgmt-network"
            )
            return result

        def _make_client():
            cred = ClientSecretCredential(tenant, client_id, secret_val)
            return NetworkManagementClient(cred, sub)

        def _list_pips():
            nc = _make_client()
            return list(nc.public_ip_addresses.list(rg)), nc

        try:
            pips, nc = await self._loop.run_in_executor(None, _list_pips)
        except Exception as exc:
            result.errors.append(f"list public_ip_addresses failed — {exc}")
            return result

        # Only touch scanner-created resources
        scanner_pips = [p for p in pips if p.name.startswith("sto-hunt-")]

        for pip in scanner_pips:
            ip      = pip.ip_address or "?"
            name    = pip.name
            region  = pip.location or "?"
            in_use  = pip.ip_configuration is not None
            info    = ResourceInfo(region=region, name=name, ip=ip, attached=in_use)
            result.found.append(info)

            if in_use:
                result.skipped.append(info)
                continue

            if dry_run:
                result.released.append(info)
                continue

            def _delete(n=name):
                c = _make_client()           # fresh client per call
                c.public_ip_addresses.begin_delete(rg, n).result()

            try:
                await self._loop.run_in_executor(None, _delete)
                result.released.append(info)
                logger.info("cleaner: azure deleted %s (%s)", ip, name)
            except Exception as exc:
                result.errors.append(f"delete {name} ({ip}) failed — {exc}")

        return result

    # ── GCP ────────────────────────────────────────────────────────────────

    async def _clean_gcp(self, dry_run: bool = False, **_) -> CleanResult:
        result = CleanResult(provider="gcp")

        project  = getattr(settings, "GCP_PROJECT_ID",           None)
        sa_path  = getattr(settings, "GCP_SERVICE_ACCOUNT_JSON", None)
        sa_key   = getattr(settings, "GCP_SERVICE_ACCOUNT_KEY",  None)

        if not project or not (sa_path or sa_key):
            result.errors.append(
                "GCP_PROJECT_ID and GCP_SERVICE_ACCOUNT_JSON (or GCP_SERVICE_ACCOUNT_KEY) "
                "not configured"
            )
            return result

        try:
            import json as _json
            from google.oauth2 import service_account
            from googleapiclient import discovery
        except ImportError:
            result.errors.append(
                "google-api-python-client / google-auth not installed — "
                "run: pip install google-api-python-client google-auth"
            )
            return result

        def _make_compute():
            if sa_key:
                info = _json.loads(sa_key)
                creds = service_account.Credentials.from_service_account_info(
                    info, scopes=["https://www.googleapis.com/auth/compute"],
                )
            else:
                creds = service_account.Credentials.from_service_account_file(
                    sa_path, scopes=["https://www.googleapis.com/auth/compute"],
                )
            return discovery.build("compute", "v1", credentials=creds, cache_discovery=False)

        raw_regions = getattr(settings, "GCP_EIP_REGIONS",
                              "us-central1,us-east1,europe-west1,asia-southeast1")
        regions = [r.strip() for r in raw_regions.split(",") if r.strip()]

        for region in regions:
            def _list(r=region):
                c = _make_compute()
                res = c.addresses().list(project=project, region=r).execute()
                return res.get("items", [])

            try:
                addrs = await self._loop.run_in_executor(None, _list)
            except Exception as exc:
                result.errors.append(f"{region}: list addresses failed — {exc}")
                continue

            # Only touch scanner-created resources
            scanner_addrs = [a for a in addrs if a.get("name", "").startswith("sto-hunt-")]

            for addr in scanner_addrs:
                name   = addr.get("name", "?")
                ip     = addr.get("address", "?")
                status = addr.get("status", "")
                in_use = status == "IN_USE"
                info   = ResourceInfo(region=region, name=name, ip=ip, attached=in_use)
                result.found.append(info)

                if in_use:
                    result.skipped.append(info)
                    continue

                if dry_run:
                    result.released.append(info)
                    continue

                def _delete(r=region, n=name):
                    c = _make_compute()          # fresh client per thread
                    op = c.addresses().delete(project=project, region=r, address=n).execute()
                    # Wait for op to finish
                    import time as _t
                    for _ in range(30):
                        _t.sleep(1)
                        s = c.regionOperations().get(
                            project=project, region=r, operation=op["name"]
                        ).execute()
                        if s.get("status") == "DONE":
                            return

                try:
                    await self._loop.run_in_executor(None, _delete)
                    result.released.append(info)
                    logger.info("cleaner: gcp deleted %s (%s) in %s", ip, name, region)
                except Exception as exc:
                    result.errors.append(f"{region}: delete {name} ({ip}) failed — {exc}")

        return result

    # ── DigitalOcean ────────────────────────────────────────────────────────

    async def _clean_do(self, dry_run: bool = False, **_) -> CleanResult:
        result = CleanResult(provider="do")

        token = getattr(settings, "DO_API_TOKEN", None)
        if not token:
            result.errors.append("DO_API_TOKEN not configured")
            return result

        raw_regions = getattr(settings, "DO_EIP_REGIONS",
                              "nyc1,nyc3,sfo3,ams3,sgp1,lon1,fra1,blr1,tor1,syd1")
        target_regions = {r.strip() for r in raw_regions.split(",") if r.strip()}

        _API = "https://api.digitalocean.com/v2"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
        }

        # Paginate through all reserved IPs
        all_rips: List[Dict] = []
        page = 1
        timeout = aiohttp.ClientTimeout(total=30)

        async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
            while True:
                try:
                    async with session.get(
                        f"{_API}/reserved_ips",
                        params={"per_page": 200, "page": page},
                    ) as resp:
                        if resp.status != 200:
                            result.errors.append(
                                f"GET /reserved_ips failed: HTTP {resp.status}"
                            )
                            break
                        data = await resp.json()
                except Exception as exc:
                    result.errors.append(f"GET /reserved_ips failed: {exc}")
                    break

                batch = data.get("reserved_ips", [])
                all_rips.extend(batch)

                next_url = (data.get("links") or {}).get("pages", {}).get("next")
                if not next_url or not batch:
                    break
                page += 1

            for rip in all_rips:
                ip        = rip.get("ip", "?")
                region_sl = (rip.get("region") or {}).get("slug", "?")
                droplet   = rip.get("droplet")
                in_use    = droplet is not None

                # Skip regions not in our config
                if region_sl not in target_regions:
                    continue

                info = ResourceInfo(region=region_sl, name=ip, ip=ip, attached=in_use)
                result.found.append(info)

                if in_use:
                    result.skipped.append(info)
                    continue

                if dry_run:
                    result.released.append(info)
                    continue

                try:
                    async with session.delete(
                        f"{_API}/reserved_ips/{ip}",
                        timeout=aiohttp.ClientTimeout(total=15),
                    ) as resp:
                        if resp.status in (204, 404):
                            result.released.append(info)
                            logger.info("cleaner: do released %s (%s)", ip, region_sl)
                        else:
                            body = await resp.text()
                            result.errors.append(
                                f"DELETE {ip} failed: HTTP {resp.status} — {body[:120]}"
                            )
                except Exception as exc:
                    result.errors.append(f"DELETE {ip} failed: {exc}")

        return result