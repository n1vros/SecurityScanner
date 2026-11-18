"""
Platform loader for bug bounty platform integrations.
"""

from typing import Dict, Optional, Type

from app.programs.base import PlatformBase


class PlatformLoader:
    """Load platform integrations."""

    def __init__(self):
        self._platforms: Dict[str, Type[PlatformBase]] = {}

    def register(self, platform: Type[PlatformBase]) -> None:
        """Register a platform integration."""
        self._platforms[platform.platform.value] = platform

    def get_platform(self, platform_name: str) -> Optional[PlatformBase]:
        """Get platform instance by name."""
        platform_class = self._platforms.get(platform_name.lower())
        if platform_class:
            return platform_class()
        return None

    def list_platforms(self) -> list[str]:
        """List available programs."""
        return list(self._platforms.keys())


# Global loader instance
_loader = PlatformLoader()


def get_loader() -> PlatformLoader:
    """Get the global platform loader."""
    return _loader


def _register_default_platforms() -> None:
    """Register all available platform integrations."""
    try:
        from app.programs.platforms.hackerone import HackerOnePlatform
        _loader.register(HackerOnePlatform)
    except Exception as e:
        from app.core.logging import logger
        logger.warning("Could not register HackerOne platform: %s", e)

    try:
        from app.programs.platforms.yeswehack import YesWeHackPlatform
        _loader.register(YesWeHackPlatform)
    except Exception as e:
        from app.core.logging import logger
        logger.warning("Could not register YesWeHack platform: %s", e)

    try:
        from app.programs.platforms.intigriti import IntigritiPlatform
        _loader.register(IntigritiPlatform)
    except Exception as e:
        from app.core.logging import logger
        logger.warning("Could not register Intigriti platform: %s", e)

    try:
        from app.programs.platforms.bugcrowd import BugcrowdPlatform
        _loader.register(BugcrowdPlatform)
    except Exception as e:
        from app.core.logging import logger
        logger.warning("Could not register Bugcrowd platform: %s", e)

    try:
        from app.programs.platforms.immunefi import ImmunefiPlatform
        _loader.register(ImmunefiPlatform)
    except Exception as e:
        from app.core.logging import logger
        logger.warning("Could not register Immunefi platform: %s", e)

    try:
        from app.programs.platforms.bugbase import BugBasePlatform
        _loader.register(BugBasePlatform)
    except Exception as e:
        from app.core.logging import logger
        logger.warning("Could not register BugBase platform: %s", e)

    try:
        from app.programs.platforms.hackenproof import HackenProofPlatform
        _loader.register(HackenProofPlatform)
    except Exception as e:
        from app.core.logging import logger
        logger.warning("Could not register HackenProof platform: %s", e)

    try:
        from app.programs.platforms.disclose import DisclosIOPlatform
        _loader._platforms["disclosio"] = DisclosIOPlatform
    except Exception as e:
        from app.core.logging import logger
        logger.warning("Could not register disclose.io platform: %s", e)

    try:
        from app.programs.platforms.bugbountydirectory import BugBountyDirectoryPlatform
        _loader._platforms["bugbountydirectory"] = BugBountyDirectoryPlatform
    except Exception as e:
        from app.core.logging import logger
        logger.warning("Could not register BugBountyDirectory platform: %s", e)


_register_default_platforms()