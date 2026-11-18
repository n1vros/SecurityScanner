"""
Platform integrations for bug bounty programs.
"""

from app.programs.base import PlatformBase
from app.programs.loader import PlatformLoader, get_loader
from app.programs.platforms.hackerone import HackerOnePlatform

# Register programs with the global loader
_loader = get_loader()
_loader.register(HackerOnePlatform)

# Note: Other programs can be registered here when implemented
# _loader.register(BugCrowdPlatform)
# _loader.register(YesWeHackPlatform)
# _loader.register(IntigritiPlatform)

__all__ = ["PlatformBase", "PlatformLoader", "get_loader", "HackerOnePlatform"]