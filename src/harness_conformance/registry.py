from __future__ import annotations

from pathlib import Path

from .canonical import load_json
from .errors import ConformanceError
from .schema import ID, validate_campaign


def campaign_registry(repository: Path) -> dict[str, Path]:
    root = repository.resolve()
    result: dict[str, Path] = {}
    campaign_root = root / "campaigns"
    if not campaign_root.is_dir() or campaign_root.is_symlink():
        raise ConformanceError("CAMPAIGN_ROOT_UNAVAILABLE", "campaign root is unavailable")
    for path in sorted(campaign_root.glob("**/campaign.json"), key=lambda item: item.as_posix().encode("utf-8")):
        if path.is_symlink() or root not in path.resolve().parents:
            raise ConformanceError("CAMPAIGN_PATH_FORBIDDEN", "campaign path is linked or escaped")
        campaign = validate_campaign(load_json(path))
        campaign_id = campaign["campaignId"]
        if campaign_id in result:
            raise ConformanceError("DUPLICATE_CAMPAIGN", f"duplicate campaign {campaign_id}")
        result[campaign_id] = path
    if not result:
        raise ConformanceError("NO_CAMPAIGNS", "no campaign definitions are registered")
    return result


def resolve_campaign(repository: Path, campaign_id: str) -> Path:
    if not isinstance(campaign_id, str) or not ID.fullmatch(campaign_id):
        raise ConformanceError("INVALID_CAMPAIGN_ID", "CAMPAIGN is not a canonical identifier")
    try:
        return campaign_registry(repository)[campaign_id]
    except KeyError as exc:
        raise ConformanceError("UNKNOWN_CAMPAIGN", f"unknown campaign {campaign_id}") from exc
