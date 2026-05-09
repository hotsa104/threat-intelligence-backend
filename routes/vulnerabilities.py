"""
/api/vulnerabilities エンドポイント

GET /api/vulnerabilities       → /list と同じ（ガイド互換）
GET /api/vulnerabilities/list  → DB から取得（Phase 2 以降）
GET /api/vulnerabilities/stats → 優先度別統計 + 最終同期情報
"""
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from config import settings
from db.ti_db import get_last_sync, get_priority_counts, query_entries, get_references
from fetchers.ti_kev_fetcher import fetch_cisa_kev
from fetchers.ti_nvd_client import enrich_with_nvd
from services.ti_scoring import score_all

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


def _normalize(row: dict) -> dict:
    """DB の snake_case キーを API の camelCase に統一する。"""
    if "cve_id" in row:
        return {
            "cveID": row.get("cve_id", ""),
            "vendorProject": row.get("vendor", ""),
            "product": row.get("product", ""),
            "vulnerabilityName": row.get("vuln_name", ""),
            "dateAdded": row.get("date_added", ""),
            "dueDate": row.get("due_date", ""),
            "shortDescription": row.get("short_desc", ""),
            "published": row.get("published"),
            "lastModified": row.get("last_modified"),
            "cvss_score": row.get("cvss_score"),
            "epss_score": row.get("epss_score", 0.0),
            "priority": row.get("priority", "LOW"),
            "knownRansomwareCampaignUse": row.get("ransomware_use", ""),
            "enriched_at": row.get("enriched_at"),
        }
    return row


@router.get("/stats")
async def vulnerability_stats():
    """優先度別件数・最終同期情報を返す。"""
    counts = get_priority_counts()
    last_sync = get_last_sync()
    total = sum(counts.values())
    return {
        "total": total,
        "priority_counts": counts,
        "last_sync": last_sync,
    }


@router.get("")
@router.get("/list")
async def list_vulnerabilities(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    priority: Optional[str] = Query(default=None, description="CRITICAL/HIGH/MEDIUM/LOW"),
    enrich_nvd: bool = Query(default=False, description="ライブ取得モード（DB 未構築時のフォールバック）"),
):
    """CVE リストを返す。

    通常は DB から取得する（高速）。
    DB が空の場合または enrich_nvd=true の場合はライブ取得にフォールバックする。
    """
    # --- DB から取得 ---
    rows, total = query_entries(
        priority=priority.upper() if priority else None,
        limit=limit,
        offset=offset,
    )

    if rows and not enrich_nvd:
        return {"count": len(rows), "total": total, "offset": offset, "data": [_normalize(r) for r in rows]}

    # --- DB が空 or ライブ取得モード: CISA KEV を直接叩く ---
    logger.info("DB empty or live mode — fetching from CISA KEV")
    try:
        kev_entries = await fetch_cisa_kev()
    except Exception as e:
        logger.error(f"Failed to fetch CISA KEV: {e}")
        raise HTTPException(status_code=503, detail=f"CISA KEV fetch failed: {e}")

    kev_total = len(kev_entries)

    if enrich_nvd:
        target = kev_entries[:limit]
        try:
            target = await enrich_with_nvd(target, api_key=settings.nvd_api_key)
        except Exception as e:
            logger.warning(f"NVD enrichment failed, proceeding without it: {e}")
        scored = score_all(target)
        if priority:
            scored = [e for e in scored if e.get("priority") == priority.upper()]
        return {
            "count": len(scored),
            "total": kev_total,
            "offset": 0,
            "data": scored,
        }

    scored = score_all(kev_entries)
    if priority:
        scored = [e for e in scored if e.get("priority") == priority.upper()]
    page = scored[offset : offset + limit]
    return {
        "count": len(page),
        "total": len(scored),
        "offset": offset,
        "data": page,
    }


@router.get("/{cve_id}/references")
async def get_cve_references(cve_id: str):
    """CVE の関連リンク（GitHub PoC・記事・アドバイザリ）を返す。"""
    references = get_references(cve_id)
    return {
        "cve_id": cve_id,
        "count": len(references),
        "references": references,
    }
