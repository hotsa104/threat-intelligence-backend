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
from db.ti_db import get_last_sync, get_priority_counts, query_entries, get_references, get_threat_categories
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
    """優先度別件数・脅威カテゴリ・最終同期情報を返す。"""
    counts = get_priority_counts()
    categories = get_threat_categories()
    last_sync = get_last_sync()
    total = sum(counts.values())
    return {
        "total": total,
        "priority_counts": counts,
        "threat_categories": categories,
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


@router.post("/refresh-references")
async def refresh_references(
    priority: str = Query(default="CRITICAL"),
    limit: int = Query(default=50, ge=1, le=200),
):
    """NVD API から CVE 参照 URL を取得して cve_references に格納する。"""
    import asyncio
    import sqlite3
    from datetime import datetime, timezone
    from urllib.parse import urlparse
    import httpx
    from db.ti_db import _DB_PATH
    from fetchers.ti_nvd_client import fetch_nvd_cve

    GITHUB_HOSTS = {"github.com", "raw.githubusercontent.com", "gist.github.com"}
    ADVISORY_HOSTS = {
        "cisa.gov", "us-cert.gov", "cert.org", "microsoft.com", "support.microsoft.com",
        "apple.com", "vmware.com", "oracle.com", "redhat.com", "access.redhat.com",
        "ubuntu.com", "debian.org", "suse.com", "cisco.com", "fortinet.com",
        "paloaltonetworks.com", "ivanti.com", "jvn.jp", "jvndb.jvn.jp",
        "portal.msrc.microsoft.com",
    }
    SKIP_HOSTS = {"nvd.nist.gov", "cve.mitre.org", "cvedetails.com"}

    def classify_url(url: str, tags: list) -> str | None:
        try:
            host = urlparse(url).netloc.lower().lstrip("www.")
        except Exception:
            return None
        if host in SKIP_HOSTS:
            return None
        tag_set = {t.lower() for t in tags}
        if "exploit" in tag_set or "proof of concept" in tag_set or host in GITHUB_HOSTS:
            return "github"
        if any(h in host for h in ADVISORY_HOSTS) or "vendor advisory" in tag_set or "patch" in tag_set:
            return "advisory"
        return "article"

    conn = sqlite3.connect(str(_DB_PATH))
    cve_ids = [r[0] for r in conn.execute(
        "SELECT cve_id FROM cve_entries WHERE priority = ? ORDER BY epss_score DESC LIMIT ?",
        (priority.upper(), limit),
    ).fetchall()]
    conn.close()

    api_key = getattr(settings, "nvd_api_key", None) or None
    rate_delay = 0.6 if api_key else 6.5
    total_saved = 0
    now = datetime.now(timezone.utc).isoformat()

    async with httpx.AsyncClient(timeout=30.0) as client:
        for i, cve_id in enumerate(cve_ids):
            try:
                nvd = await fetch_nvd_cve(cve_id, client, api_key)
                refs = nvd.get("references", [])
                conn = sqlite3.connect(str(_DB_PATH))
                for ref in refs:
                    url = ref.get("url", "")
                    ref_type = classify_url(url, ref.get("tags", []))
                    if not ref_type:
                        continue
                    conn.execute(
                        "INSERT OR IGNORE INTO cve_references (cve_id, type, title, url, source, fetched_at) VALUES (?, ?, ?, ?, ?, ?)",
                        (cve_id, ref_type, None, url, ref.get("source"), now),
                    )
                    if conn.execute("SELECT changes()").fetchone()[0]:
                        total_saved += 1
                conn.commit()
                conn.close()
            except Exception as e:
                logger.warning(f"Reference fetch failed for {cve_id}: {e}")
            if i < len(cve_ids) - 1:
                await asyncio.sleep(rate_delay)

    return {"status": "ok", "priority": priority, "cves_processed": len(cve_ids), "references_saved": total_saved}
