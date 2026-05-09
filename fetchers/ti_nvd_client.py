"""
Task 1.3: NVD API + EPSS API からの CVE 詳細情報取得

注: EPSS スコアは NVD ではなく First.org (https://api.first.org/data/v1/epss) から取得。
"""
import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"

# NVD API キーなし: 5req/30s、キーあり: 50req/30s
_RATE_DELAY_NO_KEY = 6.5  # 秒（余裕を持たせる）
_RATE_DELAY_WITH_KEY = 0.6


async def fetch_nvd_cve(
    cve_id: str,
    client: httpx.AsyncClient,
    api_key: Optional[str] = None,
) -> dict[str, Any]:
    """NVD API から単一 CVE の詳細を取得する。"""
    headers = {"apiKey": api_key} if api_key else {}
    try:
        response = await client.get(NVD_CVE_URL, params={"cveId": cve_id}, headers=headers)
        response.raise_for_status()
        vulns = response.json().get("vulnerabilities", [])
        return vulns[0].get("cve", {}) if vulns else {}
    except httpx.HTTPStatusError as e:
        logger.warning(f"NVD HTTP {e.response.status_code} for {cve_id}")
        return {}
    except httpx.RequestError as e:
        logger.warning(f"NVD request error for {cve_id}: {e}")
        return {}


async def fetch_epss_scores(
    cve_ids: list[str],
    client: httpx.AsyncClient,
) -> dict[str, float]:
    """EPSS API から複数 CVE のスコアをバッチ取得する（最大 100 件/リクエスト）。"""
    scores: dict[str, float] = {}
    for i in range(0, len(cve_ids), 100):
        chunk = cve_ids[i : i + 100]
        try:
            response = await client.get(EPSS_URL, params={"cve": ",".join(chunk)})
            response.raise_for_status()
            for item in response.json().get("data", []):
                scores[item["cve"]] = float(item.get("epss", 0.0))
        except Exception as e:
            logger.warning(f"EPSS fetch error (chunk {i}): {e}")
    logger.info(f"Got EPSS scores for {len(scores)}/{len(cve_ids)} CVEs")
    return scores


def _extract_cvss_score(nvd_cve: dict[str, Any]) -> Optional[float]:
    """NVD レスポンスから CVSSv3 ベーススコアを抽出する（v3.1 優先）。"""
    try:
        metrics = nvd_cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            if key in metrics:
                return float(metrics[key][0]["cvssData"]["baseScore"])
    except (KeyError, IndexError, TypeError):
        pass
    return None


def _extract_dates(nvd_cve: dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
    """NVD レスポンスから公開日と最終更新日を抽出する。

    Returns:
        (published, last_modified) — どちらも "YYYY-MM-DDTHH:MM:SS.000" 形式か None
    """
    return nvd_cve.get("published"), nvd_cve.get("lastModified")


async def enrich_with_nvd(
    kev_entries: list[dict[str, Any]],
    api_key: Optional[str] = None,
) -> list[dict[str, Any]]:
    """CISA KEV エントリに NVD の CVSS スコアと EPSS スコアを付加する。

    NVD API はレート制限があるため、キーの有無に応じてディレイを調整する。
    EPSS はバッチ取得なのでディレイ不要。
    """
    rate_delay = _RATE_DELAY_WITH_KEY if api_key else _RATE_DELAY_NO_KEY
    cve_ids = [e["cveID"] for e in kev_entries if "cveID" in e]
    enriched: list[dict[str, Any]] = []

    async with httpx.AsyncClient(timeout=30.0) as client:
        # EPSS スコアをまとめて取得（First.org API）
        logger.info(f"Fetching EPSS scores for {len(cve_ids)} CVEs...")
        epss_scores = await fetch_epss_scores(cve_ids, client)

        # NVD から CVSS を 1 件ずつ取得（レート制限対応）
        logger.info(f"Fetching NVD details for {len(cve_ids)} CVEs (delay={rate_delay}s)...")
        for i, entry in enumerate(kev_entries):
            cve_id = entry.get("cveID", "")
            nvd_cve = await fetch_nvd_cve(cve_id, client, api_key) if cve_id else {}
            published, last_modified = _extract_dates(nvd_cve)
            enriched.append(
                {
                    **entry,
                    "epss_score": epss_scores.get(cve_id, 0.0),
                    "cvss_score": _extract_cvss_score(nvd_cve),
                    "published": published,
                    "last_modified": last_modified,
                    "enriched_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            if i < len(kev_entries) - 1:
                await asyncio.sleep(rate_delay)
            if (i + 1) % 10 == 0:
                logger.info(f"  {i + 1}/{len(kev_entries)} done")

    return enriched
