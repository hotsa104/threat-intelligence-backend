"""
Phase 2: GitHub API からの Exploit PoC リンク取得

GitHub search API で CVE に関連する exploit リポジトリを検索。
例: github.com/search?q=CVE-2024-1234+exploit
"""
import asyncio
import logging
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"

# GitHub API レート制限: 60req/h (no auth), 6000req/h (with token)
_RATE_DELAY_NO_TOKEN = 1.0  # 秒
_RATE_DELAY_WITH_TOKEN = 0.1


async def search_github_exploits(
    cve_id: str,
    client: httpx.AsyncClient,
    github_token: Optional[str] = None,
) -> list[dict[str, Any]]:
    """GitHub API で CVE exploit リポジトリを検索する。

    Returns:
        [{"url": "...", "title": "...", "stars": N}, ...]
    """
    headers = {"Authorization": f"token {github_token}"} if github_token else {}

    query = f"{cve_id} exploit"
    params = {
        "q": query,
        "sort": "stars",
        "order": "desc",
        "per_page": 5,  # 上位5件のみ
    }

    try:
        response = await client.get(
            GITHUB_SEARCH_URL,
            params=params,
            headers=headers,
            timeout=10.0,
        )
        response.raise_for_status()

        items = response.json().get("items", [])
        results = [
            {
                "url": item["html_url"],
                "title": item["name"],
                "stars": item["stargazers_count"],
                "description": item.get("description", ""),
            }
            for item in items[:5]
        ]
        logger.debug(f"GitHub: found {len(results)} exploit repos for {cve_id}")
        return results

    except httpx.HTTPStatusError as e:
        logger.warning(f"GitHub HTTP {e.response.status_code} for {cve_id}: {e.response.text}")
        return []
    except httpx.RequestError as e:
        logger.warning(f"GitHub request error for {cve_id}: {e}")
        return []
    except Exception as e:
        logger.warning(f"GitHub parse error for {cve_id}: {e}")
        return []


async def fetch_github_exploits_batch(
    cve_ids: list[str],
    github_token: Optional[str] = None,
) -> dict[str, list[dict[str, Any]]]:
    """複数 CVE の exploit リンクをバッチ取得する。

    Returns:
        {cve_id: [{"url": "...", "title": "...", "stars": N}, ...], ...}
    """
    rate_delay = _RATE_DELAY_WITH_TOKEN if github_token else _RATE_DELAY_NO_TOKEN
    results: dict[str, list[dict[str, Any]]] = {}

    async with httpx.AsyncClient(timeout=30.0) as client:
        logger.info(f"Fetching GitHub exploits for {len(cve_ids)} CVEs (delay={rate_delay}s)...")

        for i, cve_id in enumerate(cve_ids):
            exploits = await search_github_exploits(cve_id, client, github_token)
            if exploits:
                results[cve_id] = exploits

            if i < len(cve_ids) - 1:
                await asyncio.sleep(rate_delay)

            if (i + 1) % 10 == 0:
                logger.info(f"  {i + 1}/{len(cve_ids)} done")

    logger.info(f"GitHub fetch complete: {len(results)} CVEs with exploits")
    return results
