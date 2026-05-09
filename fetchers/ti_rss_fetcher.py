"""
Phase 2: RSS フィード からのセキュリティ記事取得

- SecurityFocus BugTraq RSS
- Exploit-DB RSS
"""
import asyncio
import logging
from typing import Any, Optional
from datetime import datetime, timezone

import httpx
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

RSS_FEEDS = {
    "securityfocus": "https://www.securityfocus.com/rss/vulnerabilities.xml",
    "exploit-db": "https://www.exploit-db.com/rss.xml",
}

_RATE_DELAY = 0.5  # 秒


async def parse_rss_feed(
    feed_url: str,
    client: httpx.AsyncClient,
    timeout: int = 15,
) -> list[dict[str, Any]]:
    """RSS フィードをパースして記事リストを返す。

    Returns:
        [{"title": "...", "url": "...", "pub_date": "...", "description": "..."}, ...]
    """
    try:
        response = await client.get(feed_url, timeout=timeout)
        response.raise_for_status()

        root = ET.fromstring(response.content)
        items = []

        # RSS フォーマット: <rss><channel><item>...
        # Atom フォーマット: <feed><entry>...
        for item in root.findall(".//item") + root.findall(".//entry"):
            title_elem = item.find("title")
            link_elem = item.find("link")
            pub_date_elem = item.find("pubDate") or item.find("published")
            desc_elem = item.find("description") or item.find("summary")

            title = title_elem.text if title_elem is not None else ""
            link = link_elem.text if link_elem is not None else ""
            if link_elem is not None and link_elem.get("href"):
                link = link_elem.get("href")

            pub_date = pub_date_elem.text if pub_date_elem is not None else ""
            description = desc_elem.text if desc_elem is not None else ""

            if title and link:
                items.append(
                    {
                        "title": title,
                        "url": link,
                        "pub_date": pub_date,
                        "description": description,
                    }
                )

        logger.debug(f"RSS: parsed {len(items)} items from {feed_url}")
        return items[:10]  # 最新10件のみ

    except Exception as e:
        logger.warning(f"RSS parse error from {feed_url}: {e}")
        return []


async def fetch_rss_feeds_for_cve(
    cve_id: str,
    client: httpx.AsyncClient,
) -> list[dict[str, Any]]:
    """複数の RSS フィードから CVE 関連の記事を検索する（キーワードマッチング）。

    Returns:
        [{"title": "...", "url": "...", "pub_date": "...", "source": "..."}, ...]
    """
    results = []

    for source, feed_url in RSS_FEEDS.items():
        items = await parse_rss_feed(feed_url, client)
        # タイトルに CVE ID が含まれる記事のみ
        matching = [
            {**item, "source": source}
            for item in items
            if cve_id.lower() in item["title"].lower()
            or cve_id.lower() in item.get("description", "").lower()
        ]
        results.extend(matching)

        await asyncio.sleep(_RATE_DELAY)

    return results


async def fetch_all_rss_articles(
    limit: int = 50,
) -> list[dict[str, Any]]:
    """全 RSS フィードから最新記事を取得する（RSS 監視用）。"""
    articles = []

    async with httpx.AsyncClient(timeout=30.0) as client:
        for source, feed_url in RSS_FEEDS.items():
            items = await parse_rss_feed(feed_url, client)
            articles.extend([{**item, "source": source} for item in items])

            await asyncio.sleep(_RATE_DELAY)

    # 最新順でソート（pub_date でパース可能な場合）
    return articles[:limit]
