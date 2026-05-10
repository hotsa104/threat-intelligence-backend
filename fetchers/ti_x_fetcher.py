"""
X (Twitter) API v2 から脅威インテル関連ツイートを収集するフェッチャー。
Bearer Token (App-only auth) で search/recent エンドポイントを使用。
"""
import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

X_SEARCH_URL = "https://api.twitter.com/2/tweets/search/recent"

# 検索クエリ: セキュリティ関連ツイートに絞る
SEARCH_QUERY = (
    "(ransomware OR malware OR exploit OR phishing OR botnet OR APT OR CVE OR vulnerability) "
    "(cybersecurity OR infosec OR threatintel) "
    "lang:en -is:retweet -is:reply"
)

# キーワード判定リスト
KEYWORD_MAP: dict[str, list[str]] = {
    "ransomware":    ["ransomware", "ransom"],
    "malware":       ["malware", "trojan", "spyware", "worm", "backdoor", "rat"],
    "exploit":       ["exploit", "exploitation", "poc", "proof of concept", "log4j", "rce", "lfi", "rfi"],
    "phishing":      ["phishing", "spearphish", "credential", "spear-phishing"],
    "botnet":        ["botnet", "ddos", "distributed denial"],
    "apt":           ["apt", "lazarus", "cozy bear", "fancy bear", "nation-state", "state-sponsored"],
    "vulnerability": ["vulnerability", "zero-day", "0day", "cve-"],
    "critical":      ["critical", "urgent", "emergency patch"],
}

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _extract_keywords(text: str) -> list[str]:
    """テキストからセキュリティキーワードを抽出する。"""
    lower = text.lower()
    found = []
    for kw, patterns in KEYWORD_MAP.items():
        if any(p in lower for p in patterns):
            found.append(kw)
    return found


def _extract_cves(text: str) -> list[str]:
    """テキストから CVE ID を抽出する。"""
    return list({m.upper() for m in CVE_PATTERN.findall(text)})


def _tweet_to_threat(tweet: dict, includes: dict) -> dict:
    """X API レスポンスのツイートを threats 形式に変換する。"""
    tweet_id   = tweet["id"]
    text       = tweet.get("text", "")
    created_at = tweet.get("created_at")

    # URL を entities から取得（展開済み URL を優先）
    url = f"https://x.com/i/web/status/{tweet_id}"
    entities = tweet.get("entities", {})
    for u in entities.get("urls", []):
        expanded = u.get("expanded_url", "")
        if expanded and "x.com" in expanded or "twitter.com" in expanded:
            url = expanded
            break

    return {
        "id":        tweet_id,
        "text":      text,
        "keywords":  _extract_keywords(text),
        "cves":      _extract_cves(text),
        "timestamp": created_at,
        "url":       url,
        "source":    "x",
    }


async def fetch_x_threats(
    bearer_token: str,
    max_results: int = 100,
    next_token: Optional[str] = None,
) -> tuple[list[dict], Optional[str]]:
    since_id: Optional[str] = None,
) -> tuple[list[dict], Optional[str], Optional[str]]:
    """
    X API v2 で最新の脅威インテルツイートを取得する。

    Returns:
        (threats_list, next_token) — next_token は次ページ取得用
        (threats_list, next_token, newest_id) — newest_id は次回の since_id に使う
    """
    headers = {"Authorization": f"Bearer {bearer_token}"}
    params: dict[str, Any] = {
        "query":        SEARCH_QUERY,
        "max_results":  min(max_results, 100),
        "tweet.fields": "created_at,entities,public_metrics",
        "expansions":   "author_id",
    }
    if next_token:
        params["next_token"] = next_token
    if since_id:
        params["since_id"] = since_id

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            resp = await client.get(X_SEARCH_URL, headers=headers, params=params)
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            if status == 401:
                raise ValueError("X Bearer Token が無効です。.env.local の X_BEARER_TOKEN を確認してください。")
            if status == 403:
                raise ValueError("X API の権限が不足しています（Basic tier 以上が必要です）。")
            if status == 429:
                raise ValueError("X API のレート制限に達しました。しばらく待ってから再実行してください。")
            raise

        body = resp.json()

    tweets   = body.get("data", [])
    includes = body.get("includes", {})
    meta     = body.get("meta", {})

    threats    = [_tweet_to_threat(t, includes) for t in tweets]
    next_tok   = meta.get("next_token")

    logger.info(f"X API: {len(threats)} ツイート取得 (result_count={meta.get('result_count')})")
    return threats, next_tok
