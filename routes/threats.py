"""
/api/threats エンドポイント

DB に threats データがあれば返し、なければモックデータを返す。
"""
import logging
from typing import Optional
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Query

from config import settings
from db.ti_db import query_threats, upsert_threats
from fetchers.ti_x_fetcher import fetch_x_threats

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/threats", tags=["threats"])

MOCK_THREATS = [
    {
        "id": "mock-1",
        "text": "Critical ransomware campaign targeting healthcare institutions detected.",
        "keywords": ["ransomware", "critical"],
        "cves": ["CVE-2024-1234"],
        "timestamp": (datetime.now() - timedelta(hours=1)).isoformat(),
        "url": "https://x.com/security/status/1234567890",
        "source": "x",
    },
    {
        "id": "mock-2",
        "text": "Apache Log4j vulnerability (CVE-2021-44228) exploits remain active.",
        "keywords": ["exploit", "vulnerability"],
        "cves": ["CVE-2021-44228"],
        "timestamp": (datetime.now() - timedelta(hours=2)).isoformat(),
        "url": "https://x.com/apache/status/1234",
        "source": "x",
    },
    {
        "id": "mock-3",
        "text": "Lazarus Group activity with new malware variant targeting crypto exchanges.",
        "keywords": ["apt", "malware"],
        "cves": [],
        "timestamp": (datetime.now() - timedelta(hours=3)).isoformat(),
        "url": "https://x.com/cisa/status/5678",
        "source": "x",
    },
    {
        "id": "mock-4",
        "text": "Phishing campaign using QR codes to distribute banking trojans.",
        "keywords": ["phishing", "malware"],
        "cves": [],
        "timestamp": (datetime.now() - timedelta(hours=4)).isoformat(),
        "url": "https://x.com/team/status/9999",
        "source": "x",
    },
    {
        "id": "mock-5",
        "text": "Botnet DDoS attacks against major ISPs ongoing.",
        "keywords": ["botnet"],
        "cves": [],
        "timestamp": (datetime.now() - timedelta(hours=5)).isoformat(),
        "url": "https://x.com/team/status/0001",
        "source": "x",
    },
]


@router.get("")
async def list_threats(
    keyword: Optional[str] = Query(default=None),
    cve:     Optional[str] = Query(default=None),
    query:   Optional[str] = Query(default=None),
    limit:   int = Query(default=50, ge=1, le=500),
    offset:  int = Query(default=0, ge=0),
):
    # DB にデータがあれば使う
    try:
        rows, total = query_threats(keyword=keyword, cve=cve, query=query, limit=limit, offset=offset)
        if total > 0:
            return {"total": total, "count": len(rows), "offset": offset, "data": rows}
    except Exception as e:
        logger.warning(f"DB query failed, falling back to mock: {e}")

    # DB が空 or エラー → モックデータ
    filtered = MOCK_THREATS[:]
    if keyword:
        filtered = [t for t in filtered if any(keyword.lower() in k for k in t["keywords"])]
    if cve:
        filtered = [t for t in filtered if cve in t["cves"]]
    if query:
        filtered = [t for t in filtered if query.lower() in t["text"].lower()]

    return {"total": len(filtered), "count": len(filtered[offset:offset+limit]), "offset": offset, "data": filtered[offset:offset+limit]}

@router.post("/refresh")
async def refresh_threats(max_results: int = Query(default=100, ge=10, le=100)):
    """X API からリアルタイムで脅威ツイートを取得して DB に保存する。"""
    token = settings.x_bearer_token
    if not token:
        raise HTTPException(status_code=503, detail="X_BEARER_TOKEN が設定されていません。")

    try:
        threats, _ = await fetch_x_threats(token, max_results=max_results)
    except ValueError as e:
        raise HTTPException(status_code=502, detail=str(e))

    added, skipped = upsert_threats(threats)
    return {"fetched": len(threats), "added": added, "skipped": skipped}
    
