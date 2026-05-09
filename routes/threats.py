"""
/api/threats エンドポイント

X Threats など外部脅威情報をElasticsearch から取得
（開発モード時はモックデータを返す）
"""
import logging
from typing import Optional
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Query

from config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/threats", tags=["threats"])

# === Mock Data (Development) ===
MOCK_THREATS = [
    {
        "text": "Critical ransomware campaign targeting healthcare institutions detected. Multiple hospitals reporting encryption attacks.",
        "keywords": ["ransomware", "healthcare", "critical"],
        "cves": ["CVE-2024-1234"],
        "timestamp": (datetime.now() - timedelta(hours=1)).isoformat(),
        "url": "https://twitter.com/security/status/1234567890",
        "source": "twitter",
    },
    {
        "text": "Apache Log4j vulnerability (CVE-2021-44228) exploits remain active in enterprise environments.",
        "keywords": ["log4j", "exploit", "critical"],
        "cves": ["CVE-2021-44228"],
        "timestamp": (datetime.now() - timedelta(hours=2)).isoformat(),
        "url": "https://twitter.com/apache/status/1234",
        "source": "twitter",
    },
    {
        "text": "Lazarus Group activity increases with new malware variant targeting cryptocurrency exchanges.",
        "keywords": ["lazarus", "malware", "cryptocurrency"],
        "cves": ["CVE-2024-5678"],
        "timestamp": (datetime.now() - timedelta(hours=3)).isoformat(),
        "url": "https://twitter.com/cisa/status/5678",
        "source": "twitter",
    },
    {
        "text": "Phishing campaign using QR codes to distribute banking trojans. High success rate reported.",
        "keywords": ["phishing", "banking", "trojan"],
        "cves": [],
        "timestamp": (datetime.now() - timedelta(hours=4)).isoformat(),
        "url": "https://reddit.com/r/security/post/123456",
        "source": "reddit",
    },
    {
        "text": "Botnet activity spike detected. DDoS attacks against major ISPs ongoing. Mitigation strategies shared.",
        "keywords": ["botnet", "ddos", "isp"],
        "cves": ["CVE-2024-9999"],
        "timestamp": (datetime.now() - timedelta(hours=5)).isoformat(),
        "url": "https://twitter.com/team/status/9999",
        "source": "twitter",
    },
]


@router.get("")
async def list_threats(
    keyword: Optional[str] = Query(default=None, description="keywords フィールドに match"),
    cve: Optional[str] = Query(default=None, description="cves フィールドに term（CVE-XXXX-XXXXX形式）"),
    query: Optional[str] = Query(default=None, description="text フィールドに match"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """
    X Threats リストを返す（モックデータ）

    パラメータ:
    - keyword: キーワードフィルタ
    - cve: CVE ID フィルタ
    - query: フリーテキスト検索
    - limit: 1回あたりのレコード数（デフォルト50）
    - offset: ページネーション
    """
    # === Mock Data Mode (Fast Return) ===
    filtered = MOCK_THREATS[:]

    if keyword:
        filtered = [
            t for t in filtered
            if any(keyword.lower() in kw.lower() for kw in t.get("keywords", []))
        ]

    if cve:
        filtered = [
            t for t in filtered
            if cve in t.get("cves", [])
        ]

    if query:
        filtered = [
            t for t in filtered
            if query.lower() in t.get("text", "").lower()
        ]

    total = len(filtered)
    data = filtered[offset : offset + limit]

    return {
        "total": total,
        "count": len(data),
        "offset": offset,
        "data": data,
    }
