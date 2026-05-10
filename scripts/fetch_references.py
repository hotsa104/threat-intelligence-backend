"""
NVD API から CVE の参照 URL を取得して cve_references テーブルに格納するスクリプト。

使い方:
  python scripts/fetch_references.py [--limit N] [--priority CRITICAL]

デフォルト: CRITICAL を EPSS 降順で 50 件
"""
import asyncio
import argparse
import logging
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

# プロジェクトルートを path に追加
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import settings
from fetchers.ti_nvd_client import fetch_nvd_cve

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).parent.parent / "data" / "ti_dashboard.db"

# URL → type 判定
GITHUB_HOSTS  = {"github.com", "raw.githubusercontent.com", "gist.github.com"}
ADVISORY_HOSTS = {
    "cisa.gov", "us-cert.gov", "cert.org", "kb.cert.org",
    "microsoft.com", "support.microsoft.com",
    "apple.com", "support.apple.com",
    "vmware.com", "kb.vmware.com",
    "oracle.com",
    "redhat.com", "access.redhat.com",
    "ubuntu.com", "usn.ubuntu.com",
    "debian.org",
    "suse.com", "bugzilla.suse.com",
    "cisco.com", "tools.cisco.com",
    "fortinet.com",
    "paloaltonetworks.com",
    "ivanti.com",
    "jvn.jp", "jvndb.jvn.jp",
    "portal.msrc.microsoft.com",
}
SKIP_HOSTS = {"nvd.nist.gov", "cve.mitre.org", "cvedetails.com"}

def classify_url(url: str, tags: list[str]) -> str | None:
    """URL と NVD tags から type を判定。None の場合は格納しない。"""
    try:
        from urllib.parse import urlparse
        host = urlparse(url).netloc.lower().lstrip("www.")
    except Exception:
        return None

    if host in SKIP_HOSTS:
        return None

    # tag ベースで判定
    tag_set = {t.lower() for t in tags}
    if "exploit" in tag_set or "proof of concept" in tag_set:
        return "github"
    if host in GITHUB_HOSTS:
        return "github"
    if any(h in host for h in ADVISORY_HOSTS) or "vendor advisory" in tag_set or "patch" in tag_set:
        return "advisory"
    if "technical description" in tag_set or "press/media coverage" in tag_set or "third party advisory" in tag_set:
        return "article"

    return "article"  # その他は article として格納


def get_cves_to_fetch(priority: str, limit: int) -> list[str]:
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT cve_id FROM cve_entries WHERE priority = ? ORDER BY epss_score DESC LIMIT ?",
        (priority, limit),
    ).fetchall()
    conn.close()
    return [r[0] for r in rows]


def save_references(cve_id: str, refs: list[dict]) -> int:
    """refs を cve_references に upsert して格納件数を返す。"""
    conn = sqlite3.connect(DB_PATH)
    saved = 0
    now = datetime.now(timezone.utc).isoformat()
    for ref in refs:
        url  = ref.get("url", "")
        tags = ref.get("tags", [])
        ref_type = classify_url(url, tags)
        if not ref_type:
            continue
        try:
            conn.execute(
                """
                INSERT OR IGNORE INTO cve_references (cve_id, type, title, url, source, fetched_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (cve_id, ref_type, None, url, ref.get("source"), now),
            )
            if conn.execute("SELECT changes()").fetchone()[0]:
                saved += 1
        except Exception as e:
            logger.warning(f"Insert error {cve_id} {url}: {e}")
    conn.commit()
    conn.close()
    return saved


async def run(priority: str, limit: int, api_key: str | None):
    cve_ids = get_cves_to_fetch(priority, limit)
    logger.info(f"対象 CVE: {len(cve_ids)} 件 (priority={priority}, limit={limit})")

    rate_delay = 0.6 if api_key else 6.5
    total_saved = 0

    async with httpx.AsyncClient(timeout=30.0) as client:
        for i, cve_id in enumerate(cve_ids):
            nvd = await fetch_nvd_cve(cve_id, client, api_key)
            refs = nvd.get("references", [])
            saved = save_references(cve_id, refs)
            total_saved += saved
            logger.info(f"[{i+1}/{len(cve_ids)}] {cve_id}: {len(refs)} refs → {saved} 保存")
            if i < len(cve_ids) - 1:
                await asyncio.sleep(rate_delay)

    logger.info(f"完了: 合計 {total_saved} 件を cve_references に格納")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit",    type=int, default=50,         help="取得する CVE 数")
    parser.add_argument("--priority", type=str, default="CRITICAL", help="CRITICAL / HIGH / MEDIUM / LOW")
    args = parser.parse_args()

    api_key = getattr(settings, "NVD_API_KEY", None) or None
    logger.info(f"NVD API key: {'あり' if api_key else 'なし（レート制限 6.5s/req）'}")

    asyncio.run(run(args.priority, args.limit, api_key))
