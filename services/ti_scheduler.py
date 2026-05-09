"""
Phase 2: APScheduler による定期同期ジョブ

- 起動時に1回即実行（DB 空の場合は全件 + NVD エンリッチ）
- 以降は refresh_interval_minutes ごとに実行
- 差分のみ NVD エンリッチ（新規 CVE のみ API 呼び出し）
"""
import logging
from datetime import datetime, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from config import settings
from db.ti_db import (
    get_existing_cve_ids,
    get_unenriched_ids,
    init_db,
    log_sync,
    upsert_entries,
    upsert_references,
)
from fetchers.ti_kev_fetcher import fetch_cisa_kev
from fetchers.ti_nvd_client import enrich_with_nvd
from fetchers.ti_github_fetcher import fetch_github_exploits_batch
from fetchers.ti_rss_fetcher import fetch_rss_feeds_for_cve
from services.ti_scoring import score_all

logger = logging.getLogger(__name__)

_scheduler: AsyncIOScheduler | None = None


async def run_sync() -> None:
    """KEV → 差分検出 → NVD エンリッチ → DB upsert の1サイクル。"""
    logger.info("🔄 Sync job started")
    try:
        kev_entries = await fetch_cisa_kev()
    except Exception as e:
        logger.error(f"KEV fetch failed: {e}")
        log_sync(0, 0, f"error: KEV fetch failed: {e}")
        return

    existing_ids = get_existing_cve_ids()
    unenriched_ids = get_unenriched_ids(limit=100)  # CVSS 未取得: 最大100件/回

    new_entries = [e for e in kev_entries if e.get("cveID") not in existing_ids]
    new_entry_ids = {e.get("cveID") for e in new_entries}
    unenriched_entries = [
        e for e in kev_entries
        if e.get("cveID") in unenriched_ids and e.get("cveID") not in new_entry_ids
    ]
    entries_to_enrich = new_entries + unenriched_entries

    logger.info(
        f"KEV total={len(kev_entries)}, existing={len(existing_ids)}, "
        f"new={len(new_entries)}, unenriched_batch={len(unenriched_entries)}"
    )

    # ─── 即時保存: 新規エントリを NVD エンリッチ前に DB へ保存 ──────────────
    # フロントエンドにすぐデータを表示するため、スコアなしで先に upsert する
    if new_entries:
        pre_added, _ = upsert_entries(new_entries)
        log_sync(pre_added, 0, "partial")
        logger.info(f"✅ Pre-saved {pre_added} new KEV entries (enrichment pending)")

    # 新規 + CVSS 未取得エントリを NVD エンリッチ
    if entries_to_enrich:
        try:
            enriched = await enrich_with_nvd(entries_to_enrich, api_key=settings.nvd_api_key)
        except Exception as e:
            logger.warning(f"NVD enrichment failed, storing without enrichment: {e}")
            enriched = entries_to_enrich
        scored = score_all(enriched)
    else:
        scored = []

    # 既存かつエンリッチ済みエントリは KEV フィールドのみ更新（COALESCE で NVD データ保持）
    enriching_ids = {e.get("cveID") for e in entries_to_enrich}
    existing_entries = [e for e in kev_entries if e.get("cveID") in existing_ids and e.get("cveID") not in enriching_ids]

    added, updated = upsert_entries(scored + existing_entries)
    log_sync(added, updated, "ok")
    logger.info(f"✅ Sync done: added={added}, updated={updated}")

    # ─── GitHub Exploit PoC リンク取得（Phase 2）─────────────────
    try:
        all_cve_ids = [e.get("cveID") for e in kev_entries if e.get("cveID")]
        if all_cve_ids:
            logger.info(f"🔍 Fetching GitHub exploits for {len(all_cve_ids)} CVEs...")
            github_exploits = await fetch_github_exploits_batch(
                all_cve_ids,
                github_token=settings.github_api_token,
            )
            refs_count = 0
            for cve_id, exploits in github_exploits.items():
                refs = [
                    {
                        "type": "github",
                        "title": exp["title"],
                        "url": exp["url"],
                        "source": "github",
                        "metadata": f"stars:{exp.get('stars', 0)}",
                    }
                    for exp in exploits
                ]
                if refs:
                    refs_count += upsert_references(cve_id, refs)
            logger.info(f"✅ GitHub: {refs_count} exploit links stored")
    except Exception as e:
        logger.warning(f"⚠️ GitHub exploit fetch failed: {e}")

    # ─── RSS フィード記事取得（Phase 2）──────────────────────
    try:
        all_cve_ids = [e.get("cveID") for e in kev_entries if e.get("cveID")]
        if all_cve_ids:
            logger.info(f"📰 Fetching RSS articles for {len(all_cve_ids)} CVEs...")
            import httpx
            async with httpx.AsyncClient(timeout=30.0) as client:
                refs_count = 0
                for cve_id in all_cve_ids[:50]:  # RSS は最初の50件のみ（時間制限）
                    articles = await fetch_rss_feeds_for_cve(cve_id, client)
                    refs = [
                        {
                            "type": "article",
                            "title": art["title"],
                            "url": art["url"],
                            "source": art.get("source", "unknown"),
                            "metadata": art.get("pub_date", ""),
                        }
                        for art in articles
                    ]
                    if refs:
                        refs_count += upsert_references(cve_id, refs)
            logger.info(f"✅ RSS: {refs_count} article links stored")
    except Exception as e:
        logger.warning(f"⚠️ RSS fetch failed: {e}")


def start_scheduler() -> AsyncIOScheduler:
    """スケジューラを起動して返す。"""
    global _scheduler
    _scheduler = AsyncIOScheduler(timezone="UTC")
    _scheduler.add_job(
        run_sync,
        trigger="interval",
        minutes=settings.refresh_interval_minutes,
        next_run_time=datetime.now(timezone.utc),  # 起動直後に1回実行
        id="kev_sync",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    _scheduler.start()
    logger.info(
        f"📅 Scheduler started (interval={settings.refresh_interval_minutes}min)"
    )
    return _scheduler


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("📅 Scheduler stopped")
