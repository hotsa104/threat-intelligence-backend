"""
Phase 2: SQLite データベース層

cve_entries テーブル: CISA KEV + NVD/EPSS エンリッチ済みデータ
sync_log テーブル: 同期履歴
"""
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Optional

logger = logging.getLogger(__name__)

# Render 永続ディスクは DB_PATH 環境変数で指定、なければローカルの data/ を使用
_DB_PATH = Path(os.environ.get("DB_PATH", str(Path(__file__).parent.parent / "data" / "ti_dashboard.db")))

_DDL = """
CREATE TABLE IF NOT EXISTS cve_entries (
    cve_id          TEXT PRIMARY KEY,
    vendor          TEXT,
    product         TEXT,
    vuln_name       TEXT,
    date_added      TEXT,
    due_date        TEXT,
    short_desc      TEXT,
    published       TEXT,
    last_modified   TEXT,
    cvss_score      REAL,
    epss_score      REAL,
    priority        TEXT,
    ransomware_use  TEXT,
    enriched_at     TEXT,
    updated_at      TEXT
);

CREATE TABLE IF NOT EXISTS sync_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at          TEXT NOT NULL,
    entries_added   INTEGER DEFAULT 0,
    entries_updated INTEGER DEFAULT 0,
    status          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cve_references (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id          TEXT NOT NULL,
    type            TEXT NOT NULL,
    title           TEXT,
    url             TEXT NOT NULL,
    source          TEXT,
    metadata        TEXT,
    fetched_at      TEXT,
    FOREIGN KEY (cve_id) REFERENCES cve_entries(cve_id),
    UNIQUE (cve_id, url)
);

CREATE INDEX IF NOT EXISTS idx_priority ON cve_entries(priority);
CREATE INDEX IF NOT EXISTS idx_enriched ON cve_entries(enriched_at);
CREATE INDEX IF NOT EXISTS idx_cve_references ON cve_references(cve_id);
"""


def init_db(db_path: Path = _DB_PATH) -> None:
    """データベースとテーブルを初期化する。"""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(_DDL)
    logger.info(f"DB initialized: {db_path}")


@contextmanager
def get_conn(db_path: Path = _DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def upsert_entries(entries: list[dict[str, Any]], db_path: Path = _DB_PATH) -> tuple[int, int]:
    """entries を DB に upsert し (added, updated) 件数を返す。"""
    added = updated = 0
    now = datetime.now(timezone.utc).isoformat()

    with get_conn(db_path) as conn:
        for e in entries:
            cve_id = e.get("cveID") or e.get("cve_id", "")
            if not cve_id:
                continue

            existing = conn.execute(
                "SELECT cve_id FROM cve_entries WHERE cve_id = ?", (cve_id,)
            ).fetchone()

            row = {
                "cve_id": cve_id,
                "vendor": e.get("vendorProject"),
                "product": e.get("product"),
                "vuln_name": e.get("vulnerabilityName"),
                "date_added": e.get("dateAdded"),
                "due_date": e.get("dueDate"),
                "short_desc": e.get("shortDescription"),
                "published": e.get("published"),
                "last_modified": e.get("last_modified"),
                "cvss_score": e.get("cvss_score"),
                "epss_score": e.get("epss_score"),
                "priority": e.get("priority"),
                "ransomware_use": e.get("knownRansomwareCampaignUse"),
                "enriched_at": e.get("enriched_at"),
                "updated_at": now,
            }

            if existing:
                conn.execute(
                    """UPDATE cve_entries SET
                        vendor=:vendor, product=:product, vuln_name=:vuln_name,
                        date_added=:date_added, due_date=:due_date, short_desc=:short_desc,
                        ransomware_use=:ransomware_use, updated_at=:updated_at,
                        published=COALESCE(:published, published),
                        last_modified=COALESCE(:last_modified, last_modified),
                        cvss_score=COALESCE(:cvss_score, cvss_score),
                        epss_score=COALESCE(:epss_score, epss_score),
                        priority=COALESCE(:priority, priority),
                        enriched_at=COALESCE(:enriched_at, enriched_at)
                    WHERE cve_id=:cve_id""",
                    row,
                )
                updated += 1
            else:
                conn.execute(
                    """INSERT INTO cve_entries
                        (cve_id, vendor, product, vuln_name, date_added, due_date,
                         short_desc, published, last_modified, cvss_score, epss_score,
                         priority, ransomware_use, enriched_at, updated_at)
                    VALUES
                        (:cve_id, :vendor, :product, :vuln_name, :date_added, :due_date,
                         :short_desc, :published, :last_modified, :cvss_score, :epss_score,
                         :priority, :ransomware_use, :enriched_at, :updated_at)""",
                    row,
                )
                added += 1

    return added, updated


def log_sync(
    added: int,
    updated: int,
    status: str,
    db_path: Path = _DB_PATH,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with get_conn(db_path) as conn:
        conn.execute(
            "INSERT INTO sync_log (run_at, entries_added, entries_updated, status) VALUES (?,?,?,?)",
            (now, added, updated, status),
        )


def query_entries(
    priority: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    db_path: Path = _DB_PATH,
) -> tuple[list[dict], int]:
    """DB から CVE エントリを取得し (rows, total_count) を返す。"""
    with get_conn(db_path) as conn:
        where = "WHERE priority = ?" if priority else ""
        params_count: list[Any] = [priority] if priority else []
        total = conn.execute(
            f"SELECT COUNT(*) FROM cve_entries {where}", params_count
        ).fetchone()[0]

        order = """ORDER BY
            CASE priority
                WHEN 'CRITICAL' THEN 0
                WHEN 'HIGH'     THEN 1
                WHEN 'MEDIUM'   THEN 2
                ELSE                 3
            END,
            epss_score DESC"""
        params_data: list[Any] = [priority] if priority else []
        params_data += [limit, offset]
        rows = conn.execute(
            f"SELECT * FROM cve_entries {where} {order} LIMIT ? OFFSET ?",
            params_data,
        ).fetchall()

    return [dict(r) for r in rows], total


def get_existing_cve_ids(db_path: Path = _DB_PATH) -> set[str]:
    """DB に存在する CVE ID の集合を返す（差分検出用）。"""
    with get_conn(db_path) as conn:
        rows = conn.execute("SELECT cve_id FROM cve_entries").fetchall()
    return {r[0] for r in rows}


def get_cve_ids_without_github_refs(limit: int = 50, db_path: Path = _DB_PATH) -> set[str]:
    """GitHub PoC リンクが未取得の CVE ID を返す（差分取得用）。"""
    with get_conn(db_path) as conn:
        rows = conn.execute(
            """SELECT cve_id FROM cve_entries
               WHERE cve_id NOT IN (
                   SELECT DISTINCT cve_id FROM cve_references WHERE type = 'github'
               )
               LIMIT ?""",
            (limit,),
        ).fetchall()
    return {r[0] for r in rows}


def get_unenriched_ids(limit: int = 100, db_path: Path = _DB_PATH) -> set[str]:
    """CVSS スコアが未取得のエントリの CVE ID を返す（NVD 再エンリッチ用）。"""
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT cve_id FROM cve_entries WHERE cvss_score IS NULL LIMIT ?", (limit,)
        ).fetchall()
    return {r[0] for r in rows}


def get_priority_counts(db_path: Path = _DB_PATH) -> dict[str, int]:
    """優先度別件数を返す。"""
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT priority, COUNT(*) FROM cve_entries GROUP BY priority"
        ).fetchall()
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for priority, cnt in rows:
        key = priority if priority in counts else "UNKNOWN"
        counts[key] = cnt
    return counts


def get_last_sync(db_path: Path = _DB_PATH) -> Optional[dict]:
    """最新の同期ログを返す。"""
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM sync_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return dict(row) if row else None


# ─── CVE References（関連リンク）────────────────────────────
def upsert_references(
    cve_id: str,
    references: list[dict[str, Any]],
    db_path: Path = _DB_PATH,
) -> int:
    """CVE の関連リンクを upsert し、追加・更新件数を返す。

    Args:
        cve_id: CVE ID
        references: [{"type": "github"/"article"/"advisory", "title": "...", "url": "...", ...}, ...]

    Returns:
        upserted count
    """
    now = datetime.now(timezone.utc).isoformat()
    upserted = 0

    with get_conn(db_path) as conn:
        for ref in references:
            ref_type = ref.get("type", "unknown")
            url = ref.get("url", "")
            if not url:
                continue

            title = ref.get("title", "")
            source = ref.get("source")
            metadata = ref.get("metadata")

            try:
                conn.execute(
                    """INSERT OR IGNORE INTO cve_references
                        (cve_id, type, title, url, source, metadata, fetched_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (cve_id, ref_type, title, url, source, metadata, now),
                )
                upserted += 1
            except Exception as e:
                logger.warning(f"Failed to upsert reference for {cve_id}: {e}")

    return upserted


def get_references(cve_id: str, db_path: Path = _DB_PATH) -> list[dict]:
    """CVE の関連リンクを取得する。"""
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM cve_references WHERE cve_id = ? ORDER BY type, fetched_at DESC",
            (cve_id,),
        ).fetchall()
    return [dict(r) for r in rows]
