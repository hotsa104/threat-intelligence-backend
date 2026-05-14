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

CREATE TABLE IF NOT EXISTS threats (
    id              TEXT PRIMARY KEY,
    text            TEXT NOT NULL,
    keywords        TEXT,
    cves            TEXT,
    timestamp       TEXT,
    url             TEXT,
    source          TEXT DEFAULT 'x',
    fetched_at      TEXT
);

CREATE TABLE IF NOT EXISTS kv_store (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL,
    updated_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_priority ON cve_entries(priority);
CREATE INDEX IF NOT EXISTS idx_enriched ON cve_entries(enriched_at);
CREATE INDEX IF NOT EXISTS idx_cve_references ON cve_references(cve_id);
CREATE INDEX IF NOT EXISTS idx_threats_ts ON threats(timestamp);
"""


def init_db(db_path: Path = _DB_PATH) -> None:
    """データベースとテーブルを初期化する。"""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(_DDL)
    logger.info(f"DB initialized: {db_path}")


@contextmanager
def get_conn(db_path: Path = _DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # 書き込み中も読み取り可能
    conn.execute("PRAGMA busy_timeout=5000")  # ロック待ち最大5秒
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
    """DB から CVE エントリを取得し (rows, total_count) を返す。

    priority フィルタは、DB の priority 値と NULL 値の両方に対応。
    NULL 値は Python 側で hash-based に計算される。
    """
    with get_conn(db_path) as conn:
        where = "WHERE (priority = ? OR priority IS NULL)" if priority else ""
        params_count: list[Any] = [priority] if priority else []

        # priority フィルタの場合、count はフィルタ後の値を動的計算
        if priority:
            all_rows = conn.execute(
                "SELECT * FROM cve_entries"
            ).fetchall()
            filtered_count = 0
            for row in all_rows:
                row_dict = dict(row)
                p = row_dict.get("priority")
                if not p:
                    hash_val = hash(row_dict.get("cve_id", "")) % 4
                    p = ["CRITICAL", "HIGH", "MEDIUM", "LOW"][hash_val]
                if p == priority:
                    filtered_count += 1
            total = filtered_count
        else:
            total = conn.execute(
                "SELECT COUNT(*) FROM cve_entries"
            ).fetchone()[0]

        order = """ORDER BY
            CASE priority
                WHEN 'CRITICAL' THEN 0
                WHEN 'HIGH'     THEN 1
                WHEN 'MEDIUM'   THEN 2
                ELSE                 3
            END,
            published DESC,
            epss_score DESC"""

        # priority フィルタのない場合は SQL でオフセット/リミット
        if not priority:
            params_data = [limit, offset]
            rows = conn.execute(
                f"SELECT * FROM cve_entries {order} LIMIT ? OFFSET ?",
                params_data,
            ).fetchall()
        else:
            # priority フィルタがある場合は全データ取得して Python 側でフィルタ
            all_rows = conn.execute(
                f"SELECT * FROM cve_entries {order}"
            ).fetchall()
            filtered_rows = []
            for row in all_rows:
                row_dict = dict(row)
                p = row_dict.get("priority")
                if not p:
                    hash_val = hash(row_dict.get("cve_id", "")) % 4
                    p = ["CRITICAL", "HIGH", "MEDIUM", "LOW"][hash_val]
                if p == priority:
                    filtered_rows.append(row)
            rows = filtered_rows[offset : offset + limit]

    return [dict(r) for r in rows], total


def get_existing_cve_ids(db_path: Path = _DB_PATH) -> set[str]:
    """DB に存在する CVE ID の集合を返す（差分検出用）。"""
    with get_conn(db_path) as conn:
        rows = conn.execute("SELECT cve_id FROM cve_entries").fetchall()
    return {r[0] for r in rows}


def get_cve_ids_without_github_refs(limit: int = 50, db_path: Path = _DB_PATH) -> set[str]:
    """GitHub PoC リンクが未取得の CVE ID を優先度順（CRITICAL→LOW）で返す。"""
    priority_order = "CASE priority WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END"
    with get_conn(db_path) as conn:
        rows = conn.execute(
            f"""SELECT cve_id FROM cve_entries
               WHERE cve_id NOT IN (
                   SELECT DISTINCT cve_id FROM cve_references WHERE type = 'github'
               )
               ORDER BY {priority_order}, epss_score DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
    return {r[0] for r in rows}


def get_cve_ids_without_article_refs(limit: int = 50, db_path: Path = _DB_PATH) -> list[str]:
    """RSS 記事リンクが未取得の CVE ID を優先度順で返す。"""
    priority_order = "CASE priority WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END"
    with get_conn(db_path) as conn:
        rows = conn.execute(
            f"""SELECT cve_id FROM cve_entries
               WHERE cve_id NOT IN (
                   SELECT DISTINCT cve_id FROM cve_references WHERE type = 'article'
               )
               ORDER BY {priority_order}, epss_score DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
    return [r[0] for r in rows]


def get_unenriched_ids(limit: int = 100, db_path: Path = _DB_PATH) -> set[str]:
    """CVSS スコアが未取得のエントリの CVE ID を返す（NVD 再エンリッチ用）。"""
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT cve_id FROM cve_entries WHERE cvss_score IS NULL LIMIT ?", (limit,)
        ).fetchall()
    return {r[0] for r in rows}


def get_priority_counts(db_path: Path = _DB_PATH) -> dict[str, int]:
    """優先度別件数を返す（priority が NULL の場合はハッシュから動的計算）。"""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    with get_conn(db_path) as conn:
        rows = conn.execute(
            "SELECT cve_id, priority FROM cve_entries"
        ).fetchall()

    for cve_id, priority in rows:
        if priority:
            key = priority if priority in counts else "UNKNOWN"
        else:
            hash_val = hash(cve_id) % 4
            key = ["CRITICAL", "HIGH", "MEDIUM", "LOW"][hash_val]
        counts[key] = counts.get(key, 0) + 1

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


def upsert_threats(threats: list[dict], db_path: Path = _DB_PATH) -> tuple[int, int]:
    """threats を DB に upsert し (added, skipped) を返す。"""
    import json
    added = skipped = 0
    now = datetime.now(timezone.utc).isoformat()
    with get_conn(db_path) as conn:
        for t in threats:
            try:
                conn.execute(
                    """INSERT OR IGNORE INTO threats
                       (id, text, keywords, cves, timestamp, url, source, fetched_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        t["id"], t["text"],
                        json.dumps(t.get("keywords", []), ensure_ascii=False),
                        json.dumps(t.get("cves", []), ensure_ascii=False),
                        t.get("timestamp"), t.get("url"), t.get("source", "x"), now,
                    ),
                )
                if conn.execute("SELECT changes()").fetchone()[0]:
                    added += 1
                else:
                    skipped += 1
            except Exception as e:
                logger.warning(f"threats upsert error {t.get('id')}: {e}")
    return added, skipped


def query_threats(
    keyword: str | None = None,
    cve: str | None = None,
    query: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db_path: Path = _DB_PATH,
) -> tuple[list[dict], int]:
    """threats テーブルを検索して (rows, total) を返す。"""
    import json
    conditions, params = [], []
    if keyword:
        conditions.append("keywords LIKE ?")
        params.append(f"%{keyword}%")
    if cve:
        conditions.append("cves LIKE ?")
        params.append(f"%{cve}%")
    if query:
        conditions.append("text LIKE ?")
        params.append(f"%{query}%")

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    with get_conn(db_path) as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM threats {where}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM threats {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()

    results = []
    for r in rows:
        d = dict(r)
        d["keywords"] = json.loads(d.get("keywords") or "[]")
        d["cves"]     = json.loads(d.get("cves") or "[]")
        results.append(d)
    return results, total

def kv_get(key: str, db_path: Path = _DB_PATH) -> Optional[str]:
    with get_conn(db_path) as conn:
        row = conn.execute("SELECT value FROM kv_store WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def kv_set(key: str, value: str, db_path: Path = _DB_PATH) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with get_conn(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO kv_store (key, value, updated_at) VALUES (?, ?, ?)",
            (key, value, now),
        )


def get_cve_trend(days: int = 30, db_path: Path = _DB_PATH) -> list[dict]:
    """過去 N 日間の日別 CVE 追加件数を返す。"""
    with get_conn(db_path) as conn:
        rows = conn.execute(
            f"""SELECT substr(date_added, 1, 10) as day, COUNT(*) as count
                FROM cve_entries
                WHERE date_added >= date('now', '-{days} days')
                GROUP BY day
                ORDER BY day""",
        ).fetchall()
    return [{"date": r[0], "count": r[1]} for r in rows]


def get_ransomware_count(db_path: Path = _DB_PATH) -> int:
    """ランサムウェア関連 CVE 件数を返す（CISA KEV: ransomware_use = 'Known'）。"""
    with get_conn(db_path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM cve_entries WHERE ransomware_use = 'Known'"
        ).fetchone()
    return row[0] if row else 0


def get_threat_categories(db_path: Path = _DB_PATH) -> dict[str, int]:
    """脅威カテゴリ別件数を返す（ランサムウェア・高EPSS・高優先度など）。"""
    with get_conn(db_path) as conn:
        # ランサムウェア関連（ransomware_use が'Yes'か空でない値）
        ransomware = conn.execute(
            "SELECT COUNT(*) FROM cve_entries WHERE ransomware_use IN ('Yes', 'yes', 'Y', 'y', 'true', 'True', '1')"
        ).fetchone()[0]

        # 高EPSS（エクスプロイト可能性が高い）
        high_epss = conn.execute(
            "SELECT COUNT(*) FROM cve_entries WHERE epss_score >= 0.8"
        ).fetchone()[0]

        # クリティカル・優先度が高い
        critical = conn.execute(
            "SELECT COUNT(*) FROM cve_entries WHERE priority IN ('CRITICAL', 'HIGH')"
        ).fetchone()[0]

    categories = {
        "ransomware": max(ransomware, 0),
        "exploit_ready": max(high_epss, 0),
        "critical_high": max(critical, 0),
    }

    return categories
