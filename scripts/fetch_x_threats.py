"""
X (Twitter) から脅威インテルツイートを収集して DB に保存するスクリプト。

使い方:
  python scripts/fetch_x_threats.py [--max N]
"""
import asyncio
import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import settings
from db.ti_db import upsert_threats, init_db
from fetchers.ti_x_fetcher import fetch_x_threats

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


async def run(max_results: int):
    token = settings.x_bearer_token
    if not token:
        logger.error("X_BEARER_TOKEN が設定されていません。.env.local に追記してください。")
        sys.exit(1)

    init_db()

    try:
        threats, next_token = await fetch_x_threats(token, max_results=max_results)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

    added, skipped = upsert_threats(threats)
    logger.info(f"完了: {added} 件追加 / {skipped} 件スキップ（重複）")

    if next_token:
        logger.info(f"次ページあり（next_token={next_token[:20]}...）。再実行で続きを取得できます。")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--max", type=int, default=100, help="取得する最大ツイート数（最大100）")
    args = parser.parse_args()
    asyncio.run(run(args.max))
