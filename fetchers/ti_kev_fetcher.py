"""
Task 1.2: CISA KEV API からの脅威データ取得
"""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def fetch_cisa_kev() -> list[dict[str, Any]]:
    """CISA KEV API から最新の既知悪用脆弱性リストを取得する。"""
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(CISA_KEV_URL)
            response.raise_for_status()
            data = response.json()
            vulnerabilities: list[dict[str, Any]] = data.get("vulnerabilities", [])
            logger.info(f"Fetched {len(vulnerabilities)} KEV entries from CISA")
            return vulnerabilities
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error fetching CISA KEV: {e.response.status_code}")
            raise
        except httpx.RequestError as e:
            logger.error(f"Request error fetching CISA KEV: {e}")
            raise


async def save_to_json(data: list[dict[str, Any]], filepath: str | Path) -> None:
    """データを JSON ファイルに保存する。"""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "count": len(data),
        "data": data,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    logger.info(f"Saved {len(data)} entries to {path}")


if __name__ == "__main__":
    import asyncio

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    async def main() -> None:
        vulns = await fetch_cisa_kev()
        await save_to_json(vulns, Path(__file__).parent.parent / "data" / "cisa-kev.json")
        print(f"取得完了: {len(vulns)} 件")

    asyncio.run(main())
