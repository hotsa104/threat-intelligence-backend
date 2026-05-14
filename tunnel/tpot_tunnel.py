"""
T-pot Elasticsearch への SSH トンネル管理。

起動: open_tunnel() → ES クエリ → close_tunnel()
または async with managed_tunnel(): でコンテキスト管理。
"""
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

_tunnel = None  # sshtunnel.SSHTunnelForwarder


def _get_key_path(raw: str) -> str:
    return str(Path(raw).expanduser())


def open_tunnel(
    ssh_host: str,
    ssh_port: int,
    ssh_user: str,
    ssh_key: str,
    remote_es_host: str,
    remote_es_port: int,
    local_bind_port: int,
) -> bool:
    """SSH トンネルを開く。成功時 True を返す。"""
    global _tunnel
    try:
        from sshtunnel import SSHTunnelForwarder
    except ImportError:
        logger.warning("sshtunnel がインストールされていません")
        return False

    try:
        key_path = _get_key_path(ssh_key)
        if not Path(key_path).exists():
            logger.warning(f"SSH キーが見つかりません: {key_path}")
            return False

        _tunnel = SSHTunnelForwarder(
            (ssh_host, ssh_port),
            ssh_username=ssh_user,
            ssh_pkey=key_path,
            remote_bind_address=(remote_es_host, remote_es_port),
            local_bind_address=("127.0.0.1", local_bind_port),
            set_keepalive=30,
        )
        _tunnel.start()
        logger.info(f"✅ SSH トンネル開通: {ssh_host}:{ssh_port} → localhost:{local_bind_port}")
        return True
    except Exception as e:
        logger.warning(f"⚠️ SSH トンネル接続失敗: {e}")
        _tunnel = None
        return False


def close_tunnel() -> None:
    global _tunnel
    if _tunnel and _tunnel.is_active:
        _tunnel.stop()
        logger.info("🔌 SSH トンネル切断")
    _tunnel = None


def is_tunnel_active() -> bool:
    return _tunnel is not None and _tunnel.is_active


@asynccontextmanager
async def managed_tunnel(settings):
    """設定から SSH トンネルを開き、終了時に閉じるコンテキストマネージャ。"""
    opened = open_tunnel(
        ssh_host=settings.tpot_ssh_host,
        ssh_port=settings.tpot_ssh_port,
        ssh_user=settings.tpot_ssh_user,
        ssh_key=settings.tpot_ssh_key,
        remote_es_host=settings.tpot_es_host,
        remote_es_port=settings.tpot_es_port,
        local_bind_port=settings.local_tpot_bind_port,
    )
    try:
        yield opened
    finally:
        if opened:
            close_tunnel()


async def fetch_tpot_stats(local_bind_port: int) -> dict:
    """
    T-pot ES から過去 24h の攻撃統計を取得する。

    Returns:
        {"available": True, "total": N, "top_ports": [...]}
    """
    url = f"http://127.0.0.1:{local_bind_port}"
    query = {
        "size": 0,
        "query": {
            "range": {"@timestamp": {"gte": "now-24h"}}
        },
        "aggs": {
            "top_ports": {
                "terms": {"field": "dest_port", "size": 10}
            },
            "top_src_ips": {
                "terms": {"field": "src_ip", "size": 10}
            },
        },
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        # インデックスは T-pot のデフォルト（logstash-*）
        resp = await client.post(
            f"{url}/logstash-*/_search",
            json=query,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        body = resp.json()

    total = body.get("hits", {}).get("total", {})
    total_count = total.get("value", 0) if isinstance(total, dict) else int(total)

    aggs = body.get("aggregations", {})
    buckets = aggs.get("top_ports", {}).get("buckets", [])
    top_ports = [{"port": b["key"], "count": b["doc_count"]} for b in buckets]

    ip_buckets = aggs.get("top_src_ips", {}).get("buckets", [])
    top_src_ips = [{"ip": b["key"], "count": b["doc_count"]} for b in ip_buckets]

    return {
        "available": True,
        "total": total_count,
        "top_ports": top_ports,
        "top_src_ips": top_src_ips,
    }
