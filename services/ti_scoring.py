"""
Task 1.4: CVE 優先度スコアリングロジック

EPSS スコアは 0.0〜1.0 の範囲（0% = ほぼ悪用なし、1.0 = ほぼ確実に悪用される）。
CLAUDE.md の閾値サンプルは 9.0/7.0/5.0 だが、EPSS は 0〜1 なので 0.9/0.7/0.3 に補正。
"""
from typing import Any, Optional

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

_PRIORITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}


def calculate_priority(epss_score: float, cvss_score: Optional[float] = None) -> str:
    """EPSS スコアを優先度文字列に変換する。

    CVSS スコアが高くても EPSS が低い場合は MEDIUM 止まりとする
    （実際に悪用されている証拠を優先）。
    """
    if epss_score >= 0.9:
        return CRITICAL
    elif epss_score >= 0.7:
        return HIGH
    elif epss_score >= 0.3:
        return MEDIUM
    else:
        # CVSS が CRITICAL でも EPSS 低 → HIGH に留める
        if cvss_score is not None and cvss_score >= 9.0:
            return HIGH
        return LOW


def score_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """単一エントリに priority フィールドを付加して返す。"""
    epss = float(entry.get("epss_score") or 0.0)
    cvss = entry.get("cvss_score")
    return {**entry, "priority": calculate_priority(epss, cvss)}


def score_all(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """全エントリをスコアリングし、優先度降順・EPSS 降順でソートして返す。"""
    scored = [score_entry(e) for e in entries]
    return sorted(
        scored,
        key=lambda e: (_PRIORITY_ORDER.get(e["priority"], 4), -float(e.get("epss_score") or 0.0)),
    )
