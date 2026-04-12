"""SQLite persistence for workflow runs, ingested intel, and analysis products."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

PathLike = Union[str, Path]


def _connect(db_path: PathLike) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(str(path))


def _like_pattern(user_fragment: str) -> str:
    """Build a LIKE pattern; escape %, _, and \\ for use with ESCAPE '\\'."""
    s = user_fragment.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{s}%"


def init_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS workflow_runs (
            id TEXT PRIMARY KEY,
            workflow_type TEXT NOT NULL,
            input_preview TEXT NOT NULL,
            output_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS normalized_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL,
            source_name TEXT NOT NULL,
            source_type TEXT NOT NULL DEFAULT '',
            title TEXT NOT NULL DEFAULT '',
            url TEXT NOT NULL DEFAULT '',
            published_at TEXT,
            normalized_text TEXT NOT NULL,
            document_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_norm_docs_fingerprint ON normalized_documents(fingerprint)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_norm_docs_source_name ON normalized_documents(source_name)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_norm_docs_created ON normalized_documents(created_at)"
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analysis_products (
            row_id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id TEXT NOT NULL,
            workflow_type TEXT NOT NULL DEFAULT '',
            narrative_summary TEXT NOT NULL DEFAULT '',
            product_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ap_product_id ON analysis_products(product_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ap_created ON analysis_products(created_at)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ap_workflow ON analysis_products(workflow_type)"
    )
    conn.commit()


def save_workflow_run(
    db_path: PathLike,
    *,
    run_id: str,
    workflow_type: str,
    input_text: str,
    output_payload: dict,
    input_preview_max: int = 4000,
) -> None:
    """Persist one CLI/MCP workflow result as JSON. No-op callers validate path."""
    preview = input_text if len(input_text) <= input_preview_max else input_text[:input_preview_max] + "…"
    payload = json.dumps(output_payload, ensure_ascii=False)
    conn = _connect(db_path)
    try:
        init_schema(conn)
        conn.execute(
            """
            INSERT INTO workflow_runs (id, workflow_type, input_preview, output_json)
            VALUES (?, ?, ?, ?)
            """,
            (run_id, workflow_type, preview, payload),
        )
        conn.commit()
    finally:
        conn.close()


def save_normalized_documents(db_path: PathLike, documents: List[Any]) -> int:
    """Insert normalized intel rows (append-only history). Returns rows inserted."""
    if not documents:
        return 0
    conn = _connect(db_path)
    inserted = 0
    try:
        init_schema(conn)
        for doc in documents:
            data = doc.model_dump(mode="json") if hasattr(doc, "model_dump") else dict(doc)
            fp = str(data.get("fingerprint") or "")
            if not fp:
                continue
            conn.execute(
                """
                INSERT INTO normalized_documents (
                    fingerprint, source_name, source_type, title, url,
                    published_at, normalized_text, document_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fp,
                    str(data.get("source_name") or ""),
                    str(data.get("source_type") or ""),
                    str(data.get("title") or ""),
                    str(data.get("url") or ""),
                    data.get("published_at"),
                    str(data.get("normalized_text") or ""),
                    json.dumps(data, ensure_ascii=False),
                ),
            )
            inserted += 1
        conn.commit()
    finally:
        conn.close()
    return inserted


def save_analysis_product(
    db_path: PathLike,
    *,
    workflow_type: str,
    product: Dict[str, Any],
) -> None:
    """Persist one AnalysisProduct dict (append-only; same product_id may appear more than once)."""
    pid = str(product.get("product_id") or "").strip()
    if not pid:
        return
    narrative = str(product.get("narrative_summary") or "")[:16000]
    payload = json.dumps(product, ensure_ascii=False)
    conn = _connect(db_path)
    try:
        init_schema(conn)
        conn.execute(
            """
            INSERT INTO analysis_products (
                product_id, workflow_type, narrative_summary, product_json
            )
            VALUES (?, ?, ?, ?)
            """,
            (pid, workflow_type or "", narrative, payload),
        )
        conn.commit()
    finally:
        conn.close()


def search_normalized_documents(
    db_path: PathLike,
    *,
    text_query: str = "",
    source_name: str = "",
    fingerprint: str = "",
    limit: int = 50,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """Search ingested documents by optional text (title + body), source, or exact fingerprint."""
    conn = _connect(db_path)
    try:
        init_schema(conn)
        clauses: List[str] = []
        params: List[Any] = []
        if fingerprint.strip():
            clauses.append("fingerprint = ?")
            params.append(fingerprint.strip())
        else:
            if text_query.strip():
                pat = _like_pattern(text_query.strip())
                clauses.append(
                    "(title LIKE ? ESCAPE '\\' OR normalized_text LIKE ? ESCAPE '\\')"
                )
                params.extend([pat, pat])
            if source_name.strip():
                clauses.append("source_name LIKE ? ESCAPE '\\'")
                params.append(_like_pattern(source_name.strip()))
        where_sql = " AND ".join(clauses) if clauses else "1=1"
        lim = max(1, min(int(limit), 200))
        off = max(0, int(offset))
        sql = f"""
            SELECT id, fingerprint, source_name, source_type, title, url,
                   published_at, created_at,
                   substr(normalized_text, 1, 500) AS text_preview
            FROM normalized_documents
            WHERE {where_sql}
            ORDER BY datetime(created_at) DESC
            LIMIT ? OFFSET ?
        """  # nosec B608
        params.extend([lim, off])
        cur = conn.execute(sql, params)
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in rows]
    finally:
        conn.close()


def search_analysis_products(
    db_path: PathLike,
    *,
    text_query: str = "",
    workflow_type: str = "",
    limit: int = 50,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """Search stored analysis products by narrative / JSON substring and optional workflow."""
    conn = _connect(db_path)
    try:
        init_schema(conn)
        clauses: List[str] = []
        params: List[Any] = []
        if workflow_type.strip():
            clauses.append("workflow_type = ?")
            params.append(workflow_type.strip())
        if text_query.strip():
            pat = _like_pattern(text_query.strip())
            clauses.append(
                "(narrative_summary LIKE ? ESCAPE '\\' OR product_json LIKE ? ESCAPE '\\')"
            )
            params.extend([pat, pat])
        where_sql = " AND ".join(clauses) if clauses else "1=1"
        lim = max(1, min(int(limit), 200))
        off = max(0, int(offset))
        sql = f"""
            SELECT row_id, product_id, workflow_type, created_at,
                   substr(narrative_summary, 1, 400) AS narrative_preview
            FROM analysis_products
            WHERE {where_sql}
            ORDER BY datetime(created_at) DESC
            LIMIT ? OFFSET ?
        """  # nosec B608
        params.extend([lim, off])
        cur = conn.execute(sql, params)
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in rows]
    finally:
        conn.close()


def get_analysis_product_by_row_id(
    db_path: PathLike, row_id: int
) -> Optional[Dict[str, Any]]:
    """Fetch full product JSON for one stored row."""
    conn = _connect(db_path)
    try:
        init_schema(conn)
        row = conn.execute(
            "SELECT product_json FROM analysis_products WHERE row_id = ?",
            (int(row_id),),
        ).fetchone()
        if not row:
            return None
        return json.loads(row[0])
    finally:
        conn.close()
