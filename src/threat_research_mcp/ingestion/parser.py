"""Parse RSS/Atom, HTML, and STIX JSON into simple dicts / RawDocument fields."""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree as ET  # nosec B405

from threat_research_mcp.ingestion.errors import IngestionError


def _local(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _elem_text(el: Optional[ET.Element]) -> str:
    if el is None or el.text is None:
        return ""
    return (el.text or "").strip()


def _elem_all_text(el: ET.Element) -> str:
    parts = [el.text or ""]
    for child in el:
        parts.append(_elem_all_text(child))
        if child.tail:
            parts.append(child.tail)
    return "".join(parts).strip()


def parse_feed_xml(xml_text: str) -> List[Dict[str, Any]]:
    """Parse RSS 2.0 or Atom into a list of {title, url, published_at, summary}."""
    try:
        root = ET.fromstring(xml_text)  # nosec B314
    except ET.ParseError as e:
        raise IngestionError(f"Invalid feed XML: {e}") from e

    tag = _local(root.tag).lower()
    out: List[Dict[str, Any]] = []

    if tag == "rss":
        channel = None
        for ch in root:
            if _local(ch.tag).lower() == "channel":
                channel = ch
                break
        if channel is None:
            return out
        for item in channel:
            if _local(item.tag).lower() != "item":
                continue
            title = ""
            link = ""
            pub = ""
            summary = ""
            for child in item:
                ln = _local(child.tag).lower()
                if ln == "title":
                    title = _elem_text(child)
                elif ln == "link":
                    link = _elem_text(child) or (child.get("href") or "")
                elif ln == "pubdate":
                    pub = _elem_text(child)
                elif ln == "date" or child.tag.endswith("date"):
                    if not pub:
                        pub = _elem_text(child)
                elif ln == "description":
                    summary = _elem_all_text(child)
            if title or link:
                out.append(
                    {
                        "title": title or link or "untitled",
                        "url": link,
                        "published_at": pub or None,
                        "summary": summary,
                    }
                )
        return out

    if tag == "feed":
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        entries = root.findall("atom:entry", ns)
        if not entries:
            entries = [c for c in root if _local(c.tag).lower() == "entry"]
        for entry in entries:
            title = ""
            link = ""
            pub = ""
            summary = ""
            for child in entry:
                ln = _local(child.tag).lower()
                if ln == "title":
                    title = _elem_all_text(child)
                elif ln == "link":
                    rel = (child.get("rel") or "alternate").lower()
                    if rel in ("alternate", "self") and child.get("href"):
                        link = child.get("href") or link
                elif ln in ("published", "updated"):
                    if not pub:
                        pub = _elem_text(child)
                elif ln == "summary":
                    summary = _elem_all_text(child)
                elif ln == "content" and not summary:
                    summary = _elem_all_text(child)
            if title or link:
                out.append(
                    {
                        "title": title or link or "untitled",
                        "url": link,
                        "published_at": pub or None,
                        "summary": summary,
                    }
                )
        return out

    raise IngestionError(f"Unsupported feed root element: {tag}")


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._parts: List[str] = []
        self._skip = False

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        t = tag.lower()
        if t in ("script", "style", "noscript"):
            self._skip = True

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t in ("script", "style", "noscript"):
            self._skip = False
        elif t in ("p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4"):
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip and data:
            self._parts.append(data)

    def text(self) -> str:
        raw = "".join(self._parts)
        raw = re.sub(r"[ \t\r\f\v]+", " ", raw)
        raw = re.sub(r"\n{3,}", "\n\n", raw)
        return raw.strip()


def parse_html_title(html: str) -> str:
    m = re.search(r"<title[^>]*>([^<]+)</title>", html, re.I | re.DOTALL)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()
    return ""


def parse_html_to_text(html: str) -> str:
    """Strip tags and scripts; preserve rough paragraph breaks."""
    p = _HTMLTextExtractor()
    try:
        p.feed(html)
        p.close()
    except Exception:
        return re.sub(r"<[^>]+>", " ", html)
    return p.text()


def _stix_str(obj: Dict[str, Any], *keys: str) -> str:
    for k in keys:
        v = obj.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def stix_objects_to_entries(objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Turn STIX 2 SDOs into generic {title, body, url, published_at, tags}."""
    entries: List[Dict[str, Any]] = []

    for obj in objects:
        if not isinstance(obj, dict):
            continue
        typ = (obj.get("type") or "").lower()
        if typ in ("bundle", "relationship", "marking-definition", "language-content"):
            continue

        title = _stix_str(obj, "name", "pattern")
        if not title:
            sid = obj.get("id") or ""
            title = f"{typ} {sid}" if sid else typ

        body_parts: List[str] = []
        desc = _stix_str(obj, "description")
        if desc:
            body_parts.append(desc)
        if typ == "indicator" and obj.get("pattern"):
            body_parts.append(f"Pattern: {obj['pattern']}")
        if typ == "report" and obj.get("object_refs"):
            refs = obj["object_refs"]
            if isinstance(refs, list):
                body_parts.append("Object refs: " + ", ".join(str(r) for r in refs[:50]))
        if typ == "note" and obj.get("content"):
            c = obj["content"]
            if isinstance(c, str):
                body_parts.append(c)
            elif isinstance(c, dict) and "text" in c:
                body_parts.append(str(c["text"]))

        published = _stix_str(obj, "modified", "created", "first_seen", "last_seen")

        tags: List[str] = []
        for lbl in obj.get("labels") or []:
            if isinstance(lbl, str):
                tags.append(lbl)
        for er in obj.get("external_references") or []:
            if isinstance(er, dict):
                ext_id = er.get("external_id")
                if isinstance(ext_id, str):
                    tags.append(ext_id)

        body = "\n\n".join(p for p in body_parts if p)
        if not body:
            body = json.dumps(obj, indent=2)[:8000]

        entries.append(
            {
                "title": title[:500],
                "body": body,
                "url": "",
                "published_at": published or None,
                "tags": tags[:50],
            }
        )

    return entries


def parse_stix_bundle_json(text: str) -> List[Dict[str, Any]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise IngestionError(f"Invalid STIX JSON: {e}") from e

    if not isinstance(data, dict):
        raise IngestionError("STIX root must be a JSON object")

    objects: List[Dict[str, Any]] = []
    if data.get("type", "").lower() == "bundle" and isinstance(data.get("objects"), list):
        objects = [o for o in data["objects"] if isinstance(o, dict)]
    elif isinstance(data.get("objects"), list):
        objects = [o for o in data["objects"] if isinstance(o, dict)]
    else:
        objects = [data]

    return stix_objects_to_entries(objects)
