from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from shutil import copy2
from zipfile import ZIP_DEFLATED, ZipFile

from lxml import etree


DOCX = Path(__file__).with_name("基于 Rust 的 L4∕L7 协同 Web 防护系统设计与实现.docx")
BACKUP = DOCX.with_name(DOCX.stem + "_before_discoverability_enhance.docx")
NS = {
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
}
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"

TITLE = "基于 Rust 的 L4/L7 协同 Web 防护系统设计与实现"
CN_KEYWORDS = (
    "关键词：Rust；网络应用防火墙；Web Application Firewall；WAF；四层/七层协同防护；"
    "L4/L7；HTTP/2；HTTP/3；QUIC；规则引擎；Bloom Filter；SQLite；Vue 控制台"
)
EN_KEYWORDS = (
    "Key words: Rust; Web Application Firewall; WAF; L4/L7 Collaborative Protection; "
    "HTTP/2; HTTP/3; QUIC; Rule Engine; Bloom Filter; SQLite; Vue Management Console"
)
DISCOVERABILITY_PARA = (
    "在术语表述上，本文统一采用网络应用防火墙（Web Application Firewall，WAF）、"
    "四层/七层协同防护（L4/L7 collaborative protection）、统一请求抽象"
    "（Unified HTTP Request）、规则引擎（Rule Engine）、滑动窗口限流"
    "（Sliding Window Rate Limiting）、Bloom Filter、HTTP/2、HTTP/3、QUIC、TLS、"
    "Tokio、SQLite和Vue控制台等核心概念，以便使系统设计、算法描述和工程实现能够被"
    "相关检索系统准确归类到Web安全、网络应用防护、多协议网关和Rust异步网络服务等主题下。"
)
META_KEYWORDS = (
    "Rust, Web Application Firewall, WAF, L4/L7, Layer 4, Layer 7, HTTP/2, HTTP/3, "
    "QUIC, TLS, Rule Engine, Bloom Filter, Sliding Window Rate Limiting, SQLite, "
    "Vue, Tokio, Axum, Web Security, Network Security Gateway"
)
META_DESCRIPTION = (
    "本文设计并实现了一套基于Rust的L4/L7协同Web防护系统，内容涵盖网络应用防火墙、"
    "多协议接入、HTTP/2、HTTP/3、QUIC、规则引擎、Bloom Filter、SQLite持久化、"
    "Vue控制台和Web安全测试等主题。"
)


def para_text(p: etree._Element) -> str:
    return "".join(p.xpath(".//w:t/text()", namespaces=NS)).strip()


def set_labeled_text(p: etree._Element, text: str, label: str) -> None:
    for r in list(p.findall("w:r", NS)):
        p.remove(r)
    bold = etree.Element(W + "rPr")
    etree.SubElement(bold, W + "b")
    add_run(p, label, bold)
    add_run(p, text[len(label):], None)


def add_run(p: etree._Element, text: str, rpr: etree._Element | None = None) -> None:
    r = etree.SubElement(p, W + "r")
    if rpr is not None:
        r.append(deepcopy(rpr))
    t = etree.SubElement(r, W + "t")
    if text.startswith(" ") or text.endswith(" "):
        t.set(XML_SPACE, "preserve")
    t.text = text


def insert_para_after(anchor: etree._Element, text: str) -> None:
    new_p = etree.Element(W + "p")
    ppr = anchor.find("w:pPr", NS)
    if ppr is not None:
        new_p.append(deepcopy(ppr))
    add_run(new_p, text)
    anchor.addnext(new_p)


def ensure_core_child(core: etree._Element, qname: str) -> etree._Element:
    node = core.find(qname)
    if node is None:
        node = etree.SubElement(core, qname)
    return node


def update_core_props(core: etree._Element) -> None:
    ensure_core_child(core, "{http://purl.org/dc/elements/1.1/}title").text = TITLE
    ensure_core_child(core, "{http://purl.org/dc/elements/1.1/}subject").text = (
        "Rust Web Application Firewall L4/L7 Collaborative Protection"
    )
    ensure_core_child(core, "{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}keywords").text = META_KEYWORDS
    ensure_core_child(core, "{http://purl.org/dc/elements/1.1/}description").text = META_DESCRIPTION
    modified = ensure_core_child(core, "{http://purl.org/dc/terms/}modified")
    modified.set("{http://www.w3.org/2001/XMLSchema-instance}type", "dcterms:W3CDTF")
    modified.text = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def main() -> None:
    if not BACKUP.exists():
        copy2(DOCX, BACKUP)

    with ZipFile(DOCX, "r") as zin:
        entries = {name: zin.read(name) for name in zin.namelist()}

    doc = etree.fromstring(entries["word/document.xml"])
    body = doc.find("w:body", NS)
    if body is None:
        raise RuntimeError("document body not found")

    inserted = False
    for p in body.findall("w:p", NS):
        text = para_text(p)
        if text.startswith("关键词："):
            set_labeled_text(p, CN_KEYWORDS, "关键词：")
        elif text.startswith("Key words:"):
            set_labeled_text(p, EN_KEYWORDS, "Key words:")
        elif text.startswith("本文围绕一个真实Rust项目展开") and not inserted:
            insert_para_after(p, DISCOVERABILITY_PARA)
            inserted = True

    core = etree.fromstring(entries["docProps/core.xml"])
    update_core_props(core)

    sects = doc.xpath("//w:sectPr", namespaces=NS)
    if sects:
        pg = sects[-1].find("w:pgNumType", NS)
        if pg is None:
            pg = etree.SubElement(sects[-1], W + "pgNumType")
        pg.set(W + "start", "1")

    entries["word/document.xml"] = etree.tostring(doc, xml_declaration=True, encoding="UTF-8", standalone="yes")
    entries["docProps/core.xml"] = etree.tostring(core, xml_declaration=True, encoding="UTF-8", standalone="yes")

    with ZipFile(DOCX, "w", ZIP_DEFLATED) as zout:
        for name, data in entries.items():
            zout.writestr(name, data)

    print(f"backup={BACKUP.name}")
    print(f"inserted_discoverability_para={inserted}")


if __name__ == "__main__":
    main()
