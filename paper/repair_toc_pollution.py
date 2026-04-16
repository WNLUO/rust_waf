from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from shutil import copy2
from zipfile import ZIP_DEFLATED, ZipFile

from lxml import etree


DOCX = Path(__file__).with_name("基于 Rust 的 L4∕L7 协同 Web 防护系统设计与实现.docx")
BACKUP = DOCX.with_name(DOCX.stem + "_before_toc_pollution_repair.docx")
NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"

POLLUTED_START = "在定级与保护对象理解上，GB/T 22240-2020强调"


def para_text(p: etree._Element) -> str:
    return "".join(p.xpath(".//w:t/text()", namespaces=NS)).strip()


def para_style(p: etree._Element) -> str:
    node = p.find("w:pPr/w:pStyle", NS)
    return node.get(W + "val") if node is not None else ""


def instr_text(p: etree._Element) -> str:
    return "".join(p.xpath(".//w:instrText/text()", namespaces=NS))


def has_toc_field(p: etree._Element) -> bool:
    return "TOC " in instr_text(p) or "PAGEREF _Toc" in instr_text(p) or para_style(p).startswith("TOC")


def make_hidden_tc_para(instr: str) -> etree._Element:
    p = etree.Element(W + "p")
    ppr = etree.SubElement(p, W + "pPr")
    rpr = etree.SubElement(ppr, W + "rPr")
    etree.SubElement(rpr, W + "vanish")

    begin_r = etree.SubElement(p, W + "r")
    begin_rpr = etree.SubElement(begin_r, W + "rPr")
    etree.SubElement(begin_rpr, W + "vanish")
    begin = etree.SubElement(begin_r, W + "fldChar")
    begin.set(W + "fldCharType", "begin")

    instr_r = etree.SubElement(p, W + "r")
    instr_rpr = etree.SubElement(instr_r, W + "rPr")
    etree.SubElement(instr_rpr, W + "vanish")
    it = etree.SubElement(instr_r, W + "instrText")
    it.set(XML_SPACE, "preserve")
    it.text = instr

    end_r = etree.SubElement(p, W + "r")
    end_rpr = etree.SubElement(end_r, W + "rPr")
    etree.SubElement(end_rpr, W + "vanish")
    end = etree.SubElement(end_r, W + "fldChar")
    end.set(W + "fldCharType", "end")
    return p


def remove_tc_runs_from_para(p: etree._Element) -> None:
    for r in list(p.findall("w:r", NS)):
        if r.xpath(".//w:instrText[contains(., 'TC ')]", namespaces=NS):
            p.remove(r)
            continue
        fld = r.find("w:fldChar", NS)
        if fld is not None:
            ftype = fld.get(W + "fldCharType")
            if ftype in {"begin", "end", "separate"}:
                # Remove only field chars with hidden rPr, preserving ordinary visible text runs.
                rpr = r.find("w:rPr", NS)
                if rpr is not None and rpr.find("w:vanish", NS) is not None:
                    p.remove(r)


def insert_tc_before_abstracts(body: etree._Element) -> None:
    # Drop broken TC field fragments currently embedded in visible abstract paragraphs.
    for p in body.findall("w:p", NS):
        if "TC " in instr_text(p):
            remove_tc_runs_from_para(p)

    paras = list(body.findall("w:p", NS))
    has_cn = any('TC "摘要"' in instr_text(p) for p in paras)
    has_en = any('TC "ABSTRACT"' in instr_text(p) for p in paras)

    for p in list(body.findall("w:p", NS)):
        text = para_text(p)
        if not has_cn and text.startswith("摘") and "要" in text[:8]:
            p.addprevious(make_hidden_tc_para('TC "摘要" \\f C \\l 1'))
            has_cn = True
        if not has_en and text.startswith("Abstract"):
            p.addprevious(make_hidden_tc_para('TC "ABSTRACT" \\f C \\l 1'))
            has_en = True


def repair_polluted_toc(body: etree._Element) -> None:
    paras = list(body.findall("w:p", NS))
    polluted = None
    for p in paras:
        if para_text(p).startswith(POLLUTED_START):
            polluted = p
            break
    if polluted is None:
        return

    # If the paragraph is before the first real body heading, it is inside the cached TOC.
    first_body_heading_idx = None
    for i, p in enumerate(paras):
        if para_text(p) == "1 绪论" and para_style(p) in {"1", "Heading1"}:
            first_body_heading_idx = i
            break
    polluted_idx = paras.index(polluted)
    if first_body_heading_idx is None or polluted_idx >= first_body_heading_idx:
        return

    moved = deepcopy(polluted)
    body.remove(polluted)

    # Place it after the first content paragraph under 3.1 in the real body.
    paras = list(body.findall("w:p", NS))
    insert_after = None
    seen_31 = False
    for p in paras:
        text = para_text(p)
        if text == "3.1 系统建设目标":
            seen_31 = True
            insert_after = p
            continue
        if seen_31:
            if para_style(p) in {"2", "Heading2"} and text.startswith("3.2 "):
                break
            if text and para_style(p) == "":
                insert_after = p
                break
    if insert_after is None:
        return
    insert_after.addnext(moved)


def ensure_page_start_and_update(settings: etree._Element | None, doc: etree._Element) -> None:
    sects = doc.xpath("//w:sectPr", namespaces=NS)
    if sects:
        sect = sects[-1]
        pg = sect.find("w:pgNumType", NS)
        if pg is None:
            pg = etree.SubElement(sect, W + "pgNumType")
        pg.set(W + "start", "1")
    if settings is not None and not settings.xpath("//w:updateFields", namespaces=NS):
        upd = etree.Element(W + "updateFields")
        upd.set(W + "val", "true")
        settings.insert(0, upd)


def main() -> None:
    if not BACKUP.exists():
        copy2(DOCX, BACKUP)

    with ZipFile(DOCX, "r") as zin:
        entries = {name: zin.read(name) for name in zin.namelist()}

    doc = etree.fromstring(entries["word/document.xml"])
    body = doc.find("w:body", NS)
    settings = etree.fromstring(entries["word/settings.xml"]) if "word/settings.xml" in entries else None
    if body is None:
        raise RuntimeError("document body not found")

    repair_polluted_toc(body)
    insert_tc_before_abstracts(body)
    ensure_page_start_and_update(settings, doc)

    entries["word/document.xml"] = etree.tostring(doc, xml_declaration=True, encoding="UTF-8", standalone="yes")
    if settings is not None:
        entries["word/settings.xml"] = etree.tostring(settings, xml_declaration=True, encoding="UTF-8", standalone="yes")

    with ZipFile(DOCX, "w", ZIP_DEFLATED) as zout:
        for name, data in entries.items():
            zout.writestr(name, data)

    print(f"backup={BACKUP.name}")


if __name__ == "__main__":
    main()
