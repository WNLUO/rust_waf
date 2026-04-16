from __future__ import annotations

from pathlib import Path
from shutil import copy2
from zipfile import ZIP_DEFLATED, ZipFile

from lxml import etree


DOCX = Path(__file__).with_name("基于 Rust 的 L4∕L7 协同 Web 防护系统设计与实现.docx")
BACKUP = DOCX.with_name(DOCX.stem + "_before_abstract_tc_position_repair.docx")
NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"


def para_text(p: etree._Element) -> str:
    return "".join(p.xpath(".//w:t/text()", namespaces=NS)).strip()


def para_style(p: etree._Element) -> str:
    node = p.find("w:pPr/w:pStyle", NS)
    return node.get(W + "val") if node is not None else ""


def instr_text(p: etree._Element) -> str:
    return "".join(p.xpath(".//w:instrText/text()", namespaces=NS))


def make_hidden_tc_para(instr: str) -> etree._Element:
    p = etree.Element(W + "p")
    ppr = etree.SubElement(p, W + "pPr")
    rpr = etree.SubElement(ppr, W + "rPr")
    etree.SubElement(rpr, W + "vanish")
    for kind, text in (("begin", None), ("instr", instr), ("end", None)):
        r = etree.SubElement(p, W + "r")
        rr = etree.SubElement(r, W + "rPr")
        etree.SubElement(rr, W + "vanish")
        if kind == "instr":
            it = etree.SubElement(r, W + "instrText")
            it.set(XML_SPACE, "preserve")
            it.text = text
        else:
            fld = etree.SubElement(r, W + "fldChar")
            fld.set(W + "fldCharType", kind)
    return p


def main() -> None:
    if not BACKUP.exists():
        copy2(DOCX, BACKUP)

    with ZipFile(DOCX, "r") as zin:
        entries = {name: zin.read(name) for name in zin.namelist()}

    doc = etree.fromstring(entries["word/document.xml"])
    body = doc.find("w:body", NS)
    if body is None:
        raise RuntimeError("document body not found")

    paras = list(body.findall("w:p", NS))
    first_body_heading = next((i for i, p in enumerate(paras) if para_text(p) == "1 绪论" and para_style(p) in {"1", "Heading1"}), len(paras))

    # Remove TC fields from the cover/TOC region only; real abstract TC fields are re-added below if absent.
    for p in list(paras[:first_body_heading]):
        if "TC " in instr_text(p):
            body.remove(p)

    paras = list(body.findall("w:p", NS))
    cn_exists = any('TC "摘要"' in instr_text(p) and i < first_body_heading for i, p in enumerate(paras))
    en_exists = any('TC "ABSTRACT"' in instr_text(p) and i < first_body_heading for i, p in enumerate(paras))
    # Recompute after removal. We want the TC fields directly before the visible abstract paragraphs.
    cn_exists = any('TC "摘要"' in instr_text(p) for p in paras)
    en_exists = any('TC "ABSTRACT"' in instr_text(p) for p in paras)

    for p in list(body.findall("w:p", NS)):
        text = para_text(p)
        if not cn_exists and text.startswith("摘") and "要" in text[:8]:
            p.addprevious(make_hidden_tc_para('TC "摘要" \\f C \\l 1'))
            cn_exists = True
        elif not en_exists and text.startswith("Abstract:"):
            p.addprevious(make_hidden_tc_para('TC "ABSTRACT" \\f C \\l 1'))
            en_exists = True

    sects = doc.xpath("//w:sectPr", namespaces=NS)
    if sects:
        sect = sects[-1]
        pg = sect.find("w:pgNumType", NS)
        if pg is None:
            pg = etree.SubElement(sect, W + "pgNumType")
        pg.set(W + "start", "1")

    entries["word/document.xml"] = etree.tostring(doc, xml_declaration=True, encoding="UTF-8", standalone="yes")
    with ZipFile(DOCX, "w", ZIP_DEFLATED) as zout:
        for name, data in entries.items():
            zout.writestr(name, data)

    print(f"backup={BACKUP.name}")


if __name__ == "__main__":
    main()
