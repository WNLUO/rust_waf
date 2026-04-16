from __future__ import annotations

from pathlib import Path
from shutil import copy2
from zipfile import ZIP_DEFLATED, ZipFile

from lxml import etree


DOCX = Path(__file__).with_name("基于 Rust 的 L4∕L7 协同 Web 防护系统设计与实现.docx")
BACKUP = DOCX.with_name(DOCX.stem + "_before_abstract_tc_strict_repair.docx")
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


def make_tc(instr: str) -> etree._Element:
    p = etree.Element(W + "p")
    ppr = etree.SubElement(p, W + "pPr")
    rpr = etree.SubElement(ppr, W + "rPr")
    etree.SubElement(rpr, W + "vanish")
    for fld_type, value in (("begin", None), ("instr", instr), ("end", None)):
        r = etree.SubElement(p, W + "r")
        rr = etree.SubElement(r, W + "rPr")
        etree.SubElement(rr, W + "vanish")
        if fld_type == "instr":
            it = etree.SubElement(r, W + "instrText")
            it.set(XML_SPACE, "preserve")
            it.text = value
        else:
            fld = etree.SubElement(r, W + "fldChar")
            fld.set(W + "fldCharType", fld_type)
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

    # Remove all existing ABSTRACT TC paragraphs; they are safe to rebuild deterministically.
    for p in list(body.findall("w:p", NS)):
        if 'TC "ABSTRACT"' in instr_text(p):
            body.remove(p)

    for p in body.findall("w:p", NS):
        text = para_text(p)
        # Real English abstract body is long and has no TOC style; cached TOC entry is only "Abstract:2".
        if para_style(p) == "" and text.startswith("Abstract:") and len(text) > 80:
            p.addprevious(make_tc('TC "ABSTRACT" \\f C \\l 1'))
            break

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
