from __future__ import annotations

import re
from pathlib import Path
from shutil import copy2
from zipfile import ZIP_DEFLATED, ZipFile

from lxml import etree


DOCX = Path(__file__).with_name("基于 Rust 的 L4∕L7 协同 Web 防护系统设计与实现.docx")
BACKUP = DOCX.with_name(DOCX.stem + "_before_repair_format_after_reduction.docx")
NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"
CITE_RE = re.compile(r"(\[(?:\d+(?:-\d+)?)(?:\]\[\d+(?:-\d+)?)*\])")


def para_text(p: etree._Element) -> str:
    return "".join(p.xpath(".//w:t/text()", namespaces=NS)).strip()


def para_style(p: etree._Element) -> str:
    node = p.find("w:pPr/w:pStyle", NS)
    return node.get(W + "val") if node is not None else ""


def instr_text(p: etree._Element) -> str:
    return "".join(p.xpath(".//w:instrText/text()", namespaces=NS))


def remove_visible_runs(p: etree._Element) -> None:
    for child in list(p):
        if child.tag == W + "r":
            p.remove(child)


def rpr_bold() -> etree._Element:
    rpr = etree.Element(W + "rPr")
    etree.SubElement(rpr, W + "b")
    return rpr


def rpr_english_abstract_label() -> etree._Element:
    rpr = etree.Element(W + "rPr")
    rstyle = etree.SubElement(rpr, W + "rStyle")
    rstyle.set(W + "val", "10")
    fonts = etree.SubElement(rpr, W + "rFonts")
    fonts.set(W + "eastAsia", "黑体")
    bcs = etree.SubElement(rpr, W + "bCs")
    bcs.set(W + "val", "0")
    sz = etree.SubElement(rpr, W + "sz")
    sz.set(W + "val", "24")
    szcs = etree.SubElement(rpr, W + "szCs")
    szcs.set(W + "val", "30")
    return rpr


def rpr_citation() -> etree._Element:
    rpr = etree.Element(W + "rPr")
    fonts = etree.SubElement(rpr, W + "rFonts")
    fonts.set(W + "ascii", "宋体")
    fonts.set(W + "hAnsi", "宋体")
    fonts.set(W + "cs", "宋体")
    sz = etree.SubElement(rpr, W + "sz")
    sz.set(W + "val", "21")
    szcs = etree.SubElement(rpr, W + "szCs")
    szcs.set(W + "val", "21")
    va = etree.SubElement(rpr, W + "vertAlign")
    va.set(W + "val", "superscript")
    return rpr


def add_run(p: etree._Element, text: str, rpr: etree._Element | None = None) -> None:
    if text == "":
        return
    r = etree.SubElement(p, W + "r")
    if rpr is not None:
        r.append(etree.fromstring(etree.tostring(rpr)))
    t = etree.SubElement(r, W + "t")
    if text.startswith(" ") or text.endswith(" "):
        t.set(XML_SPACE, "preserve")
    t.text = text


def add_text_with_citations(p: etree._Element, text: str) -> None:
    parts = CITE_RE.split(text)
    for part in parts:
        if not part:
            continue
        if CITE_RE.fullmatch(part):
            # Split adjacent [1][2] into separately superscripted runs.
            for m in re.finditer(r"\[\d+(?:-\d+)?\]", part):
                add_run(p, m.group(0), rpr_citation())
        else:
            add_run(p, part)


def rewrite_normal_para(p: etree._Element, text: str) -> None:
    remove_visible_runs(p)
    add_text_with_citations(p, text)


def rewrite_labeled_para(p: etree._Element, text: str, label: str, label_rpr: etree._Element) -> None:
    remove_visible_runs(p)
    add_run(p, label, label_rpr)
    add_text_with_citations(p, text[len(label):])


def is_caption(text: str) -> bool:
    return bool(re.match(r"^(图|表)\d+-\d+", text))


def is_formula(text: str) -> bool:
    return "（" in text and "）" in text and any(sym in text for sym in ["⇒", "=", "Σ", "Score", "Snext", "Reff", "Cip", "p ="])


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
    texts = [para_text(p) for p in paras]
    first_heading = next((i for i, s in enumerate(texts) if s == "1 绪论"), len(paras))
    refs_heading = next((i for i, s in enumerate(texts) if s == "参考文献"), len(paras))

    fixed = 0
    for i, p in enumerate(paras):
        text = para_text(p)
        if not text or instr_text(p):
            continue
        style = para_style(p)
        if style.startswith("TOC") or style in {"1", "2", "3", "Heading1", "Heading2", "Heading3"}:
            continue
        if text.startswith("摘  要："):
            rewrite_labeled_para(p, text, "摘  要：", rpr_bold())
            fixed += 1
        elif text.startswith("关键词："):
            rewrite_labeled_para(p, text, "关键词：", rpr_bold())
            fixed += 1
        elif text.startswith("Abstract:"):
            rewrite_labeled_para(p, text, "Abstract:", rpr_english_abstract_label())
            fixed += 1
        elif text.startswith("Key words:"):
            rewrite_labeled_para(p, text, "Key words:", rpr_bold())
            fixed += 1
        elif first_heading <= i < refs_heading and not is_caption(text) and not is_formula(text):
            rewrite_normal_para(p, text)
            fixed += 1

    sects = doc.xpath("//w:sectPr", namespaces=NS)
    if sects:
        pg = sects[-1].find("w:pgNumType", NS)
        if pg is None:
            pg = etree.SubElement(sects[-1], W + "pgNumType")
        pg.set(W + "start", "1")

    entries["word/document.xml"] = etree.tostring(doc, xml_declaration=True, encoding="UTF-8", standalone="yes")
    with ZipFile(DOCX, "w", ZIP_DEFLATED) as zout:
        for name, data in entries.items():
            zout.writestr(name, data)

    print(f"backup={BACKUP.name}")
    print(f"fixed_paragraphs={fixed}")


if __name__ == "__main__":
    main()
