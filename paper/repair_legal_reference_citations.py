from __future__ import annotations

from pathlib import Path
from shutil import copy2
from zipfile import ZIP_DEFLATED, ZipFile

from lxml import etree


DOCX = Path(__file__).with_name("基于 Rust 的 L4∕L7 协同 Web 防护系统设计与实现.docx")
BACKUP = DOCX.with_name(DOCX.stem + "_before_legal_ref_repair.docx")
NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


LEGAL_PARA_OLD = (
    "从我国网络安全治理框架看，Web防护系统的建设还具有明确的法律和标准依据。"
    "《中华人民共和国网络安全法》明确提出“国家实行网络安全等级保护制度”[29]，"
    "数据安全法要求开展数据处理活动时建立相应的数据安全管理制度和技术保护措施[30]，"
    "个人信息保护法也强调防止未经授权访问以及个人信息泄露、篡改、丢失[31]。"
    "因此，本文系统虽然是本科毕业设计原型，但其规则管理、访问控制、日志审计、"
    "事件留存和控制台鉴权等设计，仍应放在网络运行安全、数据安全和个人信息保护的规范框架下理解。"
)

LEGAL_PARA_NEW = (
    "从我国网络安全治理框架看，Web防护系统的建设还具有明确的法律和标准依据。"
    "《中华人民共和国网络安全法》（2025年修正）第二十三条明确规定“国家实行网络安全等级保护制度”[29]；"
    "《中华人民共和国数据安全法》第二十七条提出，开展数据处理活动应当“建立健全全流程数据安全管理制度”[30]；"
    "《中华人民共和国个人信息保护法》第五十一条要求个人信息处理者采取措施，"
    "防止未经授权访问以及个人信息泄露、篡改、丢失[31]。"
    "因此，本文系统虽然是本科毕业设计原型，但其规则管理、访问控制、日志审计、"
    "事件留存和控制台鉴权等设计，仍应放在网络运行安全、数据安全和个人信息保护的规范框架下理解。"
)

REF_29_OLD = "[29] 全国人民代表大会常务委员会. 中华人民共和国网络安全法[Z]. 2016."
REF_29_NEW = "[29] 全国人民代表大会常务委员会. 中华人民共和国网络安全法（2025年修正）[Z]. 2025."


def para_text(p: etree._Element) -> str:
    return "".join(p.xpath(".//w:t/text()", namespaces=NS))


def replace_para_text(p: etree._Element, text: str) -> None:
    texts = p.xpath(".//w:t", namespaces=NS)
    if not texts:
        r = etree.SubElement(p, W + "r")
        t = etree.SubElement(r, W + "t")
        t.text = text
        return
    texts[0].text = text
    if text.startswith(" ") or text.endswith(" "):
        texts[0].set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
    for t in texts[1:]:
        t.text = ""


def ensure_toc_tc_and_page_start(doc: etree._Element, settings: etree._Element | None) -> None:
    instrs = doc.xpath("//w:instrText/text()", namespaces=NS)
    joined = " ".join(instrs)
    if 'TC "摘要"' not in joined:
        insert_tc(doc, 'TC "摘要" \\f C \\l 1', before_text="摘要")
    if 'TC "ABSTRACT"' not in joined:
        insert_tc(doc, 'TC "ABSTRACT" \\f C \\l 1', before_text="ABSTRACT")
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


def insert_tc(doc: etree._Element, instr: str, before_text: str) -> None:
    paras = doc.xpath("//w:body/w:p", namespaces=NS)
    target = None
    for p in paras:
        if para_text(p).strip() == before_text:
            target = p
            break
    if target is None:
        return
    tc_p = etree.Element(W + "p")
    ppr = etree.SubElement(tc_p, W + "pPr")
    vanish = etree.SubElement(ppr, W + "rPr")
    etree.SubElement(vanish, W + "vanish")
    r = etree.SubElement(tc_p, W + "r")
    rpr = etree.SubElement(r, W + "rPr")
    etree.SubElement(rpr, W + "vanish")
    fld = etree.SubElement(r, W + "fldChar")
    fld.set(W + "fldCharType", "begin")
    r2 = etree.SubElement(tc_p, W + "r")
    rpr2 = etree.SubElement(r2, W + "rPr")
    etree.SubElement(rpr2, W + "vanish")
    it = etree.SubElement(r2, W + "instrText")
    it.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
    it.text = instr
    r3 = etree.SubElement(tc_p, W + "r")
    rpr3 = etree.SubElement(r3, W + "rPr")
    etree.SubElement(rpr3, W + "vanish")
    fld_end = etree.SubElement(r3, W + "fldChar")
    fld_end.set(W + "fldCharType", "end")
    target.addprevious(tc_p)


def main() -> None:
    if not DOCX.exists():
        raise FileNotFoundError(DOCX)
    if not BACKUP.exists():
        copy2(DOCX, BACKUP)

    with ZipFile(DOCX, "r") as zin:
        entries = {name: zin.read(name) for name in zin.namelist()}

    doc = etree.fromstring(entries["word/document.xml"])
    settings = etree.fromstring(entries["word/settings.xml"]) if "word/settings.xml" in entries else None

    replaced_legal = False
    replaced_ref = False
    for p in doc.xpath("//w:body/w:p", namespaces=NS):
        txt = para_text(p)
        if txt == LEGAL_PARA_OLD:
            replace_para_text(p, LEGAL_PARA_NEW)
            replaced_legal = True
        elif txt == REF_29_OLD:
            replace_para_text(p, REF_29_NEW)
            replaced_ref = True

    ensure_toc_tc_and_page_start(doc, settings)
    entries["word/document.xml"] = etree.tostring(doc, xml_declaration=True, encoding="UTF-8", standalone="yes")
    if settings is not None:
        entries["word/settings.xml"] = etree.tostring(settings, xml_declaration=True, encoding="UTF-8", standalone="yes")

    with ZipFile(DOCX, "w", ZIP_DEFLATED) as zout:
        for name, data in entries.items():
            zout.writestr(name, data)

    print(f"backup={BACKUP.name}")
    print(f"replaced_legal={replaced_legal}")
    print(f"replaced_ref={replaced_ref}")


if __name__ == "__main__":
    main()
