from pathlib import Path
import re
import shutil
import zipfile

from lxml import etree


DOCX = Path("/Users/wnluo/Desktop/code/rust_waf/paper/基于 Rust 的 L4∕L7 协同 Web 防护系统设计与实现.docx")
BACKUP = DOCX.with_name("基于 Rust 的 L4∕L7 协同 Web 防护系统设计与实现_before_literature_and_length_opt.docx")

NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}


def qn(tag: str) -> str:
    prefix, local = tag.split(":")
    return f"{{{NS[prefix]}}}{local}"


def p_text(p) -> str:
    out = []
    for node in p.iter():
        if node.tag == qn("w:t") and node.text:
            out.append(node.text)
        elif node.tag == qn("w:tab"):
            out.append("\t")
    return "".join(out).strip()


def has_drawing(p) -> bool:
    return bool(p.xpath(".//w:drawing", namespaces=NS))


def is_toc_result(text: str) -> bool:
    return "\t" in text and re.search(r"\t\d+$", text) is not None


def append_sup_citations(p, numbers):
    existing = p_text(p)
    if all(f"[{n}]" in existing for n in numbers):
        return False
    for n in numbers:
        if f"[{n}]" in existing:
            continue
        r = etree.Element(qn("w:r"))
        rpr = etree.SubElement(r, qn("w:rPr"))
        va = etree.SubElement(rpr, qn("w:vertAlign"))
        va.set(qn("w:val"), "superscript")
        rf = etree.SubElement(rpr, qn("w:rFonts"))
        for attr in ["ascii", "eastAsia", "hAnsi", "cs"]:
            rf.set(qn(f"w:{attr}"), "宋体" if attr == "eastAsia" else "Times New Roman")
        sz = etree.SubElement(rpr, qn("w:sz"))
        sz.set(qn("w:val"), "21")
        t = etree.SubElement(r, qn("w:t"))
        t.text = f"[{n}]"
        p.append(r)
    return True


def clone_reference_para(template, ref_text: str):
    p = etree.fromstring(etree.tostring(template))
    # Remove existing runs and keep paragraph properties.
    for r in list(p.findall("w:r", NS)):
        p.remove(r)
    r = etree.SubElement(p, qn("w:r"))
    rpr = etree.SubElement(r, qn("w:rPr"))
    rf = etree.SubElement(rpr, qn("w:rFonts"))
    rf.set(qn("w:ascii"), "Times New Roman")
    rf.set(qn("w:hAnsi"), "Times New Roman")
    rf.set(qn("w:cs"), "Times New Roman")
    rf.set(qn("w:eastAsia"), "宋体")
    sz = etree.SubElement(rpr, qn("w:sz"))
    sz.set(qn("w:val"), "21")
    szcs = etree.SubElement(rpr, qn("w:szCs"))
    szcs.set(qn("w:val"), "21")
    t = etree.SubElement(r, qn("w:t"))
    t.text = ref_text
    return p


def main():
    if not BACKUP.exists():
        shutil.copy2(DOCX, BACKUP)

    with zipfile.ZipFile(DOCX) as zin:
        files = {name: zin.read(name) for name in zin.namelist()}

    root = etree.fromstring(files["word/document.xml"])
    body = root.find(".//w:body", NS)

    removed_figure_explain = 0
    removed_26_elements = 0
    removed_toc_26 = 0

    # 1) Remove current visible TOC entry for the removed 2.6 section.
    for child in list(body):
        if child.tag == qn("w:p"):
            tx = p_text(child)
            if is_toc_result(tx) and tx.startswith("2.6 "):
                body.remove(child)
                removed_toc_26 += 1

    # 2) Remove Section 2.6 terminology table. It is useful as notes, but bulky and not essential for the thesis argument.
    children = list(body)
    start = end = None
    for i, child in enumerate(children):
        if child.tag == qn("w:p") and p_text(child) == "2.6 主要技术术语中英文对照":
            start = i
        elif start is not None and child.tag == qn("w:p") and p_text(child).startswith("3 系统需求分析与总体设计"):
            end = i
            break
    if start is not None and end is not None:
        for child in children[start:end]:
            if child.getparent() is body:
                body.remove(child)
                removed_26_elements += 1

    # 3) Remove explanatory paragraphs that repeat figure captions.
    children = list(body)
    prev_p = None
    for child in children:
        if child.getparent() is not body:
            continue
        if child.tag == qn("w:p"):
            tx = p_text(child)
            # Keep actual figure captions: those immediately after a drawing paragraph.
            if re.match(r"^图\d+-\d+\s+", tx) and not (prev_p is not None and has_drawing(prev_p)):
                body.remove(child)
                removed_figure_explain += 1
                prev_p = None
                continue
            prev_p = child
        elif child.tag == qn("w:tbl"):
            prev_p = None

    # 4) Add more fitting citations in-place.
    citation_targets = [
        ("在云原生、微服务与前后端分离架构广泛应用的背景下", [18]),
        ("另一方面，近年来HTTP协议栈持续演进", [17]),
        ("OWASP社区将网络应用防火墙定义为", [16]),
        ("本文项目采用Tokio异步运行时构建服务入口", [19]),
        ("在控制面方面，系统后端通过Axum对外暴露REST风格接口", [20, 21]),
    ]
    added_citations = 0
    for p in body.findall("w:p", NS):
        tx = p_text(p)
        for needle, nums in citation_targets:
            if tx.startswith(needle) or needle in tx:
                if append_sup_citations(p, nums):
                    added_citations += len(nums)

    # 5) Add additional reference items if absent.
    refs_to_add = [
        "[17] Fielding R, Nottingham M, Reschke J. HTTP/1.1[S/OL]. RFC 9112, 2022.",
        "[18] OWASP Foundation. OWASP Top 10:2021[EB/OL]. [2026-04-16]. https://owasp.org/Top10/.",
        "[19] Tokio Contributors. Tokio: An asynchronous Rust runtime[EB/OL]. [2026-04-16]. https://tokio.rs/.",
        "[20] Tokio Contributors. axum crate documentation[EB/OL]. [2026-04-16]. https://docs.rs/axum/latest/axum/.",
        "[21] Vue.js Team. Vue.js Guide[EB/OL]. [2026-04-16]. https://vuejs.org/guide/.",
    ]
    all_text = "\n".join(p_text(p) for p in body.findall("w:p", NS))
    last_ref = None
    for p in body.findall("w:p", NS):
        if re.match(r"^\[\d+\]", p_text(p)):
            last_ref = p
    added_refs = 0
    if last_ref is not None:
        insert_after = last_ref
        for ref in refs_to_add:
            if ref[:5] in all_text:
                continue
            new_p = clone_reference_para(last_ref, ref)
            insert_after.addnext(new_p)
            insert_after = new_p
            added_refs += 1

    # 6) Preserve page numbering and field update settings.
    sects = root.xpath(".//w:sectPr", namespaces=NS)
    if len(sects) >= 3:
        pg = sects[2].find("w:pgNumType", NS)
        if pg is None:
            pg = etree.Element(qn("w:pgNumType"))
            sects[2].insert(0, pg)
        pg.set(qn("w:start"), "1")

    settings = etree.fromstring(files["word/settings.xml"])
    upd = settings.find("w:updateFields", NS)
    if upd is None:
        upd = etree.Element(qn("w:updateFields"))
        settings.append(upd)
    upd.set(qn("w:val"), "true")
    files["word/settings.xml"] = etree.tostring(settings, xml_declaration=True, encoding="UTF-8", standalone="yes")
    files["word/document.xml"] = etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone="yes")

    tmp = DOCX.with_suffix(".tmp.docx")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
        for name, data in files.items():
            zout.writestr(name, data)
    shutil.move(tmp, DOCX)

    print(f"backup={BACKUP.name}")
    print(f"removed_figure_explain={removed_figure_explain}")
    print(f"removed_2_6_elements={removed_26_elements}")
    print(f"removed_toc_2_6={removed_toc_26}")
    print(f"added_citations={added_citations}")
    print(f"added_refs={added_refs}")


if __name__ == "__main__":
    main()
