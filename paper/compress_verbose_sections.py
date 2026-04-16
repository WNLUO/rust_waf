from pathlib import Path
import re
import shutil
import zipfile

from lxml import etree


DOCX = Path("/Users/wnluo/Desktop/code/rust_waf/paper/基于 Rust 的 L4∕L7 协同 Web 防护系统设计与实现.docx")
BACKUP = DOCX.with_name("基于 Rust 的 L4∕L7 协同 Web 防护系统设计与实现_before_section_compress.docx")

NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}


def qn(tag):
    prefix, local = tag.split(":")
    return f"{{{NS[prefix]}}}{local}"


def text_of(el):
    out = []
    for node in el.iter():
        if node.tag == qn("w:t") and node.text:
            out.append(node.text)
        elif node.tag == qn("w:tab"):
            out.append("\t")
    return "".join(out).strip()


def is_heading_text(text, heading):
    return text == heading


def run(parent, text, sup=False):
    r = etree.SubElement(parent, qn("w:r"))
    rpr = etree.SubElement(r, qn("w:rPr"))
    rf = etree.SubElement(rpr, qn("w:rFonts"))
    rf.set(qn("w:ascii"), "Times New Roman")
    rf.set(qn("w:hAnsi"), "Times New Roman")
    rf.set(qn("w:cs"), "Times New Roman")
    rf.set(qn("w:eastAsia"), "宋体")
    sz = etree.SubElement(rpr, qn("w:sz"))
    sz.set(qn("w:val"), "24")
    szcs = etree.SubElement(rpr, qn("w:szCs"))
    szcs.set(qn("w:val"), "24")
    if sup:
        va = etree.SubElement(rpr, qn("w:vertAlign"))
        va.set(qn("w:val"), "superscript")
        sz.set(qn("w:val"), "21")
        szcs.set(qn("w:val"), "21")
    t = etree.SubElement(r, qn("w:t"))
    t.text = text
    return r


def body_paragraph(text):
    p = etree.Element(qn("w:p"))
    ppr = etree.SubElement(p, qn("w:pPr"))
    spacing = etree.SubElement(ppr, qn("w:spacing"))
    spacing.set(qn("w:before"), "0")
    spacing.set(qn("w:after"), "0")
    spacing.set(qn("w:line"), "400")
    spacing.set(qn("w:lineRule"), "exact")
    ind = etree.SubElement(ppr, qn("w:ind"))
    ind.set(qn("w:firstLine"), "480")
    jc = etree.SubElement(ppr, qn("w:jc"))
    jc.set(qn("w:val"), "both")
    pos = 0
    for m in re.finditer(r"\[(?:\d+)(?:\]\[\d+)*\]", text):
        if m.start() > pos:
            run(p, text[pos:m.start()])
        for n in re.findall(r"\[\d+\]", m.group(0)):
            run(p, n, sup=True)
        pos = m.end()
    if pos < len(text):
        run(p, text[pos:])
    return p


def compress_section(body, start_heading, end_heading, new_paragraphs):
    children = list(body)
    start = end = None
    for i, child in enumerate(children):
        if child.tag == qn("w:p") and is_heading_text(text_of(child), start_heading):
            start = i
        elif start is not None and child.tag == qn("w:p") and is_heading_text(text_of(child), end_heading):
            end = i
            break
    if start is None or end is None:
        raise RuntimeError(f"section not found: {start_heading} -> {end_heading}")
    removed = 0
    for child in children[start + 1 : end]:
        if child.getparent() is body:
            body.remove(child)
            removed += 1
    anchor = children[start]
    for text in reversed(new_paragraphs):
        anchor.addnext(body_paragraph(text))
    return removed


def repair_abstract_tc(root):
    body = root.find(".//w:body", NS)
    for p in body.findall("w:p", NS):
        if "摘  要" in text_of(p):
            # Avoid duplicates by removing old 摘要 TC blocks first.
            runs = list(p.findall("w:r", NS))
            remove = set()
            i = 0
            while i < len(runs):
                fld = runs[i].find("w:fldChar", NS)
                if fld is not None and fld.get(qn("w:fldCharType")) == "begin":
                    block, joined, j = [], "", i
                    while j < len(runs):
                        block.append(runs[j])
                        joined += "".join(n.text or "" for n in runs[j].findall(".//w:instrText", NS))
                        fld2 = runs[j].find("w:fldChar", NS)
                        if fld2 is not None and fld2.get(qn("w:fldCharType")) == "end":
                            break
                        j += 1
                    if 'TC "摘要"' in joined:
                        remove.update(block)
                        i = j + 1
                        continue
                i += 1
            for r in remove:
                if r.getparent() is p:
                    p.remove(r)
            insert_at = 1 if p.find("w:pPr", NS) is not None else 0
            parts = []
            r1 = etree.Element(qn("w:r"))
            etree.SubElement(etree.SubElement(r1, qn("w:rPr")), qn("w:vanish"))
            fc = etree.SubElement(r1, qn("w:fldChar"))
            fc.set(qn("w:fldCharType"), "begin")
            parts.append(r1)
            r2 = etree.Element(qn("w:r"))
            etree.SubElement(etree.SubElement(r2, qn("w:rPr")), qn("w:vanish"))
            instr = etree.SubElement(r2, qn("w:instrText"))
            instr.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
            instr.text = ' TC "摘要" \\f C \\l 1 '
            parts.append(r2)
            r3 = etree.Element(qn("w:r"))
            etree.SubElement(etree.SubElement(r3, qn("w:rPr")), qn("w:vanish"))
            fc = etree.SubElement(r3, qn("w:fldChar"))
            fc.set(qn("w:fldCharType"), "end")
            parts.append(r3)
            for r in reversed(parts):
                p.insert(insert_at, r)
            return


def main():
    if not BACKUP.exists():
        shutil.copy2(DOCX, BACKUP)
    with zipfile.ZipFile(DOCX) as zin:
        files = {name: zin.read(name) for name in zin.namelist()}
    root = etree.fromstring(files["word/document.xml"])
    body = root.find(".//w:body", NS)

    removed_46 = compress_section(
        body,
        "4.6 管理API与前端控制台实现",
        "4.7 核心算法设计与实现",
        [
            "系统管理面由Axum接口和Vue控制台组成，主要承担配置维护、事件查询、站点与证书管理、规则动作管理、行为画像查看和SafeLine同步等职责[20][21]。后端接口按照资源化方式组织，实时状态通过WebSocket推送到前端，使控制台能够在不直接参与安全裁决的情况下呈现运行态数据。",
            "前端控制台的设计重点不在于简单展示列表，而在于把四层参数、七层规则、动作模板、站点证书、事件画像和AI审计归入可操作页面。这样可以使运维人员从总览页快速判断系统压力、拦截趋势和风险身份，再进入具体页面调整规则、模板或联动配置。",
            "需要指出的是，当前系统仍有部分监听器和协议栈参数需要重启后生效，说明其热更新能力尚未完全覆盖所有运行路径。该限制反映了原型系统的真实边界，也为后续在规则缓存、证书刷新和监听配置动态加载方面继续优化留下空间。",
        ],
    )

    removed_52 = compress_section(
        body,
        "5.2 功能测试结果",
        "5.3 系统实现效果分析",
        [
            "论文撰写期间，项目完成了后端、前端和构建链路验证。后端执行cargo test共237项测试，全部通过；前端执行Vitest共2项测试通过，生产构建也能够成功完成。测试覆盖配置归一化、TLS接入、四层/七层规则匹配、可信转发双身份预算、四层行为分桶、HTTP/2转换、HTTP/3预检链路、SQLite持久化、管理端令牌逻辑以及SafeLine同步等关键路径。",
            "从功能验证结果看，系统已经能够完成从连接接入、分层检测、规则命中、动作响应到事件记录的基本闭环。HTTP/1.1和HTTP/2在本地环境中可以完成实际请求验证；HTTP/3受客户端工具限制，主要通过配置检查和自动化测试覆盖进行论证。该处理方式虽然不是生产级压测，但能够证明多协议支持已经落实到工程实现中。",
            "规则动作实验表明，alert、block和respond三类动作能够产生差异化响应：告警保留业务链路，阻断直接拒绝请求，自定义响应则能够输出指定状态码和响应内容。结合事件落库、画像沉淀和控制台展示，系统已具备本科毕业设计所需的功能验证依据。",
        ],
    )

    removed_53 = compress_section(
        body,
        "5.3 系统实现效果分析",
        "5.4 存在的不足与改进方向",
        [
            "从实现效果看，本文系统体现出较完整的工程链条：后端具备多协议接入、四层/七层协同检测、规则裁决、代理治理和持久化能力，前端能够围绕规则、事件、画像、证书、站点和联动状态提供管理入口。与单一规则演示程序相比，该系统更接近轻量级安全网关的形态。",
            "系统的主要优势在于分层协同思路清晰、协议覆盖较广、运行数据可追溯、控制台可操作性较强；不足则在于复杂语义检测、长期压力评估、HTTP/3真实客户端实测和运行时热更新仍需进一步加强。因此，本文结论应定位为原型系统的可行性验证，而不是成熟商业WAF的完整替代方案。",
        ],
    )

    repair_abstract_tc(root)

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
    print(f"removed_4_6_elements={removed_46}")
    print(f"removed_5_2_elements={removed_52}")
    print(f"removed_5_3_elements={removed_53}")


if __name__ == "__main__":
    main()
