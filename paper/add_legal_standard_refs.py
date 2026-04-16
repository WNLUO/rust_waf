from pathlib import Path
import re
import shutil
import zipfile

from lxml import etree


DOCX = Path("/Users/wnluo/Desktop/code/rust_waf/paper/基于 Rust 的 L4∕L7 协同 Web 防护系统设计与实现.docx")
BACKUP = DOCX.with_name("基于 Rust 的 L4∕L7 协同 Web 防护系统设计与实现_before_legal_standard_refs.docx")

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


def add_run(p, text, sup=False):
    r = etree.SubElement(p, qn("w:r"))
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


def body_para(text):
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
            add_run(p, text[pos:m.start()])
        for token in re.findall(r"\[\d+\]", m.group(0)):
            add_run(p, token, sup=True)
        pos = m.end()
    if pos < len(text):
        add_run(p, text[pos:])
    return p


def insert_after_anchor(body, anchor, text):
    joined = "\n".join(text_of(p) for p in body.findall("w:p", NS))
    if text[:32] in joined:
        return False
    for p in body.findall("w:p", NS):
        if anchor in text_of(p):
            p.addnext(body_para(text))
            return True
    raise RuntimeError(f"anchor not found: {anchor}")


def clone_ref_para(template, text):
    p = etree.fromstring(etree.tostring(template))
    for r in list(p.findall("w:r", NS)):
        p.remove(r)
    r = etree.SubElement(p, qn("w:r"))
    rpr = etree.SubElement(r, qn("w:rPr"))
    rf = etree.SubElement(rpr, qn("w:rFonts"))
    rf.set(qn("w:ascii"), "Times New Roman")
    rf.set(qn("w:hAnsi"), "Times New Roman")
    rf.set(qn("w:cs"), "Times New Roman")
    rf.set(qn("w:eastAsia"), "宋体")
    for tag in ["w:sz", "w:szCs"]:
        sz = etree.SubElement(rpr, qn(tag))
        sz.set(qn("w:val"), "21")
    t = etree.SubElement(r, qn("w:t"))
    t.text = text
    return p


def repair_abstract_tc(root):
    body = root.find(".//w:body", NS)
    for p in body.findall("w:p", NS):
        if "摘  要" not in text_of(p):
            continue
        existing = "".join(n.text or "" for n in p.findall(".//w:instrText", NS))
        if 'TC "摘要"' in existing:
            return
        insert_at = 1 if p.find("w:pPr", NS) is not None else 0
        r1 = etree.Element(qn("w:r"))
        etree.SubElement(etree.SubElement(r1, qn("w:rPr")), qn("w:vanish"))
        fc = etree.SubElement(r1, qn("w:fldChar"))
        fc.set(qn("w:fldCharType"), "begin")
        r2 = etree.Element(qn("w:r"))
        etree.SubElement(etree.SubElement(r2, qn("w:rPr")), qn("w:vanish"))
        instr = etree.SubElement(r2, qn("w:instrText"))
        instr.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
        instr.text = ' TC "摘要" \\f C \\l 1 '
        r3 = etree.Element(qn("w:r"))
        etree.SubElement(etree.SubElement(r3, qn("w:rPr")), qn("w:vanish"))
        fc = etree.SubElement(r3, qn("w:fldChar"))
        fc.set(qn("w:fldCharType"), "end")
        for r in reversed([r1, r2, r3]):
            p.insert(insert_at, r)
        return


def main():
    if not BACKUP.exists():
        shutil.copy2(DOCX, BACKUP)
    with zipfile.ZipFile(DOCX) as zin:
        files = {name: zin.read(name) for name in zin.namelist()}
    root = etree.fromstring(files["word/document.xml"])
    body = root.find(".//w:body", NS)

    additions = [
        (
            "从文献依据看，网络应用防火墙并不是单纯的访问控制列表",
            "从我国网络安全治理框架看，Web防护系统的建设还具有明确的法律和标准依据。《中华人民共和国网络安全法》明确提出“国家实行网络安全等级保护制度”[29]，数据安全法要求开展数据处理活动时建立相应的数据安全管理制度和技术保护措施[30]，个人信息保护法也强调防止未经授权访问以及个人信息泄露、篡改、丢失[31]。因此，本文系统虽然是本科毕业设计原型，但其规则管理、访问控制、日志审计、事件留存和控制台鉴权等设计，仍应放在网络运行安全、数据安全和个人信息保护的规范框架下理解。",
        ),
        (
            "围绕上述研究问题，本文在设计上遵循四项原则",
            "结合国家标准，本文将“网络防护能力”进一步界定为由技术防护、管理控制和审计验证共同构成的综合能力。GB/T 22239-2019从安全物理环境、安全通信网络、安全区域边界、安全计算环境和安全管理中心等方面提出等级保护基本要求[32]；GB/T 28448-2019则从测评角度强调对安全控制措施的符合性、有效性和风险影响进行验证[33]。据此，本文系统的设计原则不仅包括能否阻断攻击，还包括配置是否可管理、事件是否可追溯、运行状态是否可观测以及测试结果是否能够支撑论文结论。",
        ),
        (
            "四层防护主要关注源IP、目的IP、端口、传输协议、连接频率和连接状态等信息",
            "为避免概念混用，本文对若干基础术语作如下限定：所谓威胁，是指可能利用系统脆弱性并对资产造成损害的潜在因素；所谓脆弱性，是指系统设计、实现、配置或管理中可能被威胁利用的弱点；所谓风险，是指威胁利用脆弱性后造成影响的可能性及其后果组合。GB/T 25069-2022作为信息安全术语标准，对安全服务、鉴别授权、通信安全、应用安全、数据安全和安全测评等术语进行了分类整理[35]。因此，本文所称四层风险、七层行为风险和规则命中风险，并不等同于单个异常请求，而是结合来源身份、访问频率、协议上下文和处置结果形成的综合判断。",
        ),
        (
            "系统建设目标",
            "在定级与保护对象理解上，GB/T 22240-2020强调应根据业务信息安全和系统服务安全受到破坏后所侵害的客体及侵害程度确定安全保护等级[34]。虽然本文系统并非面向某一正式备案系统开展等保测评，但其部署位置接近应用边界，能够影响站点访问、事件记录和管理操作，因此在工程设计中仍需参考等级保护思想，将数据面、控制面和审计面作为相互关联的保护对象。GB/T 20271-2006关于通用安全技术要求的内容也提示，身份鉴别、访问控制、安全审计、通信保护和系统容错是信息系统安全设计中的基础要素[37]。",
        ),
        (
            "工程化网络应用防火墙不仅要具备拦截能力",
            "从个人信息和日志数据处理角度看，安全系统本身也会产生来源IP、请求路径、浏览器指纹、封禁记录和行为画像等数据。GB/T 35273-2020将个人信息处理活动概括为收集、存储、使用、共享、转让、公开披露和删除等环节，并提出相应安全要求[36]。因此，本文系统在保存安全事件和画像数据时，应坚持最小必要、可追溯、可删除和权限受控原则；对控制台展示的数据，也应避免把安全审计需要扩大为无边界的数据收集。",
        ),
        (
            "从学术表述上看，本文所谓“核心算法”并不等同于某一个孤立数学公式",
            "为使算法表达更严谨，本文将核心裁决过程抽象为五元组A=(I,S,F,T,O)：其中I表示输入集合，包括连接元数据、统一请求对象、规则配置和历史事件；S表示状态集合，包括计数窗口、风险分桶、画像样本和阻断表；F表示特征提取函数，用于从I和S中计算连接频率、等效请求数、重复访问比例、路由集中度和挑战次数；T表示阈值集合，包括连接阈值、挑战阈值、阻断阈值和过载等级阈值；O表示输出动作集合，包括放行、告警、挑战、延迟、阻断和自定义响应。该定义能够把四层限流、七层CC、行为画像和规则引擎统一到“输入—状态—特征—阈值—动作”的算法框架下。",
        ),
        (
            "风险分值采用指数滑动平均方式平滑波动",
            "在分值更新公式Snext=α×Sewma+(1-α)×min(Sraw,100)中，α为平滑系数，取值范围为0≤α≤1；Sraw表示当前窗口根据连接数、请求数、反馈次数和异常行为计算得到的原始风险；Sewma表示上一轮平滑后的历史风险；Snext表示本轮输出的平滑风险。α越大，算法越依赖历史状态，风险分值变化更平缓；α越小，算法越敏感于当前窗口，能够更快响应突发异常。本文实现中采用0.7与0.3的权重组合，是在稳定性与响应速度之间进行折中，适合原型系统对风险抖动进行抑制。",
        ),
        (
            "尽管系统已经具备较好的完整性",
            "后续若将本系统用于更正式的实验或课程成果验收，可将GB/T 28448-2019的测评思想转化为检查表：先确认保护对象和边界，再检查身份鉴别、访问控制、安全审计、通信保护、入侵防范和恶意代码防范等控制项，最后结合测试证据判断控制措施是否有效[33]。同时，GB/T 20269-2006所强调的策略制度、机构人员、风险管理和安全运维等管理要求也提示，安全系统的成熟度不只取决于代码实现，还取决于配置流程、权限分工、日志留存和应急处置机制[38]。",
        ),
    ]

    inserted = 0
    for anchor, para in additions:
        if insert_after_anchor(body, anchor, para):
            inserted += 1

    refs = [
        "[29] 全国人民代表大会常务委员会. 中华人民共和国网络安全法[Z/OL]. 2025年修正.",
        "[30] 全国人民代表大会常务委员会. 中华人民共和国数据安全法[Z/OL]. 2021.",
        "[31] 全国人民代表大会常务委员会. 中华人民共和国个人信息保护法[Z/OL]. 2021.",
        "[32] 国家市场监督管理总局, 国家标准化管理委员会. GB/T 22239-2019 信息安全技术 网络安全等级保护基本要求[S]. 2019.",
        "[33] 国家市场监督管理总局, 国家标准化管理委员会. GB/T 28448-2019 信息安全技术 网络安全等级保护测评要求[S]. 2019.",
        "[34] 国家市场监督管理总局, 国家标准化管理委员会. GB/T 22240-2020 信息安全技术 网络安全等级保护定级指南[S]. 2020.",
        "[35] 国家市场监督管理总局, 国家标准化管理委员会. GB/T 25069-2022 信息安全技术 术语[S]. 2022.",
        "[36] 国家市场监督管理总局, 国家标准化管理委员会. GB/T 35273-2020 信息安全技术 个人信息安全规范[S]. 2020.",
        "[37] 国家质量监督检验检疫总局, 中国国家标准化管理委员会. GB/T 20271-2006 信息安全技术 信息系统通用安全技术要求[S]. 2006.",
        "[38] 国家质量监督检验检疫总局, 中国国家标准化管理委员会. GB/T 20269-2006 信息安全技术 信息系统安全管理要求[S]. 2006.",
    ]
    all_text = "\n".join(text_of(p) for p in body.findall("w:p", NS))
    last_ref = None
    for p in body.findall("w:p", NS):
        if re.match(r"^\[\d+\]", text_of(p)):
            last_ref = p
    added_refs = 0
    if last_ref is not None:
        anchor = last_ref
        for ref in refs:
            if ref[:5] in all_text:
                continue
            new_ref = clone_ref_para(last_ref, ref)
            anchor.addnext(new_ref)
            anchor = new_ref
            added_refs += 1

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
    print(f"inserted_paragraphs={inserted}")
    print(f"added_refs={added_refs}")


if __name__ == "__main__":
    main()
