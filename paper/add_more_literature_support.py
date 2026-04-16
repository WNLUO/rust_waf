from pathlib import Path
import re
import shutil
import zipfile

from lxml import etree


DOCX = Path("/Users/wnluo/Desktop/code/rust_waf/paper/基于 Rust 的 L4∕L7 协同 Web 防护系统设计与实现.docx")
BACKUP = DOCX.with_name("基于 Rust 的 L4∕L7 协同 Web 防护系统设计与实现_before_more_literature.docx")

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
    for match in re.finditer(r"\[(?:\d+)(?:\]\[\d+)*\]", text):
        if match.start() > pos:
            add_run(p, text[pos:match.start()])
        for token in re.findall(r"\[\d+\]", match.group(0)):
            add_run(p, token, sup=True)
        pos = match.end()
    if pos < len(text):
        add_run(p, text[pos:])
    return p


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
    sz = etree.SubElement(rpr, qn("w:sz"))
    sz.set(qn("w:val"), "21")
    szcs = etree.SubElement(rpr, qn("w:szCs"))
    szcs.set(qn("w:val"), "21")
    t = etree.SubElement(r, qn("w:t"))
    t.text = text
    return p


def insert_after_anchor(body, anchor, paragraph_text):
    if paragraph_text[:30] in "\n".join(text_of(p) for p in body.findall("w:p", NS)):
        return False
    for p in body.findall("w:p", NS):
        if anchor in text_of(p):
            p.addnext(body_para(paragraph_text))
            return True
    raise RuntimeError(f"anchor not found: {anchor}")


def repair_abstract_tc(root):
    body = root.find(".//w:body", NS)
    for p in body.findall("w:p", NS):
        if "摘  要" not in text_of(p):
            continue
        # Do not remove visible text; only ensure the TC field exists.
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
            "综合已有资料可以看出，国外开源实践更强调规则体系",
            "应用安全验证和测试资料进一步说明，Web安全系统的设计不应只围绕少数攻击样例展开，而应面向可验证的安全控制和可复核的测试过程。OWASP ASVS提供了应用安全需求的分层验证框架，WSTG则从信息收集、配置审查、认证授权、输入验证和业务逻辑测试等角度整理了Web安全测试方法[22][23]。这些资料提示本文在描述系统能力时，应同时说明检测规则、配置管理、日志审计和测试验证之间的关系，使论文论证从“功能已经实现”扩展到“安全控制可被验证”。",
        ),
        (
            "从协议标准角度看，HTTP/1.1更接近传统文本请求模型",
            "HTTP/3相关生态还包含QPACK头部压缩和可扩展优先级等配套机制，这些机制虽然主要服务于传输效率和资源调度，但也会影响网关对请求头、流、优先级和连接状态的观察方式[25][26]。因此，本文系统把HTTP/3支持放在统一请求抽象和协议元数据传递框架下讨论，而不是把它简单视为HTTP/1.1接口的替换版本。这样的处理能够更准确地反映多协议网关在检测一致性、可观测性和后续扩展方面面临的工程约束。",
        ),
        (
            "工程化网络应用防火墙不仅要具备拦截能力",
            "在云原生和微服务环境中，应用系统通常被拆分为多个服务、接口和独立部署单元，安全控制也随之从单点边界防护扩展为服务间通信、身份、策略和观测的组合问题。NIST关于微服务安全策略的文档强调，微服务架构需要关注服务发现、接口暴露、通信保护、访问控制和监控审计等方面[24]；零信任架构则强调不默认信任网络位置，而是基于身份、设备、策略和上下文持续做访问决策[27]。这与本文系统强调的站点治理、规则配置、事件记录和控制面可观测具有一致性。",
        ),
        (
            "系统管理面由Axum接口和Vue控制台组成",
            "从安全开发实践看，控制台本身也属于受保护的管理面，而不是普通展示页面。OWASP Cheat Sheet Series以简明实践指南形式覆盖认证、会话管理、输入验证、日志记录、TLS和访问控制等主题[28]，对本文系统的管理API和前端控制台具有直接参考意义。因而，本文在评价控制台实现时，不只关注页面是否能够展示数据，还关注令牌校验、配置写入、事件审计和敏感操作入口是否能够形成基本的管理闭环。",
        ),
        (
            "尽管系统已经具备较好的完整性",
            "从后续研究角度看，系统还可以进一步把ASVS、WSTG和OWASP Cheat Sheet中的要求转化为更细的测试用例与验收项[22][23][28]。例如，管理端认证与授权可对应访问控制验证，规则输入与自定义响应可对应输入验证和输出处理，事件审计可对应日志与监控要求；协议层则可继续结合HTTP/3、QPACK和优先级机制补充异常流、头部压缩边界和降级路径测试[25][26]。这样可以使后续改进从“继续增加功能”转向“按安全要求补齐验证证据”。",
        ),
    ]
    inserted = 0
    for anchor, para in additions:
        if insert_after_anchor(body, anchor, para):
            inserted += 1

    refs = [
        "[22] OWASP Foundation. OWASP Application Security Verification Standard (ASVS)[EB/OL]. [2026-04-16]. https://owasp.org/www-project-application-security-verification-standard/.",
        "[23] OWASP Foundation. OWASP Web Security Testing Guide[EB/OL]. [2026-04-16]. https://owasp.org/www-project-web-security-testing-guide/.",
        "[24] Chandramouli R. Security Strategies for Microservices-based Application Systems[S/OL]. NIST SP 800-204, 2019.",
        "[25] Krasic C, Bishop M, Frindell A. QPACK: Field Compression for HTTP/3[S/OL]. RFC 9204, 2022.",
        "[26] Oku K, Nottingham M. Extensible Prioritization Scheme for HTTP[S/OL]. RFC 9218, 2022.",
        "[27] Rose S, Borchert O, Mitchell S, Connelly S. Zero Trust Architecture[S/OL]. NIST SP 800-207, 2020.",
        "[28] OWASP Foundation. OWASP Cheat Sheet Series[EB/OL]. [2026-04-16]. https://cheatsheetseries.owasp.org/.",
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
