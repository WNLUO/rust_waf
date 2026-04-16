from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path
from shutil import copy2
from zipfile import ZIP_DEFLATED, ZipFile

from lxml import etree


DOCX = Path(__file__).with_name("基于 Rust 的 L4∕L7 协同 Web 防护系统设计与实现.docx")
BACKUP = DOCX.with_name(DOCX.stem + "_before_cited_standard_basis.docx")
NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"
CITE_RE = re.compile(r"(\[(?:\d+(?:-\d+)?)(?:\]\[\d+(?:-\d+)?)*\])")


INSERTIONS = [
    (
        "从检索和主题归类角度看，本文还将Web防护系统放在",
        [
            "从行业定义看，Web Application Firewall通常被理解为部署在Web应用前方、依据HTTP请求语义、规则集合和安全策略对恶意访问进行检测、过滤、记录或阻断的应用层安全组件[1][2][3]。OWASP相关资料也将WAF能力与规则维护、日志审计、误报控制和部署模式联系在一起，说明WAF并不是单一函数或单一黑名单，而是由检测引擎、策略规则、动作处置和运维反馈共同组成的安全机制[1][15]。本文系统沿用这一通用定义，将网络应用防火墙界定为位于客户端与业务站点之间、同时承担代理转发、协议归一化、规则裁决和安全审计职责的边界防护系统。",
            "从标准化表述看，网络安全等级保护要求关注边界防护、访问控制、安全审计、通信保护和集中管理等控制项[32][33]。虽然本文系统属于本科毕业设计原型，但其功能模块与这些控制项具有对应关系：四层限流和阻断表对应边界访问控制，七层规则引擎对应应用访问控制，事件落库对应安全审计，TLS与证书管理对应通信保护，Vue控制台和配置接口对应安全管理中心。通过这种对应关系，可以使系统设计不只停留在工程实现层面，也能与国家标准中的安全控制框架形成呼应。"
        ],
    ),
    (
        "在行业通用定义中，L4通常对应传输层或连接层观察视角",
        [
            "HTTP/2和HTTP/3的协议演进进一步强化了统一抽象的必要性。HTTP/2通过二进制分帧、多路复用和头部压缩改变了传统HTTP请求的传输形态；HTTP/3则建立在QUIC之上，将传输层连接管理、加密握手和流控制机制进一步整合[7][8][9]。如果安全网关分别为每种协议编写完全独立的检测逻辑，将造成规则重复、审计口径不一致和维护成本上升。因此，本文把HTTP/1.1、HTTP/2与HTTP/3统一转换为请求对象，再由同一套规则和行为算法进行判断。",
            "在Web安全测试语境中，认证、授权、输入验证、配置管理、日志监控和错误处理通常被视为应用安全评估的重要方面[22][23][28]。本文系统虽然不是完整的应用安全测试平台，但其规则引擎、自定义响应、控制台鉴权、安全事件、行为画像和日志查询功能能够为这些测试维度提供支撑。换言之，WAF原型系统的价值不仅在于能否拦截某一次攻击请求，还在于能否把拦截依据、请求特征、处置动作和后续审计记录保存下来，形成可复核的安全证据链。"
        ],
    ),
    (
        "从安全责任划分看，监听接入层主要承担资源保护责任",
        [
            "按照信息安全术语标准，威胁、脆弱性、风险、鉴别、授权、访问控制和审计等概念均属于安全系统设计中的基础术语[35]。在本文系统中，威胁主要表现为异常连接、恶意请求、自动化扫描和规则化攻击；脆弱性主要表现为协议解析差异、配置错误、上游暴露和管理面权限不足；风险则体现为威胁利用脆弱性后对业务可用性、数据安全和运维秩序造成的潜在影响。基于这一术语框架，系统通过限流、挑战、阻断、告警和审计记录等动作降低风险。"
        ],
    ),
    (
        "为了使算法描述更便于复现，本文进一步把防护决策拆分为采集",
        [
            "从算法评价角度看，安全防护系统不能只说明“能够阻断”，还应说明阻断依据、阈值来源、状态更新和误判控制。滑动窗口限流适合表达单位时间内的访问强度，指数滑动平均适合缓解短时峰值带来的策略抖动，Bloom Filter适合在集合规模较大时进行快速预判，但其误判概率决定了它不能单独作为最终阻断依据[6]。因此，本文将快速预判、风险评分和规则精确匹配组合使用，以便在性能、准确性和可解释性之间取得平衡。"
        ],
    ),
    (
        "为了进一步提升系统的研究价值，后续可以从检索主题覆盖和实验证据两个方向继续完善",
        [
            "若从论文复核和工程验收角度进一步展开，可将后续测试划分为功能正确性、协议兼容性、安全控制有效性、性能稳定性和审计完整性五类。功能正确性关注规则命中、动作响应和配置保存；协议兼容性关注HTTP/1.1、HTTP/2、HTTP/3和QUIC处理一致性；安全控制有效性关注SQL注入、XSS、路径穿越、扫描探测和CC攻击等典型场景；性能稳定性关注吞吐量、延迟、连接数和资源占用；审计完整性关注事件字段、来源身份、处置动作和日志留存。上述分类与OWASP测试资料、WAF评估资料和等级保护测评思路具有一致性[15][22][23][33]。"
        ],
    ),
]


def para_text(p: etree._Element) -> str:
    return "".join(p.xpath(".//w:t/text()", namespaces=NS)).strip()


def add_run(p: etree._Element, text: str, rpr: etree._Element | None = None) -> None:
    r = etree.SubElement(p, W + "r")
    if rpr is not None:
        r.append(deepcopy(rpr))
    t = etree.SubElement(r, W + "t")
    if text.startswith(" ") or text.endswith(" "):
        t.set(XML_SPACE, "preserve")
    t.text = text


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


def add_text_with_citations(p: etree._Element, text: str) -> None:
    for part in CITE_RE.split(text):
        if not part:
            continue
        if CITE_RE.fullmatch(part):
            for m in re.finditer(r"\[\d+(?:-\d+)?\]", part):
                add_run(p, m.group(0), rpr_citation())
        else:
            add_run(p, part)


def make_para_like(anchor: etree._Element, text: str) -> etree._Element:
    p = etree.Element(W + "p")
    ppr = anchor.find("w:pPr", NS)
    if ppr is not None:
        p.append(deepcopy(ppr))
    add_text_with_citations(p, text)
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

    inserted = 0
    for anchor_start, paragraphs in INSERTIONS:
        target = None
        for p in body.findall("w:p", NS):
            if para_text(p).startswith(anchor_start):
                target = p
                break
        if target is None:
            print(f"missing anchor: {anchor_start}")
            continue
        after = target
        for text in paragraphs:
            new_p = make_para_like(target, text)
            after.addnext(new_p)
            after = new_p
            inserted += 1

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
    print(f"inserted_paragraphs={inserted}")


if __name__ == "__main__":
    main()
