from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path
from shutil import copy2
from zipfile import ZIP_DEFLATED, ZipFile

from lxml import etree


DOCX = Path(__file__).with_name("基于 Rust 的 L4∕L7 协同 Web 防护系统设计与实现.docx")
BACKUP = DOCX.with_name(DOCX.stem + "_before_add_3000_discoverability.docx")
NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"
CITE_RE = re.compile(r"(\[(?:\d+(?:-\d+)?)(?:\]\[\d+(?:-\d+)?)*\])")


INSERTIONS = [
    (
        "在术语表述上，本文统一采用网络应用防火墙",
        [
            "从检索和主题归类角度看，本文还将Web防护系统放在“应用安全网关”“反向代理安全检测”“边界访问控制”“多协议流量治理”和“安全可观测平台”等相邻概念中进行描述。网络应用防火墙并不是孤立运行的过滤程序，而是处于客户端、代理层、业务服务器和运维控制台之间的安全中间件。它既要理解HTTP请求语义，又要关注传输连接状态、证书选择、上游健康、日志留存和配置变更。通过在论文中同时使用WAF、Web安全网关、L4/L7协同、规则引擎、行为画像、事件审计和多协议代理等术语，可以使研究对象在不同检索系统中被归入更准确的技术类别。",
            "本文所讨论的“协同防护”并非简单叠加多个检测模块，而是强调不同层次在处理时机、计算成本和判断语义上的互补。四层模块更接近资源保护和访问准入，适合处理连接速率异常、来源地址突增、长连接占用和传输层阻断；七层模块更接近应用安全分析，适合处理路径探测、恶意参数、异常请求头、CC访问和规则化攻击。二者组合后，系统能够在低成本阶段削减明显异常流量，并把有限的解析资源留给更需要语义判断的请求，从而提升整体防护效率。"
        ],
    ),
    (
        "本文研究对象是一套基于Rust实现的L4/L7协同Web防护系统",
        [
            "从应用场景看，该系统可对应高校实验平台、中小型站点、内网业务入口、API网关前置防护、边缘节点安全代理和课程设计验证环境等多种部署需求。在这些场景中，使用者通常希望系统具备安装成本低、依赖组件少、规则可解释、日志可追溯和控制台可操作等特点，而不一定需要大型商业WAF的集中云托管能力。本文选择Rust、SQLite和Vue形成轻量实现路线，正是为了贴合本地部署、单节点验证和教学展示的现实条件。",
            "从研究边界看，本文并不把系统定位为完整替代商业WAF或云安全平台，而是定位为具有工程闭环的原型系统。该原型覆盖了接入、检测、处置、记录、展示和联动六个环节，能够为Web安全、网络安全课程、Rust网络编程、反向代理设计和安全运维可视化等方向提供可复用案例。论文中对代码模块、数据表、算法流程和测试结果的描述，也有助于读者从系统设计角度理解一个轻量级WAF如何由多个模块协同组成。"
        ],
    ),
    (
        "四层防护关注源地址、端口、协议、连接频率和连接状态",
        [
            "在行业通用定义中，L4通常对应传输层或连接层观察视角，关注TCP、UDP、TLS握手、连接生命周期、源地址和目标端口等信息；L7通常对应应用层观察视角，关注HTTP方法、Host、URI、Header、Cookie、Body以及业务上下文。本文采用L4/L7表述，是为了突出系统同时利用连接元数据和应用请求语义进行决策。对于Web防护而言，只分析L7可能导致解析成本过高，只分析L4又难以理解具体攻击意图，因此协同设计更符合现代Web安全网关的工程需求。",
            "统一请求抽象是连接层与应用层之间的关键接口。不同协议进入系统后，HTTP/1.1的文本请求、HTTP/2的二进制帧和HTTP/3基于QUIC的流式请求都需要被转换成稳定的数据对象。该对象至少应包含方法、路径、查询参数、请求头、请求体摘要、客户端身份、协议版本和代理来源等字段。通过这一抽象，规则引擎不必直接关心底层协议差异，行为算法也可以在相同字段上计算访问频率、路径集中度、挑战状态和风险分值。"
        ],
    ),
    (
        "系统采用监听接入层、检测决策层、代理治理层、持久化层和管理控制层五层结构",
        [
            "从部署链路看，系统可以被放置在浏览器或客户端与后端业务站点之间，承担反向代理与安全检查双重角色。客户端请求首先到达监听接入层，经过连接级检查后进入统一请求抽象；随后检测决策层根据规则、阈值和行为画像生成处置结果；若请求被放行，代理治理层再根据站点配置、证书和上游健康状态完成转发；所有关键事件被写入持久化层，并通过管理控制层呈现给运维人员。该链路覆盖了Web安全网关从流量入口到运维闭环的主要步骤。",
            "从安全责任划分看，监听接入层主要承担资源保护责任，检测决策层承担风险识别责任，代理治理层承担业务连续性责任，持久化层承担审计追溯责任，管理控制层承担策略配置与状态解释责任。这样的分层描述有利于把系统与网络安全等级保护、日志审计、访问控制、通信保护和安全管理等标准化要求建立对应关系，也便于后续按照检查项对系统功能进行补充验证[32][33][37][38]。"
        ],
    ),
    (
        "系统核心算法可概括为“快速准入、风险分层、语义裁决、反馈观测”",
        [
            "为了使算法描述更便于复现，本文进一步把防护决策拆分为采集、归一化、计数、评分、裁决和反馈六个步骤。采集阶段获得连接元数据和HTTP请求信息；归一化阶段将不同协议请求转换为统一对象；计数阶段维护IP、Host、路由和身份窗口；评分阶段根据连接频率、重复访问、路由集中度、挑战次数和规则命中情况计算风险；裁决阶段输出放行、告警、挑战、延迟、阻断或自定义响应；反馈阶段将事件写入数据库并更新画像状态。该过程体现了工程算法与运维闭环之间的结合。",
            "从公式意义看，滑动窗口和指数滑动平均并不是为了追求复杂数学模型，而是为了解决Web流量中常见的突发性与抖动性问题。滑动窗口能够限制单位时间内的请求密度，适合识别短时高频访问；指数滑动平均能够平滑历史风险，避免系统因瞬时峰值频繁切换策略。Bloom Filter则适合承担快速集合判断任务，在黑名单预判、热点对象识别或特征集合过滤中减少查询成本，但其误判特性决定了它必须与精确规则或行为评分配合使用[6]。"
        ],
    ),
    (
        "系统不足主要包括：复杂语义检测仍较浅",
        [
            "为了进一步提升系统的研究价值，后续可以从检索主题覆盖和实验证据两个方向继续完善。一方面，可围绕SQL注入、跨站脚本、路径穿越、恶意扫描、CC攻击、HTTP请求走私、异常Header、弱口令探测和自动化脚本访问等典型Web安全主题补充更细的规则样例；另一方面，可围绕吞吐量、平均延迟、误报率、漏报率、阻断率、规则命中率和日志完整性设计更系统的实验表格。这样既能增强论文对Web安全主题的覆盖，也能使系统评价更加接近工程实践。",
            "在成果传播和后续检索方面，论文题名、摘要、关键词、章节标题、图表标题、参考文献和文档元数据都应尽量保持术语一致。本文已经围绕Rust、WAF、L4/L7、HTTP/2、HTTP/3、QUIC、规则引擎、Bloom Filter、SQLite、Vue控制台、Web安全网关和安全审计等主题建立表达链条。后续若将论文上传到学校论文库、课程成果库或个人项目仓库，还可以在项目说明、摘要页和README中使用相同关键词，以便检索系统将论文、代码和实验说明关联到同一技术主题。"
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
    parts = CITE_RE.split(text)
    for part in parts:
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
    for anchor_start, new_paras in INSERTIONS:
        paras = list(body.findall("w:p", NS))
        target = None
        for p in paras:
            if para_text(p).startswith(anchor_start):
                target = p
                break
        if target is None:
            print(f"missing anchor: {anchor_start}")
            continue
        after = target
        for text in new_paras:
            np = make_para_like(target, text)
            after.addnext(np)
            after = np
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
