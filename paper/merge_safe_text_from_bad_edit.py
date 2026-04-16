from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path
from shutil import copy2
from zipfile import ZIP_DEFLATED, ZipFile

from lxml import etree


DOCX = Path(__file__).with_name("基于 Rust 的 L4∕L7 协同 Web 防护系统设计与实现.docx")
BAD = Path(__file__).with_name("基于 Rust 的 L4∕L7 协同 Web 防护系统设计与实现_before_restore_from_bad_user_edit.docx")
BACKUP = DOCX.with_name(DOCX.stem + "_before_merge_safe_text_from_bad_edit.docx")
NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"
CITE_RE = re.compile(r"(\[(?:\d+(?:-\d+)?)(?:\]\[\d+(?:-\d+)?)*\])")


SAFE_INSERTIONS = [
    (
        "从行业定义看，Web Application Firewall通常被理解为部署在Web应用前方",
        [
            "从防火墙技术演进看，传统包过滤防火墙主要依据源地址、目的地址、端口和协议类型等五元组信息进行访问控制，状态检测防火墙进一步关注连接状态和会话过程，而网络应用防火墙则把检测对象扩展到HTTP请求语义、路径参数、请求头、Cookie和请求体等应用层内容。本文系统在四层和七层之间建立协同关系，正是为了兼顾连接级快速治理和应用层精细识别，避免单纯依赖某一层造成防护盲区。",
        ],
    ),
    (
        "Rust强调内存安全、零成本抽象和高性能并发",
        [
            "Rust所有权机制规定每个值在任一时刻只有一个所有者，所有者离开作用域时值被释放；借用检查器进一步限制可变引用和不可变引用的并发关系，从编译阶段降低悬垂指针、越界访问和数据竞争风险[4][5]。对于需要长期运行的Web安全网关而言，这种内存安全模型能够减少由底层资源管理错误引入的新安全问题。",
        ],
    ),
    (
        "四层防护关注源地址、端口、协议、连接频率和连接状态",
        [
            "在限流策略中，漏桶算法强调以固定速率平滑处理请求，适合削峰和稳定输出；令牌桶算法则允许在令牌充足时处理一定突发流量，更适合兼顾突发访问和平均速率控制。本文系统的一秒级连接窗口、滑动窗口CC判断和行为分桶预算，都可以看作这些经典限流思想在Web防护场景中的工程化变体。",
        ],
    ),
    (
        "HTTP/2和HTTP/3的协议演进进一步强化了统一抽象的必要性",
        [
            "根据HTTP/2相关标准，二进制分帧层将请求和响应拆分为帧并组织到流中，以实现多路复用和头部压缩[7]；HTTP/3则借助QUIC把传输可靠性、加密握手和流控制整合到UDP之上[8][9]。这些差异说明，多协议WAF若缺少统一请求抽象，就容易在协议升级过程中出现规则适配不一致和审计字段不统一的问题。",
        ],
    ),
    (
        "规则引擎是WAF的核心能力",
        [
            "Bloom Filter的误判率与位数组长度m、插入元素数量n和哈希函数个数k有关，常用近似公式为p=(1-e-kn/m)k；当k=(m/n)ln2时，误判率可取得较优值[6]。这一性质说明Bloom Filter适合承担快速预筛任务，但不适合作为唯一阻断依据，仍需与规则引擎、行为评分或精确查表结合使用。",
        ],
    ),
    (
        "测试结果显示，后端cargo test共237项通过",
        [
            "误改版中保留的验证信息显示，前端Vitest包含1个测试文件和2个测试用例，生产构建过程中完成约2454个模块转换，构建流程能够成功结束但存在大chunk提示。这些数据可作为工程验证的补充说明：系统不仅后端测试通过，前端控制台也能够完成基础测试和生产打包，但仍需在后续优化中关注前端包体积与资源拆分。",
            "本地轻量接口实验还可作为补充验证思路：选择health、metrics和dashboard/traffic-map等代表性管理接口，使用固定请求次数和并发度观察平均响应时间。该类实验不能替代生产级压测，但可以为管理面接口的基础可用性和短时响应能力提供初步证据。"
        ],
    ),
    (
        "系统不足主要包括：复杂语义检测仍较浅",
        [
            "从后续完善方向看，系统还可以补充请求体结构化解析、参数级异常检测、HTTP请求走私识别、异常Header统计、HTTP/3异常流观测和策略热更新能力。对于控制台部分，则可继续增强前端包体积优化、实时图表压力测试和角色权限细分，使系统从教学原型进一步接近真实运维环境。"
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
    if not BAD.exists():
        raise FileNotFoundError(BAD)
    if not BACKUP.exists():
        copy2(DOCX, BACKUP)

    with ZipFile(DOCX, "r") as zin:
        entries = {name: zin.read(name) for name in zin.namelist()}

    doc = etree.fromstring(entries["word/document.xml"])
    body = doc.find("w:body", NS)
    if body is None:
        raise RuntimeError("document body not found")

    existing = "\n".join(para_text(p) for p in body.findall("w:p", NS))
    inserted = 0
    for anchor_start, paragraphs in SAFE_INSERTIONS:
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
            if text in existing:
                continue
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
