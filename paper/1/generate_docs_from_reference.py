from copy import deepcopy
from pathlib import Path
import shutil
import zipfile
import xml.etree.ElementTree as ET


W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
XML_NS = "http://www.w3.org/XML/1998/namespace"
ET.register_namespace("w", W_NS)


def qn(tag: str) -> str:
    return f"{{{W_NS}}}{tag}"


def get_text(paragraph: ET.Element) -> str:
    return "".join(node.text or "" for node in paragraph.findall(".//w:t", {"w": W_NS}))


def set_paragraph_text(paragraph: ET.Element, text: str) -> None:
    first_run = paragraph.find("./w:r", {"w": W_NS})
    run_props = None
    if first_run is not None:
        props = first_run.find("./w:rPr", {"w": W_NS})
        if props is not None:
            run_props = deepcopy(props)

    for child in list(paragraph):
        if child.tag != qn("pPr"):
            paragraph.remove(child)

    run = ET.Element(qn("r"))
    if run_props is not None:
        run.append(run_props)

    parts = text.split("\n")
    for idx, part in enumerate(parts):
        if idx:
            run.append(ET.Element(qn("br")))
        t = ET.Element(qn("t"))
        if part.startswith(" ") or part.endswith(" "):
            t.set(f"{{{XML_NS}}}space", "preserve")
        t.text = part
        run.append(t)

    paragraph.append(run)


def insert_paragraph_after(anchor: ET.Element, text: str) -> ET.Element:
    new_para = deepcopy(anchor)
    set_paragraph_text(new_para, text)
    parent = anchor.getparent() if hasattr(anchor, "getparent") else None
    if parent is None:
        parent = anchor  # not used with stdlib, fallback below
    return new_para


def replace_zip_entry(docx_path: Path, entry_name: str, data: bytes) -> None:
    temp_path = docx_path.with_suffix(".tmp")
    with zipfile.ZipFile(docx_path, "r") as zin, zipfile.ZipFile(temp_path, "w") as zout:
        for item in zin.infolist():
            content = data if item.filename == entry_name else zin.read(item.filename)
            zout.writestr(item, content)
    temp_path.replace(docx_path)


def clone_paragraph(parent: ET.Element, template_para: ET.Element, text: str, after_para: ET.Element | None = None) -> ET.Element:
    new_para = deepcopy(template_para)
    set_paragraph_text(new_para, text)
    children = list(parent)
    if after_para is None:
        parent.append(new_para)
    else:
        parent.insert(children.index(after_para) + 1, new_para)
    return new_para


def set_section_paragraphs(body: ET.Element, heading_para: ET.Element, template_para: ET.Element, paragraphs: list[str], stop_para: ET.Element) -> None:
    children = list(body)
    start_idx = children.index(heading_para) + 1
    stop_idx = children.index(stop_para)
    for child in children[start_idx:stop_idx]:
        body.remove(child)
    last = heading_para
    for text in paragraphs:
        last = clone_paragraph(body, template_para, text, last)


def set_cell_section_paragraphs(cell: ET.Element, heading_idx: int, template_idx: int, stop_idx: int | None, paragraphs: list[str]) -> None:
    paras = cell.findall("./w:p", {"w": W_NS})
    heading_para = paras[heading_idx]
    template_para = paras[template_idx]
    children = list(cell)
    start = children.index(heading_para) + 1
    if stop_idx is None or stop_idx >= len(paras):
        stop = len(children)
    else:
        stop_para = paras[stop_idx]
        stop = children.index(stop_para)
    for child in children[start:stop]:
        cell.remove(child)
    last = heading_para
    for text in paragraphs:
        last = clone_paragraph(cell, template_para, text, last)


def build_literature_review(template: Path, output: Path) -> None:
    shutil.copyfile(template, output)
    with zipfile.ZipFile(output, "r") as zf:
        root = ET.fromstring(zf.read("word/document.xml"))

    ns = {"w": W_NS}
    body_paras = root.findall(".//w:body/w:p", ns)

    replacements = {
        15: "题    目：基于Rust的L4/L7协同Web防护系统设计与实现研究的文献综述",
        21: "时    间：2026年04月14日",
        45: "[1] OWASP Foundation. Web Application Firewall[EB/OL]. https://owasp.org/www-community/Web_Application_Firewall.",
        46: "[2] OWASP Foundation. OWASP ModSecurity[EB/OL]. https://owasp.org/www-project-modsecurity/.",
        47: "[3] OWASP Foundation. OWASP ModSecurity Core Rule Set[EB/OL]. https://waf.owasp.org/.",
        48: "[4] Klabnik S, Nichols C. The Rust Programming Language[M]. San Francisco: No Starch Press, 2019.",
        49: "[5] Blandy J, Orendorff J, Tindall L. Programming Rust: Fast, Safe Systems Development[M]. Sebastopol: O'Reilly Media, 2021.",
    }

    for idx, text in replacements.items():
        set_paragraph_text(body_paras[idx], text)

    body = root.find(".//w:body", ns)
    assert body is not None
    set_section_paragraphs(
        body,
        body_paras[28],
        body_paras[29],
        [
            "随着政务平台、在线教育、电商服务、媒体内容分发以及企业内部业务不断向Web端集中，Web应用已经成为组织对外提供服务的主要入口。Web入口一方面带来了便捷访问与统一交互，另一方面也暴露出大量攻击面，例如SQL注入、跨站脚本、目录遍历、弱口令扫描、自动化爬取、恶意探测以及高频CC请求等。这些问题使得“如何在网关侧对Web请求进行有效识别与拦截”成为网络安全实践中的重要议题。",
            "传统的边界防火墙更关注IP、端口、协议等网络层和传输层特征，适合用于粗粒度访问控制；而单纯依赖反向代理或应用日志分析，又往往难以及时完成实时阻断。因此，Web应用防火墙逐渐发展为介于网络接入与业务系统之间的专门防护组件，负责在请求进入应用之前完成协议解析、规则匹配、异常响应和审计记录。随着业务形态变化，现代WAF不再只是“返回一个拦截页”，而是需要兼顾性能、协议兼容、误报控制、配置管理和运行可观测性。",
            "近年来，Rust语言因其内存安全、并发性能和良好的系统编程能力，被越来越多地用于网络服务、中间件和安全工具开发。与传统C/C++实现相比，Rust通过所有权、借用和生命周期机制在编译阶段约束资源管理，能够降低缓冲区越界、悬垂引用和数据竞争等风险。对于需要长期运行、同时处理大量连接和请求的网关型程序而言，这种特性具有较强吸引力。",
            "基于此，本文围绕“基于Rust的L4/L7协同Web防护系统设计与实现”这一课题，对WAF体系、Rust系统编程、HTTP多协议处理、规则引擎、Bloom Filter与轻量级持久化等相关文献进行梳理。通过综述已有研究成果，既可以为后续开题报告和毕业论文奠定理论基础，也有助于明确本课题相对于已有研究的切入点，即以真实可运行项目为基础，形成兼顾接入、检测、治理、存储和控制台运维的一体化实现。"
        ],
        body_paras[31],
    )
    set_section_paragraphs(
        body,
        body_paras[31],
        body_paras[32],
        [
            "从研究背景看，现代Web业务早已不局限于传统HTTP/1.1场景。HTTP/2通过多路复用和头部压缩提升了连接利用率，HTTP/3则建立在QUIC之上，进一步改变了传输层与会话层的处理方式。对于安全设备来说，这意味着如果仍停留在单一文本报文处理思路上，就容易出现协议覆盖不足、检测逻辑割裂和规则复用困难的问题。尤其在真实部署环境中，安全系统还需要同时处理TCP、UDP、TLS、HTTP/2与HTTP/3等多种流量入口，这对系统设计提出了更高要求。",
            "从理论意义看，L4/L7协同防护体系为现代轻量级WAF设计提供了一种较有代表性的思路。L4适合在连接建立早期根据源地址、端口、连接频率和会话状态执行快速过滤，L7则适合围绕HTTP方法、URI、Header、Body和代理元数据开展细粒度规则判定。将二者协同起来，可以形成“先粗筛、后精判”的分层模式，这不仅有助于降低上层协议解析负担，也有利于在系统架构层面划清不同模块的责任边界。",
            "从工程意义看，一个真正可用的WAF不应只具备拦截能力，还应具备配置管理、规则维护、站点与证书治理、安全事件审计以及控制台展示等功能。特别是在毕业设计语境下，单一算法实验或局部功能演示往往难以体现系统设计与实现能力，而一个同时覆盖数据面、控制面、持久化和联动能力的项目，更能反映需求分析、模块划分、编码实现、测试验证和文档总结的综合训练价值。",
            "从应用意义看，基于Rust实现一套可本地运行的WAF原型，可以验证Rust在异步网络编程、多协议接入、规则引擎组织和运维控制台开发中的适用性，也能为教学场景提供更贴近真实工程的案例。它既可以作为理解现代Web边界安全体系的实践样本，也能够为后续继续扩展动态热更新、性能压测、策略联动和更复杂语义检测奠定基础。"
        ],
        body_paras[35],
    )
    set_section_paragraphs(
        body,
        body_paras[35],
        body_paras[36],
        [
            "国外关于WAF的研究和工程实践起步较早。OWASP持续维护了Web Application Firewall、ModSecurity、Core Rule Set（CRS）以及WAFEC等项目资料，对WAF的定义、评价维度、规则组织方式和开源生态形成了较系统的总结。这些资料普遍认为，成熟的WAF不仅要有基本的阻断能力，还应在规则可维护性、误报控制、部署兼容性、日志审计与可观测性方面具备工程化支撑。由此可见，现代WAF研究已经逐渐从“能否识别攻击”走向“能否稳定运行并长期维护”。",
            "在协议与网关层面，HTTP/2、HTTP/3、QUIC、TLS 1.3和HTTP语义相关RFC构成了现代Web防护系统的重要基础文献。HTTP/2强调多路复用和帧化处理，HTTP/3与QUIC则重新定义了部分连接管理方式，这些变化都直接影响WAF对请求接入、上下文抽象和流量治理的实现方式。相关标准文档的共同启示在于，安全系统不能只面向某一种旧协议做检测，而要先完成协议适配，再将请求统一抽象为可复用的结构化对象。",
            "在攻击防护与规则体系方面，国外大量研究和开源实践围绕正则规则、签名匹配、异常评分、可疑请求拦截和阻断页面返回等策略展开。ModSecurity及其规则生态之所以被广泛引用，很大程度上是因为它形成了较规范的规则组织方式和持续演化的社区经验。虽然本文课题并不直接复制这些大型组件的全部实现，但其思想对规则分层、动作设计以及控制面管理具有直接借鉴意义。",
            "在编程语言与系统实现方向，Klabnik、Nichols以及Blandy等人的Rust著作系统阐述了所有权模型、并发安全和零成本抽象思想。结合近年的工程实践可以看到，Rust越来越多地被用于构建网络代理、服务网格组件、边缘中间件和安全基础设施。这说明国外研究已经逐步接受Rust作为现代系统软件的重要候选语言，特别是在需要性能和可靠性并重的场景中，Rust显示出明显优势。",
            "国内关于WAF的研究多集中在Web攻击检测、代理网关设计、规则匹配优化、日志审计和部署实践等方面，部分成果更强调与国产环境、教学实验系统或企业边界防护需求的结合。从公开材料看，国内研究在问题背景和应用场景上往往更贴近本土需求，但在“从接入监听、规则匹配、数据库持久化到控制台运维”的一体化系统总结方面仍有进一步深化空间。尤其是围绕Rust语言构建轻量级、可视化、多协议WAF的公开毕业设计型成果仍不多见。",
            "综合国内外研究现状可以发现，当前WAF研究已经从单点能力转向系统性能力建设。一方面，研究者越来越重视协议适配、代理治理和部署可维护性；另一方面，工程实践也越来越强调运行指标、配置归档、事件审计和与外部安全平台联动。本文课题正是在这一背景下展开，其目标不是重复已有大型产品，而是在毕业设计范围内实现一套结构清晰、功能完整、真实可运行的Rust WAF原型，并对其设计过程进行系统归纳。",
            "值得注意的是，很多公开研究虽然会提到多协议支持、规则管理和控制台展示，但真正把这些能力收束进同一套数据模型和统一架构中的并不多。有些项目偏重规则引擎，有些项目偏重代理转发，还有些工作更重视攻击分类而忽略了运维视角。本文课题希望通过一体化实现，把接入、判定、存储、展示和联动这些能力尽量放进同一项目中完成验证。"
        ],
        body_paras[39],
    )
    set_section_paragraphs(
        body,
        body_paras[39],
        body_paras[44],
        [
            "通过对上述文献的梳理可以发现，现有研究为本课题提供了几类直接启发。第一，OWASP、ModSecurity和CRS相关资料为WAF的功能边界、规则组织、运维要求和评估维度提供了可借鉴的基本框架，使本文能够在规则、防护、审计和可维护性等方面建立较明确的系统目标。第二，HTTP/2、HTTP/3、QUIC和TLS 1.3等标准文档提醒我们，现代Web防护系统必须将多协议接入与统一请求抽象视为基础问题，而不能将其当作后期附加功能。",
            "第三，Bloom Filter等数据结构理论说明，工程化防护系统需要在性能和准确性之间做权衡。对WAF而言，快速预筛、黑名单命中预判、连接级粗过滤等场景，往往更关注在有限资源下尽早缩小可疑范围，而最终裁决仍需要依赖更完整的规则匹配和上下文判断。这也说明一个真正可用的安全系统往往是多层策略的组合，而不是单一算法的直接套用。",
            "第四，Rust相关文献和工程实践为系统实现语言的选择提供了充分依据。对于需要长时间稳定运行、同时处理大量连接和请求的边界服务，内存安全和并发可靠性具有基础性意义。Rust并不能自动替代所有设计决策，但它确实为构建高可靠网络服务提供了更安全的实现基础。将Rust与WAF课题结合，既具有技术前沿性，也符合“系统设计与实现”类毕业论文对工程实践深度的要求。",
            "不过，现有文献也存在明显不足。许多研究偏重攻击理论或组件介绍，对“如何基于具体语言和框架搭建一套轻量级、可本地运行、具备数据面与控制面的完整系统”讨论不够；一些研究虽然关注WAF规则与检测策略，却较少触及站点与证书管理、事件持久化、前端控制台与配置回滚等工程问题；还有一些工作更像产品功能罗列，而缺乏对模块边界、处理流程和技术取舍的系统总结。",
            "进一步看，现有公开材料中对控制面与数据面的讨论通常并不平衡。很多文献重视检测算法本身，却较少讨论管理接口如何组织、配置项如何持久化、历史参数如何归档以及规则变更如何在控制台中安全呈现。对于真正要落地的系统来说，这些“看起来不够学术”的工程细节反而决定了系统能否长期稳定使用。尤其在教学或中小规模部署场景下，运维人员更需要一套结构清晰、可解释、可回溯的管理界面，而不仅仅是若干零散的检测模块。",
            "此外，安全系统的评估也不应只停留在拦截成功率这一单一维度。一个合格的WAF还需要关注误报率、协议兼容性、站点接入便利性、证书管理难度、事件可追踪性和性能开销等问题。由于本科毕业设计的实验条件有限，本文不以大规模压测数据为主要目标，而更强调系统闭环是否完整、功能路径是否真实可验证、实现边界是否描述清楚。这样的评价思路更符合本课题的研究定位。",
            "基于这些观察，本文认为本课题的价值在于做一层“工程化整合”：在吸收现有研究成果的同时，坚持以真实代码为依据、以系统落地为目标，将L4连接治理、L7规则检测、多协议适配、SQLite持久化与Vue控制台管理结合起来，形成一套既有理论依据又能实际运行的Rust WAF实现方案。这样的工作不仅有助于完成毕业设计，也能为后续继续扩展动态热更新、更多防护动作模板和性能压测提供基础。",
            "从毕业论文写作角度看，文献综述还承担着“收紧边界”的功能。通过回顾已有研究，本文将课题目标明确限定为轻量级、可本地运行、面向多协议与协同防护的WAF原型，而不是泛泛讨论所有Web安全问题。这样的边界控制有助于后续摘要、总体设计、详细实现、测试分析和结论之间保持稳定对应关系。",
            "同时，本文也认识到毕业设计与商业级安全产品之间存在范围差异。前者更强调设计思路是否合理、实现链路是否完整、文档是否真实可对应，后者则更关注长周期运维、海量规则积累和复杂攻防场景。正因为如此，本课题在借鉴现有文献时将坚持“适度实现、如实描述”的原则，不夸大系统能力，也不回避尚未完成的边界，这种写作与实现策略同样是对已有研究的一种理性吸收。",
            "进一步来说，文献综述的价值还在于帮助研究者确定哪些能力属于本课题的核心范围，哪些能力应当被明确划为后续扩展。例如，大规模攻击样本训练、商业规则库长期维护、跨集群部署和复杂运维编排等问题虽然也属于WAF领域的重要内容，但并不适合在本科毕业设计阶段追求面面俱到。相比之下，围绕多协议接入、L4/L7协同、规则动作、事件持久化和控制台管理形成一套闭环实现，更符合本课题当前的目标定位，也更容易在论文中做出真实、清晰、可验证的论证。",
            "综上所述，本文的文献综述并不是为了简单罗列概念，而是试图从已有研究中提炼出适合当前课题的技术路线：以Rust为实现语言，以L4/L7协同为防护主线，以多协议统一抽象为桥梁，以SQLite和控制台管理为工程支撑。这样的组合既回应了现代Web环境的现实需求，也能够在毕业设计范围内形成较完整、较可信的系统实现成果。"
        ],
        body_paras[44],
    )
    ref_anchor = body_paras[49]
    last = ref_anchor
    extra_refs = [
        "[6] Bloom B H. Space/Time Trade-offs in Hash Coding with Allowable Errors[J]. Communications of the ACM, 1970, 13(7): 422-426.",
        "[7] Thomson M, Benfield C. HTTP/2[S/OL]. RFC 9113, 2022.",
        "[8] Bishop M. HTTP/3[S/OL]. RFC 9114, 2022.",
        "[9] Iyengar J, Thomson M. QUIC: A UDP-Based Multiplexed and Secure Transport[S/OL]. RFC 9000, 2021.",
        "[10] Owens M. The Definitive Guide to SQLite[M]. Berkeley: Apress, 2006.",
        "[11] Stuttard D, Pinto M. The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws[M]. 2nd ed. Indianapolis: Wiley, 2011.",
    ]
    for ref in extra_refs:
        last = clone_paragraph(body, ref_anchor, ref, last)
    set_paragraph_text(body.findall("./w:p", ns)[-1], "")

    replace_zip_entry(output, "word/document.xml", ET.tostring(root, encoding="utf-8", xml_declaration=True))


def build_proposal(template: Path, output: Path) -> None:
    shutil.copyfile(template, output)
    with zipfile.ZipFile(output, "r") as zf:
        root = ET.fromstring(zf.read("word/document.xml"))

    ns = {"w": W_NS}
    body_paras = root.findall(".//w:body/w:p", ns)
    set_paragraph_text(body_paras[23], "2026年04月14日")

    tables = root.findall(".//w:tbl", ns)
    table = tables[0]
    rows = table.findall("./w:tr", ns)

    def cell_paras(row_idx: int, cell_idx: int) -> list[ET.Element]:
        cell = rows[row_idx].findall("./w:tc", ns)[cell_idx]
        return cell.findall("./w:p", ns)

    set_paragraph_text(cell_paras(0, 1)[0], "基于Rust的L4/L7协同Web防护系统设计与实现")

    # Row 2
    cell2 = rows[2].findall("./w:tc", ns)[0]
    set_cell_section_paragraphs(
        cell2,
        1,
        2,
        5,
        [
            "Web应用防火墙是网络边界安全的重要组成部分，其研究涉及网络协议、系统架构、安全检测和软件工程等多个方向。随着HTTP/2、HTTP/3、QUIC和TLS 1.3等协议逐步普及，传统面向单一HTTP/1.1文本流量的防护思路已难完全适应新的Web环境。因此，围绕L4/L7协同、多协议统一抽象、规则引擎组织和安全事件持久化等问题开展研究，有助于进一步理解现代Web防护系统在架构层面的设计规律。",
            "从学术角度看，L4/L7协同机制能够把连接级快速过滤与请求级语义分析结合起来，为现代轻量级WAF设计提供较清晰的分层思路。它既涉及网络编程与协议处理，也涉及规则表达、判定流程与系统建模，因而具有较好的综合研究价值。Rust语言近年来在系统软件、网络中间件和安全基础设施中的应用不断增加，将Rust与WAF系统设计结合，也有助于从语言特性、异步模型和模块化设计角度，为轻量级安全系统实现提供可借鉴的技术路线。",
            "此外，本课题还能从真实代码实现出发，对需求分析、架构划分、运行机制和模块边界进行系统总结，避免论文只停留在概念层面。这对于提升毕业论文的真实性、完整性和工程说服力具有积极意义。",
            "在当前高校毕业设计评价中，真实性与可验证性越来越受到重视。基于实际项目展开研究，不仅可以减少“纸面设计”和“代码实现”脱节的问题，也有助于在答辩阶段更清楚地说明系统做了什么、没有做什么、为什么这样设计。"
            ,"同时，选题还具有较好的交叉性：它既涉及后端服务与网络协议，又涵盖数据库持久化、前端控制台和运维可视化。这种交叉特征使课题更适合体现计算机科学与技术专业在系统分析、软件实现和工程整合方面的综合训练要求。"
            ,"从培养目标角度看，本课题还有助于锻炼学生面对复杂系统时的取舍能力。一个真实的安全系统往往不可能在有限周期内把所有功能全部做到极致，因此必须在核心能力、扩展能力和展示能力之间做平衡。开题阶段就明确这一点，有助于后续工作安排更加务实，也能减少论文后期因范围失控导致的质量下降。"
            ,"除此之外，课题还要求学生在开发与写作之间保持同步推进，这种训练本身就具有较高价值。只有在实现过程中持续整理思路、补充文档、记录变更，最终才能形成一份内容与系统一致、逻辑与结果对应的毕业论文。"
            ,"除此之外，课题还要求学生在开发与写作之间保持同步推进，这种训练本身就具有较高价值。只有在实现过程中持续整理思路、补充文档、记录变更，最终才能形成一份内容与系统一致、逻辑与结果对应的毕业论文。"
        ],
    )
    set_cell_section_paragraphs(
        cell2,
        5,
        6,
        9,
        [
            "从工程实践角度看，现代Web系统往往面临恶意扫描、SQL注入、跨站脚本、CC攻击、异常连接激增和自动化探测等多种风险。一个具备L4快速过滤、L7细粒度规则判定、站点与证书管理、事件审计和可视化控制台的本地可运行WAF原型，能够较真实地反映实际边界安全系统的核心能力。",
            "对于毕业设计而言，这样的课题既具有明确的应用背景，也能够体现需求分析、系统设计、编码实现、测试验证和文档撰写的完整过程。相比只做局部算法实验或单页前端展示，该课题更能体现学生对后端开发、协议处理、数据库设计和控制台管理的综合能力。",
            "同时，若系统最终能够支持真实站点接入、规则配置和事件留痕，它还可以作为后续答辩展示与课程实践的样例，为理解现代Web边界安全体系提供更直观的支撑。",
            "从就业与能力训练角度看，本课题还覆盖了目前软件工程岗位中较受重视的多项能力，包括异步后端开发、接口设计、前端管理页实现、数据库操作、联调测试以及文档整理等，这使其具有较高的实践训练价值。"
            ,"此外，课题成果具有较好的展示性。答辩时不仅可以展示论文文字结论，还可以结合控制台页面、规则配置流程、事件记录和测试结果说明系统运行情况，这会让研究成果更直观、更容易被理解。"
            ,"如果后续论文与系统继续完善，这套成果还可以作为课程实践、个人作品集或后续深入研究的基础材料。因此，本课题并不是一次性任务，而是具有持续积累价值的工程起点。"
            ,"对于实际教学场景而言，这种能够同时落在代码、页面和文档上的成果，也更容易体现学生是否真正掌握了系统级项目开发流程，而不只是完成了局部实现。"
            ,"在学校答辩语境下，这类既能写成论文、又能现场演示的课题通常更容易形成完整表达：文字部分负责说明思路与依据，系统部分负责说明成果与边界，两者结合能够提高论证的可信度。"
        ],
    )

    # Row 3
    cell3 = rows[3].findall("./w:tc", ns)[0]
    set_cell_section_paragraphs(
        cell3,
        1,
        2,
        4,
        [
            "国外关于WAF的研究和开源实践相对成熟。OWASP长期维护Web Application Firewall、ModSecurity、Core Rule Set和WAFEC等项目资料，形成了关于规则体系、功能边界与评估指标的较完整参考。相关资料普遍表明，成熟WAF不仅强调拦截能力，还强调规则可维护性、误报控制、日志审计和运行可观测性。",
            "随着Web协议演进，HTTP/2、HTTP/3、QUIC和TLS相关RFC也逐渐成为现代防护系统必须面对的技术基础。与此同时，Rust在网络服务和基础设施领域的应用不断扩展，越来越多研究和工程实践开始尝试用Rust重构高可靠服务组件。国内相关研究更多聚焦于攻击检测、代理网关、规则匹配优化和日志审计等方向，但能够同时覆盖多协议接入、L4/L7协同、防护规则、数据库持久化和控制台管理的一体化轻量级实现仍然不多。",
            "这说明本课题既可以借鉴成熟的国外开源经验，也具有结合本地项目实践做工程化整合的空间。",
            "另外，从已有项目演进路径看，控制面能力正在变得越来越重要。规则不再只是静态文本文件，很多系统都开始强调界面化管理、策略预览、模板复用、事件筛选和第三方联动，这些趋势都与本文课题当前的实现方向高度一致。"
            ,"从研究空白角度看，当前较少有开题与论文材料把这些控制面能力与数据面能力同时纳入同一套本科毕业设计叙述之中，这也意味着本课题在写作上需要更强调整体系统视角。"
            ,"同时还可以看到，许多已有研究在评价系统时更强调检测效果，却较少交代配置管理、历史参数兼容、页面操作逻辑和后续维护方式。对于实际系统而言，这些内容并非边缘问题，而是决定系统是否真正可用的重要组成部分。"
            ,"由此可见，本课题并不是简单追随某一项前沿技术，而是尝试把当前研究中的若干关键趋势有机组合起来，形成适合本科毕业设计表达的完整系统方案。"
            ,"从论文写作角度说，这种研究动态的梳理也有助于后续章节安排。它能够帮助我们说明为什么论文会同时讨论网络接入、规则引擎、数据库持久化和控制台页面，而不是把课题理解成单纯的攻击检测实验。"
        ],
    )
    set_cell_section_paragraphs(
        cell3,
        4,
        5,
        None,
        [
            "综合已有研究，本文认为现代WAF系统的发展趋势主要体现在三个方面：第一，防护逻辑正在从单一阻断转向分层协同，即连接级快速治理与请求级语义识别并重；第二，系统实现正在从“能拦截”走向“可管理、可回溯、可观察”，控制台、事件库和联动能力的重要性不断提升；第三，随着协议复杂度提高和工程可靠性要求增强，使用Rust这类更强调安全性与并发能力的语言构建安全基础设施，具有较强可行性。",
            "因此，若能在毕业设计中基于真实项目实现一套Rust WAF原型，并对其架构、流程和测试结果进行总结，就能够较好地回应当前研究中“理论多、完整系统少”的不足。",
            "这一判断也意味着，后续研究不应只关注某一个检测技巧，而应从整体系统视角考虑接入、判定、存储、展示与运维的协同关系。",
            "对于本课题而言，这种见解会直接体现在实现选择上：优先保证系统闭环与模块协同，再在此基础上逐步细化检测能力。"
            ,"换言之，本课题的重点不是构造最复杂的攻击识别算法，而是完成一个结构清晰、功能真实、页面可展示、结果可验证的工程化系统原型。"
            ,"这也要求开题报告在一开始就把研究目标表述清楚：强调系统设计与实现，而不是夸大为全面商用防护平台。只有目标收敛，后续进度安排和论文撰写才能真正落地。"
            ,"这种“先完成系统，再逐步增强能力”的判断，也更符合毕业设计的时间条件和评价逻辑。"
            ,"因此，本课题的见解部分不仅是对外部研究的总结，也是对自身实施边界的声明，用来保证后续开发与写作始终围绕同一目标展开。"
        ],
    )

    # Row 4
    cell4 = rows[4].findall("./w:tc", ns)[0]
    set_cell_section_paragraphs(
        cell4,
        1,
        2,
        3,
        [
            "本课题采用“需求分析—架构设计—系统实现—测试验证—论文总结”的总体思路展开。首先结合WAF相关文献与Web应用防护场景，明确系统应具备的多协议接入、L4/L7协同检测、规则管理、持久化与可视化控制能力；其次依据Rust异步网络编程特点完成模块划分，构建监听接入层、检测决策层、代理治理层、存储层和管理控制层；随后结合项目源码逐步实现核心功能，并通过后端测试、前端测试和构建验证评估系统可运行性；最后对系统效果、不足与优化方向进行总结，完成论文撰写。",
            "研究思路上坚持“以真实代码对应真实论文”，避免出现论文写得很大、系统做得很小的脱节问题。所有章节描述都将尽量落到可验证的模块、接口、页面和测试结果上。",
            "同时，研究过程中会优先保障主功能链路闭环，再补充细节功能与展示内容，以保证在既定时间内完成质量可控的系统原型。"
            ,"这一思路也有助于把开发节奏与论文写作节奏统一起来，使每一阶段的代码成果都能及时沉淀为论文材料，减少后期集中补写带来的风险。"
            ,"研究思路上还会坚持边开发、边记录、边验证的方式。每次完成一个相对独立的模块，都同步梳理其输入输出、页面表现和测试结果，为最终论文的系统结构图、流程图和测试章节提供直接素材。"
            ,"如果某一阶段出现计划偏差，也将及时通过阶段复盘调整重点，把时间优先投入到最能体现课题价值的模块上。"
            ,"这种研究思路的核心是把“系统真实完成度”放在首位。只要关键链路跑通、页面可展示、数据可留痕、论文能对应，就能够形成较完整的毕业设计成果。"
            ,"更进一步地说，这种思路能够把论文写作从“事后总结”转变为“过程沉淀”。每当系统新增一个页面、补上一条接口、修正一个流程，相关内容都可以及时转化为论文素材，使最终文稿不是临时拼凑出来的，而是随着项目推进逐步长成的。"
        ],
    )
    set_cell_section_paragraphs(
        cell4,
        3,
        4,
        6,
        [
            "第一，文献研究法。通过查阅OWASP资料、Rust相关著作、HTTP/2与HTTP/3等协议标准文档以及Web安全基础文献，明确课题的理论基础与技术边界。",
            "第二，系统分析法。对WAF在接入、检测、转发、存储与运维方面的需求进行拆解，形成模块化设计方案，并对模块职责与数据流进行梳理。",
            "第三，工程实现法。以Rust项目为载体，采用Tokio、Axum、SQLite和Vue等技术完成原型系统搭建。",
            "第四，测试验证法。通过自动化测试、功能验证和构建验证检查系统主要功能路径，确保论文结论与实际实现相符。",
            "第五，文档归纳法。将代码演进、论文修改和阶段性成果对应记录，保证开题报告、文献综述与最终论文正文之间前后一致。"
            ,"第六，比较分析法。将项目当前实现与开源WAF常见能力进行对照，明确本课题已完成的部分、暂未涉及的部分以及后续可继续深化的方向。"
            ,"第七，案例展示法。通过选择具有代表性的规则配置、动作模板、事件记录和管理页面，说明系统并非停留在源码层面，而是具备实际操作和展示能力。"
            ,"第八，阶段复盘法。在每个关键阶段结束后，对已完成内容、未完成内容和下一步重点进行小结，以保证研究节奏始终围绕最终答辩目标推进。"
            ,"第九，结果对应法。对论文中的每一项重要描述，尽量都在代码、页面、接口或测试结果中找到对应依据，减少空泛表述。"
            ,"第十，范围控制法。在实现过程中持续评估任务优先级，把有限时间集中投入到最能代表课题价值的功能上，避免功能堆积但完成度下降。"
        ],
    )
    set_cell_section_paragraphs(
        cell4,
        6,
        7,
        None,
        [
            "技术路线拟分为五个环节：一是搭建Rust后端框架，实现TCP、UDP、TLS和HTTP/3等监听接入能力；二是设计L4连接跟踪、速率限制和风险分桶机制，并在此基础上接入L7统一请求抽象与规则引擎；三是使用SQLite保存规则、证书、站点、安全事件和系统设置等数据；四是构建Vue管理控制台，实现规则管理、动作模板管理、站点与证书管理、事件查看和系统设置；五是通过测试与运行结果分析，总结系统的实际效果与后续优化方向。",
            "论文写作阶段将同步记录每次程序变化与文稿修改之间的对应关系，重点保证摘要、总体设计、详细实现、测试分析和结论部分始终与当前代码实现保持一致。",
            "在实施过程中，将优先保证系统主路径真实可运行，再逐步完善控制台交互、文档整理和答辩展示材料，以确保最终成果能够在2026年4月底前完成定稿和答辩准备。",
            "若中途出现非关键功能来不及完全实现的情况，将坚持保留系统主框架、核心检测链路、事件持久化和控制台主页面，保证课题整体完成度与答辩可展示性。"
            ,"在答辩准备阶段，还将同步整理系统架构图、流程图、关键页面截图和测试说明，使论文内容、系统演示与答辩陈述保持一致。"
            ,"通过这样的技术路线安排，可以把有限时间优先投入到最能体现系统设计价值的部分，避免在非关键细节上消耗过多精力。"
            ,"若阶段推进顺利，还会继续补充页面细节打磨、测试说明整理和答辩展示稿完善，以提升最终提交质量。"
            ,"同时，技术路线中会保留必要的弹性空间，用于应对程序迭代后论文同步修改、截图刷新和答辩讲解材料调整等工作，确保最终提交版本前后一致。"
            ,"整体来看，这条技术路线既服务于系统开发，也服务于论文写作和答辩表达。它强调不是把所有工作拆开独立进行，而是让开发、验证、截图、文档和答辩材料在同一条节奏线上同步推进，这样才能在有限时间内交付质量更高、逻辑更完整的毕业设计成果。"
        ],
    )

    # Row 5 schedule
    r5 = cell_paras(5, 0)
    schedule = [
        "2025.11 - 2025.12   确定课题方向，收集WAF、Rust、HTTP多协议和SQLite相关文献，完成开题准备",
        "2026.01            完成总体需求分析，明确系统模块划分与论文框架",
        "2026.02            实现监听接入、L4检测、L7统一请求抽象与基础规则引擎",
        "2026.03            补充网关转发、SQLite持久化、站点证书管理和管理API",
        "2026.03下旬-04上旬 完善Vue控制台、事件审计、联动能力与系统测试，形成论文主体内容",
        "2026.04中旬        根据最新代码继续修订文稿，完善文献综述、开题报告和毕业论文版本",
        "2026.04下旬        完成论文定稿、格式检查、查重准备与答辩材料整理",
    ]
    for idx, item in enumerate(schedule, start=1):
        if idx < len(r5):
            set_paragraph_text(r5[idx], item)
    # clear extra old lines if any
    for idx in range(len(schedule) + 1, len(r5)):
        set_paragraph_text(r5[idx], "")

    # Row 6 refs
    r6 = cell_paras(6, 0)
    refs = [
        "[1] OWASP Foundation. Web Application Firewall[EB/OL]. https://owasp.org/www-community/Web_Application_Firewall.",
        "[2] OWASP Foundation. OWASP ModSecurity[EB/OL]. https://owasp.org/www-project-modsecurity/.",
        "[3] Klabnik S, Nichols C. The Rust Programming Language[M]. San Francisco: No Starch Press, 2019.",
        "[4] Thomson M, Benfield C. HTTP/2[S/OL]. RFC 9113, 2022.",
        "[5] Bishop M. HTTP/3[S/OL]. RFC 9114, 2022.",
        "[6] Owens M. The Definitive Guide to SQLite[M]. Berkeley: Apress, 2006.",
        "[7] Bloom B H. Space/Time Trade-offs in Hash Coding with Allowable Errors[J]. Communications of the ACM, 1970, 13(7): 422-426.",
        "[8] Stuttard D, Pinto M. The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws[M]. 2nd ed. Indianapolis: Wiley, 2011.",
    ]
    template_ref_para = r6[-1]
    parent_tc = rows[6].findall("./w:tc", ns)[0]
    for idx, ref in enumerate(refs, start=1):
        if idx < len(r6):
            set_paragraph_text(r6[idx], ref)
        else:
            clone_paragraph(parent_tc, template_ref_para, ref, parent_tc.findall("./w:p", ns)[-1])

    # Row 7 opinion
    r7 = cell_paras(7, 0)
    set_paragraph_text(r7[1], "该课题面向真实Web安全防护场景，具备明确的工程背景和较好的综合训练价值。课题内容覆盖网络协议、系统架构、后端实现、前端控制台与测试验证，工作量较充足，技术路线基本可行。")
    set_paragraph_text(r7[2], "同意开题。")

    replace_zip_entry(output, "word/document.xml", ET.tostring(root, encoding="utf-8", xml_declaration=True))


def main() -> None:
    base = Path(__file__).resolve().parent
    build_literature_review(
        base / "02  文献综述（2000字左右）_参考.docx",
        base / "02  文献综述（2000字左右）.docx",
    )
    build_proposal(
        base / "03  开题报告_参考.docx",
        base / "03  开题报告.docx",
    )


if __name__ == "__main__":
    main()
