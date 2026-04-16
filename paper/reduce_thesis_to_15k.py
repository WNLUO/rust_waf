from __future__ import annotations

from pathlib import Path
from shutil import copy2
from zipfile import ZIP_DEFLATED, ZipFile

from lxml import etree


DOCX = Path(__file__).with_name("基于 Rust 的 L4∕L7 协同 Web 防护系统设计与实现.docx")
BACKUP = DOCX.with_name(DOCX.stem + "_before_reduce_to_15k.docx")
NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


REPLACEMENTS = [
    ("摘  要：随着互联网应用体系", "摘  要：针对现代Web系统面临的异常连接、应用层攻击和多协议接入问题，本文设计并实现了一套基于Rust的L4/L7协同Web防护系统。系统以后端防护引擎为核心，结合四层连接限流、七层统一请求抽象、规则裁决、事件持久化和前端控制台，实现了连接级快速治理与请求级精细检测的组合。测试结果表明，系统能够完成多协议接入、规则命中、阻断响应、事件记录和可视化管理等主要功能，具备轻量部署和教学实践价值。"),
    ("Abstract:As Web applications increasingly", "Abstract: This thesis designs and implements a Rust-based L4/L7 collaborative Web protection system. The system combines connection-level filtering, unified HTTP request abstraction, rule-based inspection, event persistence and a Vue management console. Tests show that the prototype can support multi-protocol access, rule decisions, blocking responses, event logging and basic operation management."),
    ("在云原生、微服务与前后端分离架构广泛应用", "随着云原生、微服务和前后端分离架构的普及，Web系统逐渐成为业务访问和数据交互的核心入口。传统边界防火墙或静态规则列表难以同时兼顾连接级治理、应用层语义识别和运维可观测性，因此有必要设计一种轻量化、可本地部署的协同式Web防护系统。"),
    ("基于上述背景，围绕一个实际实现的Rust项目", "本文围绕一个真实Rust项目展开，采用文献研究、系统分析、原型实现和测试验证相结合的方法，总结L4/L7协同防护、统一请求抽象、规则匹配、持久化审计和控制台管理的实现过程。"),
    ("国外针对网络应用防火墙的研究和工程实践起步较早", "国内外关于WAF、HTTP/2、HTTP/3、QUIC、TLS、Bloom Filter和Rust异步并发的研究，为本文提供了规则检测、协议适配和安全实现依据[1][4][6][7][8][9]。现有开源WAF多采用“引擎+规则集”模式，商业网关则强调云侧托管和集中运维；相比之下，本文更关注本地轻量部署、多协议接入和控制面闭环。"),
    ("本文的研究对象是一套基于Rust实现", "本文研究对象是一套基于Rust实现的L4/L7协同Web防护系统。系统后端以Tokio和Axum为基础，使用SQLite保存配置、事件和画像数据，前端采用Vue构建控制台。研究重点包括多协议接入、四层限流、七层统一请求抽象、规则引擎、站点证书管理和测试验证。"),
    ("全文共分为六章", "全文共六章：第一章说明研究背景与内容；第二章介绍相关技术；第三章分析需求与总体架构；第四章阐述系统实现和核心算法；第五章给出测试结果；第六章总结全文。"),
    ("Rust是一种面向系统编程的现代语言", "Rust强调内存安全、零成本抽象和高性能并发，适合实现长期运行的边界网关服务[4][5]。本文项目采用Tokio异步运行时处理TCP、UDP、TLS和HTTP/3监听任务，并通过并发限制避免资源失控。"),
    ("四层防护主要关注源IP", "四层防护关注源地址、端口、协议、连接频率和连接状态，适合快速限流和初步拦截；七层防护关注HTTP方法、URI、头部、请求体和业务语义，适合规则检测和行为识别。二者形成“先粗筛、后精判”的协同关系。"),
    ("为避免概念混用", "本文按GB/T 25069-2022将威胁理解为可能造成损害的潜在因素，将脆弱性理解为可被利用的弱点，将风险理解为威胁利用脆弱性后产生影响的可能性及后果组合[35]。"),
    ("传统网络应用防火墙大多直接面向HTTP/1.1", "HTTP/1.1、HTTP/2和HTTP/3在传输方式、头部组织和连接管理上存在差异[7][8][9]。系统通过UnifiedHttpRequest统一方法、URI、头部、请求体、客户端地址和协议元数据，使规则引擎面对稳定的数据结构。"),
    ("在检测策略方面，规则引擎", "规则引擎是WAF的核心能力。本文系统将规则划分为四层和七层两类，支持allow、block、alert和respond动作，并通过正则预编译和事件记录实现可配置裁决。Bloom Filter用于快速预筛，其误判概率由p=(1-e-kn/m)k表示，适合作为黑名单或特征集合的前置判断[6]。"),
    ("工程化网络应用防火墙不仅要具备拦截能力", "工程化WAF还需要持久化、审计和控制面支持。本文采用SQLite保存安全事件、阻断IP、规则、证书、站点、行为画像和联动状态，使系统在无外部数据库的条件下仍可完成配置管理与事件追溯[13]。"),
    ("从个人信息和日志数据处理角度看", "日志和画像数据涉及来源IP、请求路径、浏览器指纹等信息，因此系统应遵循最小必要、权限受控和可追溯原则；相关设计可参考个人信息保护法、GB/T 35273-2020及等级保护要求[31][32][36]。"),
    ("在控制面方面，系统后端通过Axum", "控制面由Axum API和Vue控制台组成，负责规则、证书、站点、事件、画像和联动配置管理，实现数据面与管理面的基本分离[20][21]。"),
    ("本文系统定位为一套轻量级", "本文系统定位为轻量级本地Web防护网关，目标是实现多协议接入、L4/L7协同检测、规则管理、事件审计、站点证书维护和可视化运维。"),
    ("在定级与保护对象理解上", "从规范依据看，网络安全法、数据安全法和个人信息保护法要求网络运营者建立安全保护、数据安全管理和个人信息保护措施[29][30][31]；GB/T 22239、GB/T 28448、GB/T 22240、GB/T 20271和GB/T 20269则为等级保护、测评、定级和安全管理提供参考[32][33][34][37][38]。"),
    ("从业务功能角度看", "功能需求包括接入监听、四层限流、七层规则检测、代理转发、事件持久化、站点证书管理、控制台配置和SafeLine联动。非功能需求包括安全性、并发性、可维护性、可观测性和可扩展性。"),
    ("系统采用“监听接入层", "系统采用监听接入层、检测决策层、代理治理层、持久化层和管理控制层五层结构。监听层处理多协议连接，检测层完成L4/L7裁决，代理层负责站点与上游，持久化层保存配置和事件，控制层提供可视化管理。"),
    ("为支撑控制台、规则引擎", "SQLite数据库主要保存安全事件、阻断IP、规则、应用配置、站点证书、行为画像、AI审计和SafeLine同步状态。其作用可概括为“配置中心、审计中心、画像仓和联动缓存”。"),
    ("系统入口由Rust二进制程序启动", "系统启动时加载配置、初始化WafContext，并装配四层检测器、七层检测器、规则引擎、SQLite存储、网关运行时和实时观测组件。随后分别启动TCP、UDP、TLS和HTTP/3监听任务，并通过后台任务维护健康检查、同步和指标推送。"),
    ("四层检测模块由四层检测器", "四层模块由L4Inspector、ConnectionTracker、ConnectionLimiter和L4BehaviorEngine组成。其流程是构造数据包信息、执行连接跟踪与速率限制、检查阻断表和规则，并在必要时输出拒绝、告警或运行态限流策略。"),
    ("在此基础上，四层行为引擎", "四层行为引擎以(peer_ip, authority, alpn, transport)为分桶键统计连接、反馈和生命周期特征，并根据风险等级导出连接预算、延迟或拒绝策略。"),
    ("七层实现的关键在于先完成协议归一化", "七层处理先完成协议归一化，再执行行为检测、CC检测和规则裁决。HTTP/1.1、HTTP/2和HTTP/3请求都会被转换为UnifiedHttpRequest，从而使规则引擎能够以统一文本和元数据进行匹配。"),
    ("在统一请求对象生成后", "规则引擎会预编译启用规则，按四层或七层文本进行匹配，并根据动作返回放行、阻断、告警或自定义响应。自定义响应可来自规则内模板或预置动作模板。"),
    ("除了检测功能外", "网关模块负责站点匹配、证书选择、上游健康检查和请求转发。系统根据Host、监听端口和证书配置选择目标站点，并在转发时补充请求ID和转发头，便于后端追踪。"),
    ("系统的持久化设计采用单写入队列", "持久化层采用SQLite与单写入队列组合，异步保存安全事件和阻断记录，同时维护规则、站点、证书、画像和同步状态，降低请求链路上的IO压力。"),
    ("系统管理面由Axum接口和Vue控制台组成", "管理API和前端控制台用于查看运行状态、配置规则、维护动作模板、管理站点证书、查看事件画像和执行联动同步。控制台不直接参与安全裁决，而是提供策略治理和审计入口。"),
    ("通过前述前端控制台和后端防护链路分析", "系统核心算法可概括为“快速准入、风险分层、语义裁决、反馈观测”。四层算法先降低无效连接消耗，七层算法识别请求行为，规则引擎执行精确裁决，持久化与控制台负责解释和回溯结果。"),
    ("为使算法表达更严谨", "本文将核心裁决抽象为五元组A=(I,S,F,T,O)：I为连接元数据、统一请求对象和规则配置；S为计数窗口、风险分桶和阻断表；F为特征提取函数；T为阈值集合；O为放行、告警、挑战、延迟、阻断和自定义响应。"),
    ("四层连接限流算法对应代码中的", "四层连接限流以源IP为键维护一秒计数窗口和阻断表。当连接数超过阈值时，系统拒绝请求并短期封禁该地址。"),
    ("单纯的一秒级限流只能处理明显", "四层行为分桶算法用于处理慢速占用、代理转发和多协议入口等复杂场景。系统综合连接数、请求数、反馈次数和连接生命周期计算风险分值。"),
    ("在分值更新公式", "公式中Sraw为当前窗口原始风险，Sewma为历史平滑风险，Snext为输出风险，α为平滑系数。α越大越平稳，α越小越敏感，本文取0.7与0.3作为稳定性和响应速度的折中。"),
    ("七层CC防护算法对应", "七层CC算法从统一请求对象中提取IP、Host、方法、路由和挑战状态，并在多个维度维护滑动窗口。算法通过加权等效请求数判断是否挑战或阻断。"),
    ("七层行为画像算法对应", "七层行为画像算法以身份标识为键记录访问序列，计算重复访问、路由集中、请求间隔抖动和挑战次数等特征，并输出延迟、挑战或阻断建议。"),
    ("规则引擎对应 RuleEngine", "规则引擎在启动或规则更新时预编译启用规则，运行时分别对数据包摘要和统一请求文本进行匹配，并根据动作类型输出InspectionResult。"),
    ("系统测试主要采用单元测试", "系统测试采用后端单元测试、前端脚本测试、构建验证和功能链路分析。测试重点覆盖配置校验、规则引擎、四层限流、HTTP/2与HTTP/3处理、SQLite持久化、管理鉴权和SafeLine同步。"),
    ("论文撰写期间，项目完成了", "测试结果显示，后端cargo test共237项通过，前端Vitest共2项通过，生产构建成功。系统能够完成连接接入、分层检测、规则命中、动作响应、事件记录和控制台展示。"),
    ("从实现效果看", "总体看，系统已经形成多协议接入、L4/L7协同检测、规则裁决、代理治理、持久化审计和控制台运维的闭环，达到了本科毕业设计原型验证要求。"),
    ("尽管系统已经具备较好的完整性", "系统不足主要包括：复杂语义检测仍较浅，HTTP/3真实客户端场景验证不足，部分配置需要重启后生效，长期压力测试和热更新机制仍需完善。"),
    ("本文围绕“基于Rust的L4/L7", "本文围绕基于Rust的L4/L7协同Web防护系统，完成了需求分析、架构设计、核心模块实现和测试验证。系统以Rust异步网络能力为基础，将四层快速治理、七层语义检测、规则裁决、事件持久化和可视化控制台整合为轻量级安全网关原型。"),
    ("研究表明，该系统已经实现了", "测试表明，系统主要功能链路能够正常运行，具有一定工程完整性和实践价值。后续可继续加强深层语义检测、HTTP/3实测、策略热更新和长期运行评估，使其从教学原型逐步接近真实运维场景。"),
]

REMOVE_STARTS = [
    "在实现过程中，系统强调",
    "The implementation treats the system",
    "网络应用防火墙是介于客户端",
    "另一方面，近年来HTTP协议栈",
    "本文的研究方法主要包括四类",
    "从文献依据看，网络应用防火墙",
    "从我国网络安全治理框架看",
    "在协议支持方面，HTTP/2",
    "在数据结构与检测效率方面",
    "在系统实现语言方面",
    "综合已有资料可以看出",
    "应用安全验证和测试资料",
    "国内相关研究更多聚焦",
    "从研究问题角度看",
    "在方法层面，本文不是",
    "围绕上述研究问题",
    "结合国家标准，本文将",
    "围绕上述内容，本文拟达到",
    "这种分层思想与现有网络安全工程实践",
    "本文系统将四层检测前置",
    "该表达式对应系统中连接限流器",
    "从协议标准角度看",
    "HTTP/3相关生态还包含",
    "为解决这一问题，本文系统引入",
    "从相关安全实践看",
    "为了提升部分场景下的查询效率",
    "其中，m表示位数组长度",
    "需要强调的是，Bloom Filter",
    "在云原生和微服务环境中",
    "为使这些目标落到可实现",
    "结合项目当前代码统计",
    "除功能需求外，系统还需要",
    "除功能需求外，系统还应满足",
    "这种结构的优点在于",
    "从结构上看，该数据库",
    "引擎启动后，会根据配置",
    "除实时请求链路外，系统还在启动后",
    "从部署视角看，当前系统更接近",
    "连接跟踪器负责统计源地址",
    "随着自适应防护逐步成为主入口",
    "值得注意的是，四层检测结果",
    "在最新实现中，动作模板进一步",
    "除规则本体外，系统还形成了",
    "在代理前处理阶段，系统还会自动",
    "在七层配置管理上，当前实现同样",
    "在最新网关实现中，主机头治理",
    "在代理转发前，系统会调用",
    "网关运行时还负责站点",
    "在安全审计之外，SQLite",
    "除基础规则表外，系统还通过",
    "针对浏览器指纹诱导模板",
    "在第三方联动方面，系统集成",
    "从论文视角来看，这一部分",
    "从安全开发实践看，控制台本身",
    "前端控制台的设计重点",
    "需要指出的是，当前系统仍有",
    "从执行顺序看，核心算法",
    "从学术表述上看，本文所谓",
    "分值计算完成后，系统将连接群",
    "为降低正常页面加载中静态资源",
    "在评分策略上，系统为重复访问",
    "从整体流程看，系统的后端算法",
    "从功能验证结果看",
    "规则动作实验表明",
    "系统的主要优势在于",
    "后续若将本系统用于更正式",
    "从后续研究角度看",
    "再次，部分配置更新仍需重启",
]


def para_text(p: etree._Element) -> str:
    return "".join(p.xpath(".//w:t/text()", namespaces=NS)).strip()


def set_para_text(p: etree._Element, text: str) -> None:
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


def main() -> None:
    if not BACKUP.exists():
        copy2(DOCX, BACKUP)

    with ZipFile(DOCX, "r") as zin:
        entries = {name: zin.read(name) for name in zin.namelist()}

    doc = etree.fromstring(entries["word/document.xml"])
    body = doc.find("w:body", NS)
    if body is None:
        raise RuntimeError("document body not found")

    removed = 0
    replaced = 0
    for p in list(body.findall("w:p", NS)):
        text = para_text(p)
        if not text:
            continue
        if any(text.startswith(s) for s in REMOVE_STARTS):
            body.remove(p)
            removed += 1
            continue
        for start, new_text in REPLACEMENTS:
            if text.startswith(start):
                set_para_text(p, new_text)
                replaced += 1
                break

    sects = doc.xpath("//w:sectPr", namespaces=NS)
    if sects:
        sect = sects[-1]
        pg = sect.find("w:pgNumType", NS)
        if pg is None:
            pg = etree.SubElement(sect, W + "pgNumType")
        pg.set(W + "start", "1")

    entries["word/document.xml"] = etree.tostring(doc, xml_declaration=True, encoding="UTF-8", standalone="yes")
    with ZipFile(DOCX, "w", ZIP_DEFLATED) as zout:
        for name, data in entries.items():
            zout.writestr(name, data)

    print(f"backup={BACKUP.name}")
    print(f"removed={removed}")
    print(f"replaced={replaced}")


if __name__ == "__main__":
    main()
