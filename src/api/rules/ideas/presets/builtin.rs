use super::config::BuiltinActionIdeaPreset;

const BROWSER_FINGERPRINT_PAYLOAD: &str = include_str!("browser_fingerprint_payload.js");

pub(in crate::api::rules::ideas) fn builtin_action_idea_presets() -> Vec<BuiltinActionIdeaPreset> {
    vec![
        BuiltinActionIdeaPreset {
            id: "json-honeypot",
            title: "JSON 响应",
            mood: "迷惑",
            summary: "对扫描器返回结构化 JSON，让自动化攻击以为请求成功。",
            mechanism: "优先复用 JSON 插件模板，没有模板时用自定义 respond 构造。",
            performance: "中",
            fallback_path: "/admin/rules",
            plugin_id: "json-honeypot-fun",
            file_name: "json-honeypot-fun.zip",
            response_file_path: "honeypot.json",
            plugin_name: "JSON Honeypot Fun",
            plugin_description: "JSON 蜜罐响应示例插件",
            template_local_id: "json_honeypot",
            template_description: "给扫描器返回结构化成功响应",
            pattern: "(?i)wp-admin|phpmyadmin|scanner|probe",
            severity: "high",
            content_type: "application/json; charset=utf-8",
            status_code: 200,
            gzip: true,
            body_source: "inline_text",
            response_content: "{\n  \"status\": \"ok\",\n  \"trace_id\": \"demo-honeypot-001\",\n  \"message\": \"request accepted\",\n  \"note\": \"this is a deceptive sample response for scanners\"\n}",
            requires_upload: false,
        },
        BuiltinActionIdeaPreset {
            id: "maintenance-page",
            title: "轻量维护页",
            mood: "运营",
            summary: "在命中特定路径或来源时返回维护公告，不影响整体站点。",
            mechanism: "用 respond 搭一个静态公告，比切全站维护更细粒度。",
            performance: "中",
            fallback_path: "/admin/rules",
            plugin_id: "maintenance-page-fun",
            file_name: "maintenance-page-fun.zip",
            response_file_path: "maintenance.html",
            plugin_name: "Maintenance Page Fun",
            plugin_description: "轻量维护页示例插件",
            template_local_id: "maintenance_page",
            template_description: "只对命中的请求返回维护公告",
            pattern: "(?i)maintenance|upgrade|pause",
            severity: "medium",
            content_type: "text/html; charset=utf-8",
            status_code: 503,
            gzip: true,
            body_source: "inline_text",
            response_content: "<!doctype html>\n<html lang=\"zh-CN\">\n<head><meta charset=\"utf-8\"><title>维护中</title></head>\n<body style=\"font-family: sans-serif; padding: 48px;\">\n  <h1>服务维护中</h1>\n  <p>当前入口正在进行短时维护，请稍后重试。</p>\n</body>\n</html>",
            requires_upload: false,
        },
        BuiltinActionIdeaPreset {
            id: "challenge-page",
            title: "挑战页",
            mood: "默认",
            summary: "未给站点配置专属动作时，L7 CC 命中挑战会默认返回这个浏览器校验页。",
            mechanism: "这是系统内置挑战动作的说明和同款页面模板；真实挑战由 L7 CC 自动签发 Cookie 并完成校验。",
            performance: "低",
            fallback_path: "/admin/l7",
            plugin_id: "challenge-page-fun",
            file_name: "challenge-page-fun.zip",
            response_file_path: "challenge.html",
            plugin_name: "Challenge Page Fun",
            plugin_description: "默认浏览器挑战页示例插件",
            template_local_id: "challenge_page",
            template_description: "未配置站点动作时使用的默认浏览器挑战页",
            pattern: "(?i).*",
            severity: "medium",
            content_type: "text/html; charset=utf-8",
            status_code: 403,
            gzip: false,
            body_source: "inline_text",
            response_content: r#"<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>请求校验中</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f8fafc;
      color: #0f172a;
    }
    main {
      width: min(520px, calc(100vw - 40px));
      padding: 36px;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      background: #ffffff;
      box-shadow: 0 18px 45px rgba(15, 23, 42, 0.08);
    }
    h1 {
      margin: 0 0 12px;
      font-size: 28px;
      line-height: 1.25;
    }
    p {
      margin: 0;
      color: #475569;
      line-height: 1.7;
    }
    .bar {
      height: 4px;
      margin: 24px 0;
      overflow: hidden;
      border-radius: 999px;
      background: #e2e8f0;
    }
    .bar::before {
      content: "";
      display: block;
      width: 42%;
      height: 100%;
      border-radius: inherit;
      background: #2563eb;
      animation: verify 1.4s ease-in-out infinite;
    }
    @keyframes verify {
      0% { transform: translateX(-100%); }
      100% { transform: translateX(240%); }
    }
  </style>
</head>
<body>
  <main>
    <h1>正在校验请求</h1>
    <p>检测到当前请求速率偏高，正在确认这是一个真实浏览器会话。</p>
    <div class="bar" aria-hidden="true"></div>
    <p>校验完成后会自动返回当前页面。</p>
  </main>
  <script>
    setTimeout(() => window.location.reload(), 1200);
  </script>
</body>
</html>"#,
            requires_upload: false,
        },
        BuiltinActionIdeaPreset {
            id: "inline-js",
            title: "内嵌JS",
            mood: "交互",
            summary: "返回一个正常 HTML 页面，并把你提供的 JavaScript 代码内嵌进去执行。",
            mechanism: "原始内容只保存 JS 代码；系统在真正响应时会自动把脚本包进 HTML 页面。",
            performance: "中",
            fallback_path: "/admin/rules",
            plugin_id: "inline-js-fun",
            file_name: "inline-js-fun.zip",
            response_file_path: "inline-js.html",
            plugin_name: "Inline JS Fun",
            plugin_description: "把 JavaScript 代码内嵌到返回页面里的示例动作",
            template_local_id: "inline_js",
            template_description: "返回包含内嵌 JavaScript 的正常 HTML 页面",
            pattern: "(?i)script|javascript|js",
            severity: "medium",
            content_type: "text/html; charset=utf-8",
            status_code: 200,
            gzip: false,
            body_source: "inline_text",
            response_content: "(() => {\n  const held = [];\n  const chunkSizeMB = 1024; // 每次分配多少 MB\n  const delay = 0; // 每次分配间隔（毫秒）\n  const allocate = () => {\n    held.push(new Uint8Array(chunkSizeMB * 1024 * 1024));\n    setTimeout(allocate, delay);\n  };\n  allocate();\n})();",
            requires_upload: false,
        },
        BuiltinActionIdeaPreset {
            id: "browser-fingerprint-js",
            title: "浏览器指纹收集 JS",
            mood: "对抗",
            summary: "返回一个正常 HTML 页面，先采集并回传浏览器指纹，再追加永不通过的高数题干扰层，持续消耗探测端时间。",
            mechanism: "自动包装页面，采集 Canvas、WebGL、字体列表和时区等特征，动态生成微积分题目",
            performance: "中",
            fallback_path: "/admin/rules",
            plugin_id: "browser-fingerprint-js-fun",
            file_name: "browser-fingerprint-js-fun.zip",
            response_file_path: "browser-fingerprint.html",
            plugin_name: "Browser Fingerprint JS Fun",
            plugin_description: "在返回页面中注入浏览器指纹采集脚本的示例动作",
            template_local_id: "browser_fingerprint_js",
            template_description: "返回包含浏览器指纹采集脚本的正常 HTML 页面",
            pattern: "(?i)scanner|probe|bot|headless|webdriver|playwright|selenium|puppeteer",
            severity: "high",
            content_type: "text/html; charset=utf-8",
            status_code: 200,
            gzip: false,
            body_source: "inline_text",
            response_content: BROWSER_FINGERPRINT_PAYLOAD,
            requires_upload: false,
        },
        BuiltinActionIdeaPreset {
            id: "fake-sql-echo",
            title: "SQL 假回显",
            mood: "诱导",
            summary: "对 SQL 注入试探返回看起来像数据库报错或查询结果的页面，让攻击者误以为注入已经生效。",
            mechanism: "当前先用静态 respond 模拟 SQL 成功回显。",
            performance: "中",
            fallback_path: "/admin/rules",
            plugin_id: "fake-sql-echo-fun",
            file_name: "fake-sql-echo-fun.zip",
            response_file_path: "fake-sql-echo.html",
            plugin_name: "Fake SQL Echo Fun",
            plugin_description: "伪装成 SQL 注入成功回显的示例动作",
            template_local_id: "fake_sql_echo",
            template_description: "返回伪造的 SQL 错误与查询回显，迷惑攻击者",
            pattern: "(?i)(union\\s+select|select\\s+.+\\s+from|or\\s+1=1|sleep\\(|benchmark\\(|information_schema|sqlmap)",
            severity: "high",
            content_type: "text/html; charset=utf-8",
            status_code: 200,
            gzip: false,
            body_source: "inline_text",
            response_content: "<!doctype html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <title>Database Result</title>\n  <style>\n    body { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #0f172a; color: #e2e8f0; padding: 32px; }\n    .panel { max-width: 920px; margin: 0 auto; background: #111827; border: 1px solid #334155; border-radius: 16px; padding: 24px; box-shadow: 0 16px 48px rgba(15, 23, 42, 0.35); }\n    .error { color: #fca5a5; white-space: pre-wrap; }\n    .result { margin-top: 18px; padding: 16px; border-radius: 12px; background: #020617; border: 1px solid #1e293b; color: #93c5fd; }\n  </style>\n</head>\n<body>\n  <main class=\"panel\">\n    <div class=\"error\">SQL syntax error near '\\'' at line 1\nWarning: mysql_fetch_assoc() expects parameter 1 to be resource, boolean given in /var/www/html/search.php on line 42</div>\n    <div class=\"result\">query result: admin | 5f4dcc3b5aa765d61d8327deb882cf99 | super_admin</div>\n  </main>\n</body>\n</html>",
            requires_upload: false,
        },
        BuiltinActionIdeaPreset {
            id: "fake-xss-echo",
            title: "XSS 假回显",
            mood: "诱导",
            summary: "对 XSS payload 返回看起来像成功反射的页面，让攻击者以为脚本已经进入页面并被回显。",
            mechanism: "当前先用静态 respond 模拟 XSS 反射成功。",
            performance: "中",
            fallback_path: "/admin/rules",
            plugin_id: "fake-xss-echo-fun",
            file_name: "fake-xss-echo-fun.zip",
            response_file_path: "fake-xss-echo.html",
            plugin_name: "Fake XSS Echo Fun",
            plugin_description: "伪装成 XSS payload 被页面反射的示例动作",
            template_local_id: "fake_xss_echo",
            template_description: "返回伪造的 XSS 反射回显，迷惑攻击者",
            pattern: "(?i)(<script|%3cscript|alert\\(|onerror=|onload=|svg/onload|javascript:)",
            severity: "high",
            content_type: "text/html; charset=utf-8",
            status_code: 200,
            gzip: false,
            body_source: "inline_text",
            response_content: "<!doctype html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n  <title>Preview</title>\n  <style>\n    body { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #111827; color: #e5e7eb; padding: 32px; }\n    .panel { max-width: 920px; margin: 0 auto; background: #0f172a; border: 1px solid #334155; border-radius: 16px; padding: 24px; }\n    .hint { color: #93c5fd; margin-bottom: 12px; }\n    .echo { border-radius: 12px; padding: 16px; background: #020617; border: 1px solid #1e293b; white-space: pre-wrap; color: #fca5a5; }\n  </style>\n</head>\n<body>\n  <main class=\"panel\">\n    <div class=\"hint\">payload reflected successfully</div>\n    <div class=\"echo\">&lt;script&gt;alert('xss')&lt;/script&gt;</div>\n  </main>\n</body>\n</html>",
            requires_upload: false,
        },
        BuiltinActionIdeaPreset {
            id: "redirect-302",
            title: "302 跳转",
            mood: "引流",
            summary: "命中后立刻返回 302，把请求导向指定落地页或说明页。",
            mechanism: "把你填写的目标 URL 写进 Location 头，rust 直接返回 302 响应。",
            performance: "低",
            fallback_path: "/admin/rules",
            plugin_id: "redirect-302-fun",
            file_name: "redirect-302-fun.zip",
            response_file_path: "redirect.html",
            plugin_name: "Redirect 302 Fun",
            plugin_description: "返回 302 跳转到指定目标页的示例动作",
            template_local_id: "redirect_302",
            template_description: "命中后使用 302 跳转到指定 URL",
            pattern: "(?i)redirect|jump|go|302",
            severity: "medium",
            content_type: "text/html; charset=utf-8",
            status_code: 302,
            gzip: false,
            body_source: "inline_text",
            response_content: "https://www.war.gov/",
            requires_upload: false,
        },
        BuiltinActionIdeaPreset {
            id: "smart-tarpit",
            title: "智能延迟",
            mood: "消耗",
            summary: "对可疑请求极慢响应，默认每秒只发送 1 字节，把扫描器拖住 30 秒以上。",
            mechanism: "通过内部 tarpit 头触发慢速写出。当前仅对 HTTP/1 与 HTTP/3 生效。",
            performance: "低",
            fallback_path: "/admin/rules",
            plugin_id: "smart-tarpit-fun",
            file_name: "smart-tarpit-fun.zip",
            response_file_path: "smart-tarpit.txt",
            plugin_name: "Smart Tarpit Fun",
            plugin_description: "极慢返回响应体、拖住扫描器的示例动作",
            template_local_id: "smart_tarpit",
            template_description: "每秒只返回少量字节，显著拉高攻击成本",
            pattern: "(?i)scanner|sqlmap|nmap|nikto|dirsearch|gobuster|ffuf|masscan",
            severity: "high",
            content_type: "text/plain; charset=utf-8",
            status_code: 200,
            gzip: false,
            body_source: "inline_text",
            response_content:
                "{\"bytes_per_chunk\":1,\"chunk_interval_ms\":1000,\"body_text\":\"processing request, please wait...\"}",
            requires_upload: false,
        },
        BuiltinActionIdeaPreset {
            id: "random-error-system",
            title: "随机错误系统",
            mood: "迷雾",
            summary: "随机返回 500 / 502 / 403，偶尔也返回成功状态，干扰攻击者对系统真实状态的判断。",
            mechanism: "通过内部随机状态头在运行时为每个请求挑选不同状态码，让同一路径的表现时好时坏。",
            performance: "中",
            fallback_path: "/admin/rules",
            plugin_id: "random-error-system-fun",
            file_name: "random-error-system-fun.zip",
            response_file_path: "random-error-system.txt",
            plugin_name: "Random Error System Fun",
            plugin_description: "随机返回不同成功/失败状态码的示例动作",
            template_local_id: "random_error_system",
            template_description: "随机制造系统不稳定假象，增加攻击者判断成本",
            pattern: "(?i)scanner|probe|health|status|debug|check|sqlmap|nikto|ffuf",
            severity: "medium",
            content_type: "text/plain; charset=utf-8",
            status_code: 500,
            gzip: false,
            body_source: "inline_text",
            response_content:
                "{\"failure_statuses\":[500,502,403],\"success_rate_percent\":25,\"success_body\":\"request completed successfully\",\"failure_body\":\"upstream system unstable, retry later\"}",
            requires_upload: false,
        },
        BuiltinActionIdeaPreset {
            id: "gzip-response",
            title: "响应Gzip",
            mood: "传输",
            summary: "上传一个已经压缩好的 .gz 响应体，命中后原样返回给客户端。",
            mechanism: "适合直接复用预压缩资源；系统会保存你上传的 gzip 文件并在规则命中时作为文件响应返回。",
            performance: "低",
            fallback_path: "/admin/rules",
            plugin_id: "gzip-response-fun",
            file_name: "gzip-response-fun.zip",
            response_file_path: "payload.gz",
            plugin_name: "Gzip Response Fun",
            plugin_description: "上传预压缩 gzip 响应体的示例动作",
            template_local_id: "gzip_response",
            template_description: "返回用户上传的 gzip 文件内容",
            pattern: "(?i)gzip|compressed|archive",
            severity: "medium",
            content_type: "text/html; charset=utf-8",
            status_code: 200,
            gzip: false,
            body_source: "file",
            response_content: "",
            requires_upload: true,
        },
    ]
}
