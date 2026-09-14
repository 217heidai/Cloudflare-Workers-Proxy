addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

/**
 * 代理白名单配置（URL 级）
 * ------------------------------------------------------------------
 * enableWhiteList: true=开启URL白名单校验，false=关闭（全部放行）
 *
 * whiteListUrls: URL白名单，支持 * 通配符
 *   - 通配符 * 可匹配任意字符（包括 / ? & = 等），放在不同位置控制粒度
 *   - 未写协议时自动匹配任意协议（http/https 均可命中）
 *   - 写了协议则必须完全一致（更严格，推荐）
 *   - 需要允许带查询参数时，用 * 覆盖，例如 "https://example.com/path*"
 *   - 匹配失败直接返回 403
 *
 * 示例：
 *   "https://example.com/*"                 只允许 example.com 的所有路径（仅 https）
 *   "https://api.github.com/users/*"        只允许该前缀下的路径
 *   "*.google.com/*"                        允许任意协议、google.com 任意子域、所有路径
 *   "https://example.com/api/user?name=*"   允许带指定查询参数的精确路径
 *
 * blockInternalAddress: 是否拦截内网/回环地址（SSRF 基础防护）
 *   拦截 localhost、127.x、10.x、172.16-31.x、192.168.x、169.254.x、
 *   100.64.x（CGNAT）、0.0.0.0、组播段、::1、fc00::/7、fe80::/10 等
 */
const PROXY_CONFIG = {
  enableWhiteList: true,
  whiteListUrls: [
    "https://github.com/217heidai/*",
    "https://raw.githubusercontent.com/217heidai/*",
    "https://api.telegram.org/*",
    "https://prod.ave-api.com/*",
    "https://www.binance.com/api/*",
    "https://api.etherscan.io/*",
    "https://go.getblock.us/*",
  ],
  blockInternalAddress: true
};

async function handleRequest(request) {
  try {
    const url = new URL(request.url);
    // 如果访问根目录，返回HTML
    if (url.pathname === "/") {
      return new Response(getRootHtml(), {
        headers: {
          'Content-Type': 'text/html; charset=utf-8'
        }
      });
    }
    // 从请求路径中提取目标 URL
    let actualUrlStr = decodeURIComponent(url.pathname.replace("/", ""));
    // 判断用户输入的 URL 是否带有协议
    actualUrlStr = ensureProtocol(actualUrlStr, url.protocol);
    // 保留查询参数
    actualUrlStr += url.search;

    // ================= 白名单校验（URL 级） =================
    const targetUrl = new URL(actualUrlStr);
    if (PROXY_CONFIG.enableWhiteList) {
      if (!isUrlAllowed(actualUrlStr, PROXY_CONFIG.whiteListUrls)) {
        return jsonResponse({
          error: "目标URL不在代理白名单内，已拒绝访问",
          url: targetUrl.href
        }, 403);
      }
    }
    // ================= 内网/回环地址拦截（SSRF 基础防护） =================
    if (PROXY_CONFIG.blockInternalAddress) {
      const hostname = targetUrl.hostname.replace(/^\[|\]$/g, '').toLowerCase();
      if (isInternalAddress(hostname)) {
        return jsonResponse({
          error: "禁止代理访问内网/回环地址，已拒绝访问",
          host: targetUrl.hostname
        }, 403);
      }
    }
    // ================= 校验结束 =================

    // 创建新 Headers 对象，排除以 'cf-' 开头的请求头
    const newHeaders = filterHeaders(request.headers, name => !name.startsWith('cf-'));
    // 创建一个新的请求以访问目标 URL
    const modifiedRequest = new Request(actualUrlStr, {
      headers: newHeaders,
      method: request.method,
      body: request.body,
      redirect: 'manual'
    });
    // 发起对目标 URL 的请求
    const response = await fetch(modifiedRequest);
    let body = response.body;
    // 处理重定向
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      body = response.body;
      // 创建新的 Response 对象以修改 Location 头部
      return handleRedirect(response, body);
    } else if (response.headers.get("Content-Type")?.includes("text/html")) {
      body = await handleHtmlContent(response, url.protocol, url.host, actualUrlStr);
    }
    // 创建修改后的响应对象
    const modifiedResponse = new Response(body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers
    });
    // 添加禁用缓存的头部
    setNoCacheHeaders(modifiedResponse.headers);
    // 添加 CORS 头部，允许跨域访问
    setCorsHeaders(modifiedResponse.headers);
    return modifiedResponse;
  } catch (error) {
    // 如果请求目标地址时出现错误，返回带有错误消息的响应和状态码 500（服务器错误）
    return jsonResponse({
      error: error.message
    }, 500);
  }
}

/**
 * URL 白名单匹配（支持 * 通配符）
 * 先通过 new URL() 规范化（域名转小写、默认端口归一化、IP 进制归一化），
 * 再按通配符匹配完整 URL。任何解析失败均视为不匹配（fail-closed）。
 */
function isUrlAllowed(urlStr, whiteListUrls) {
  let target;
  try {
    target = new URL(urlStr).href;
  } catch (e) {
    return false; // 目标URL无法解析，拒绝放行
  }
  for (const rawPattern of whiteListUrls) {
    try {
      let pattern = rawPattern;
      // 未写协议时，通配任意协议（http/https 均可命中）
      if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(pattern)) {
        pattern = "*://" + pattern;
      }
      const normalized = new URL(pattern).href;
      const regex = patternToRegex(normalized);
      if (regex.test(target)) {
        return true;
      }
    } catch (e) {
      // 非法 pattern 跳过（该条不生效，等同拒绝，不影响其他条目）
      continue;
    }
  }
  return false;
}

/**
 * 将带 * 通配符的 URL pattern 转换为正则
 * * 匹配任意字符（含 / ? & = 等），例如：
 *   https://example.com/*         -> example.com 下所有路径
 *   https://api.github.com/users/* -> /users/ 前缀的所有路径
 *   https://example.com/path      -> 仅精确匹配该路径（不含查询参数）
 */
function patternToRegex(pattern) {
  let regexStr = "";
  for (const ch of pattern) {
    if (ch === "*") {
      regexStr += ".*";
    } else {
      regexStr += ch.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
    }
  }
  return new RegExp("^" + regexStr + "$");
}

/**
 * 内网/回环地址检测（基础 SSRF 防护）
 * 注意：Cloudflare Workers 无法在发起请求前做 DNS 解析校验，
 * 本函数只拦截字面量形式的内网 IP/域名；域名解析到内网的情况
 * 需结合 Cloudflare WAF / egress 策略进一步防护。
 */
function isInternalAddress(hostname) {
  if (!hostname) return true;
  // 回环域名
  if (hostname === "localhost" || hostname.endsWith(".localhost") || hostname === "::1") {
    return true;
  }
  // IPv4 字面量
  const ipv4 = hostname.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const a = Number(ipv4[1]);
    const b = Number(ipv4[2]);
    const c = Number(ipv4[3]);
    const d = Number(ipv4[4]);
    if (a === 0) return true;                          // 0.0.0.0/8 本机
    if (a === 10) return true;                         // 10.0.0.0/8 私有
    if (a === 127) return true;                        // 127.0.0.0/8 回环
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
    if (a === 169 && b === 254) return true;           // 169.254.0.0/16 链路本地
    if (a === 172 && b >= 16 && b <= 31) return true;  // 172.16.0.0/12 私有
    if (a === 192 && b === 168) return true;           // 192.168.0.0/16 私有
    if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 基准测试
    if (a >= 224) return true;                         // 组播/保留段
  }
  // IPv6 字面量（hostname 已去除方括号）
  const ipv6 = hostname.toLowerCase();
  if (ipv6.startsWith("fc") || ipv6.startsWith("fd")) return true;   // fc00::/7 ULA
  if (ipv6.startsWith("fe8") || ipv6.startsWith("fe9") ||
      ipv6.startsWith("fea") || ipv6.startsWith("feb")) return true; // fe80::/10 链路本地
  if (ipv6.startsWith("::")) return true;              // ::1 / ::ffff:x 等特殊地址
  return false;
}

// 确保 URL 带有协议
function ensureProtocol(url, defaultProtocol) {
  return url.startsWith("http://") || url.startsWith("https://") ? url : defaultProtocol + "//" + url;
}

// 处理重定向
function handleRedirect(response, body) {
  const location = new URL(response.headers.get('location'));
  const modifiedLocation = `/${encodeURIComponent(location.toString())}`;
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers: {
      ...response.headers,
      'Location': modifiedLocation
    }
  });
}

// 处理 HTML 内容中的相对路径
async function handleHtmlContent(response, protocol, host, actualUrlStr) {
  const originalText = await response.text();
  let modifiedText = replaceRelativePaths(originalText, protocol, host, new URL(actualUrlStr).origin);
  return modifiedText;
}

// 替换 HTML 内容中的相对路径
function replaceRelativePaths(text, protocol, host, origin) {
  const regex = new RegExp('((href|src|action)=["\'])/(?!/)', 'g');
  return text.replace(regex, `$1${protocol}//${host}/${origin}/`);
}

// 返回 JSON 格式的响应
function jsonResponse(data, status) {
  return new Response(JSON.stringify(data), {
    status: status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8'
    }
  });
}

// 过滤请求头
function filterHeaders(headers, filterFunc) {
  return new Headers([...headers].filter(([name]) => filterFunc(name)));
}

// 设置禁用缓存的头部
function setNoCacheHeaders(headers) {
  headers.set('Cache-Control', 'no-store');
}

// 设置 CORS 头部
function setCorsHeaders(headers) {
  headers.set('Access-Control-Allow-Origin', '*');
  headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  headers.set('Access-Control-Allow-Headers', '*');
}

// 返回根目录的 HTML
function getRootHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <link href="https://s4.zstatic.net/ajax/libs/materialize/1.0.0/css/materialize.min.css" rel="stylesheet">
  <title>Proxy Everything</title>
  <link rel="icon" type="image/png" href="https://s2.hdslb.com/bfs/openplatform/1682b11880f5c53171217a03c8adc9f2e2a27fcf.png@100w.webp">
  <meta name="Description" content="Proxy Everything with CF Workers.">
  <meta property="og:description" content="Proxy Everything with CF Workers.">
  <meta property="og:image" content="https://s2.hdslb.com/bfs/openplatform/1682b11880f5c53171217a03c8adc9f2e2a27fcf.png@100w.webp">
  <meta name="robots" content="index, follow">
  <meta http-equiv="Content-Language" content="zh-CN">
  <meta name="copyright" content="Copyright © ymyuuu">
  <meta name="author" content="ymyuuu">
  <link rel="apple-touch-icon-precomposed" sizes="120x120" href="https://s2.hdslb.com/bfs/openplatform/1682b11880f5c53171217a03c8adc9f2e2a27fcf.png@100w.webp">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="viewport" content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0, user-scalable=no">
  <style>
      body, html {
          height: 100%;
          margin: 0;
      }
      .background {
          background-size: cover;
          background-position: center;
          height: 100%;
          display: flex;
          align-items: center;
          justify-content: center;
      }
      .card {
          background-color: rgba(255, 255, 255, 0.8);
          transition: background-color 0.3s ease, box-shadow 0.3s ease;
      }
      .card:hover {
          background-color: rgba(255, 255, 255, 1);
          box-shadow: 0px 8px 16px rgba(0, 0, 0, 0.3);
      }
      .input-field input[type=text] {
          color: #2c3e50;
      }
      .input-field input[type=text]:focus+label {
          color: #2c3e50 !important;
      }
      .input-field input[type=text]:focus {
          border-bottom: 1px solid #2c3e50 !important;
          box-shadow: 0 1px 0 0 #2c3e50 !important;
      }
      @media (prefers-color-scheme: dark) {
          body, html {
              background-color: #121212;
              color: #e0e0e0;
          }
          .card {
              background-color: rgba(33, 33, 33, 0.9);
              color: #ffffff;
          }
          .card:hover {
              background-color: rgba(50, 50, 50, 1);
              box-shadow: 0px 8px 16px rgba(0, 0, 0, 0.6);
          }
          .input-field input[type=text] {
              color: #ffffff;
          }
          .input-field input[type=text]:focus+label {
              color: #ffffff !important;
          }
          .input-field input[type=text]:focus {
              border-bottom: 1px solid #ffffff !important;
              box-shadow: 0 1px 0 0 #ffffff !important;
          }
          label {
              color: #cccccc;
          }
      }
  </style>
</head>
<body>
  <div class="background">
      <div class="container">
          <div class="row">
              <div class="col s12 m8 offset-m2 l6 offset-l3">
                  <div class="card">
                      <div class="card-content">
                          <span class="card-title center-align"><i class="material-icons left">link</i>Proxy Everything</span>
                          <form id="urlForm" onsubmit="redirectToProxy(event)">
                              <div class="input-field">
                                  <input type="text" id="targetUrl" placeholder="在此输入目标地址" required>
                                  <label for="targetUrl">目标地址</label>
                              </div>
                              <button type="submit" class="btn waves-effect waves-light teal darken-2 full-width">跳转</button>
                          </form>
                      </div>
                  </div>
              </div>
          </div>
      </div>
  </div>
  <script src="https://s4.zstatic.net/ajax/libs/materialize/1.0.0/js/materialize.min.js"></script>
  <script>
      function redirectToProxy(event) {
          event.preventDefault();
          const targetUrl = document.getElementById('targetUrl').value.trim();
          const currentOrigin = window.location.origin;
          window.open(currentOrigin + '/' + encodeURIComponent(targetUrl), '_blank');
      }
  </script>
</body>
</html>`;
}
