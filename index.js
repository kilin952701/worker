// 配置项
const TURNSTILE_SECRET_KEY = "0x4AAAAAABM4ehiS0ZNJcU-Q";
const SITE_KEY = "0x4AAAAAABM4egLEzJzXx4-PzCoEi9t0_AE";
const KV_NAMESPACE = ANTI_BOT_KV; // 绑定到 Worker 的 KV
const TARGET_URL = "https://rgzv.jqnmbdbsmuh.es/WqCVRYD/";
const COOKIE_NAME = "secure_token";
const BLOCK_THRESHOLD = 0.8; // 风险阈值（超过则触发二次验证）

// 主逻辑
async function handleRequest(request) {
  const url = new URL(request.url);
  const cookie = request.headers.get("Cookie") || "";
  const userIP = request.headers.get("CF-Connecting-IP");

  // --- 情况1：已通过验证 → 透传 ---
  if (cookie.includes(`${COOKIE_NAME}=`)) {
    const token = cookie.match(new RegExp(`${COOKIE_NAME}=([^;]+)`))[1];
    const isValid = await validateToken(token, userIP);
    if (isValid) return Response.redirect(TARGET_URL, 302);
  }

  // --- 情况2：提交验证（POST）---
  if (url.pathname === "/verify" && request.method === "POST") {
    return handleVerification(request, userIP);
  }

  // --- 情况3：首次访问 → 返回含陷阱和指纹的页面 ---
  return generateChallengePage(request, userIP);
}

// 处理验证请求
async function handleVerification(request, userIP) {
  const formData = await request.formData();
  const turnstileToken = formData.get('cf-turnstile-response');
  const honeypot = formData.get('email'); // 蜜罐字段
  const fpHash = formData.get('fp');

  // 规则1：蜜罐检测
  if (honeypot) {
    await logMaliciousRequest(userIP, "蜜罐触发");
    return blockRequest(userIP);
  }

  // 规则2：验证 Turnstile
  const isHuman = await verifyTurnstile(turnstileToken, userIP);
  if (!isHuman) return new Response("验证失败", { status: 403 });

  // 规则3：浏览器指纹评分模型（示例：简单哈希匹配）
  const riskScore = await calculateRiskScore(fpHash, userIP);
  if (riskScore > BLOCK_THRESHOLD) {
    return forceInteractiveChallenge(); // 高风险时跳转强验证
  }

  // 生成动态令牌并写入 Cookie
  const token = generateSecureToken(userIP);
  await KV_NAMESPACE.put(token, JSON.stringify({ valid: true, ip: userIP }), { expirationTtl: 3600 });

  return new Response(null, {
    status: 302,
    headers: {
      "Location": TARGET_URL,
      "Set-Cookie": `${COOKIE_NAME}=${token}; Path=/; Max-Age=3600; Secure; HttpOnly`
    }
  });
}

// 生成挑战页面（含指纹和蜜罐）
async function generateChallengePage(request, userIP) {
  const fpScript = ` /* 前端生成指纹的 JavaScript 代码 */ 
    import('https://openfpcdn.io/fingerprintjs/v3').then(FingerprintJS => {
      FingerprintJS.load().then(fp => fp.get()).then(result => {
        document.getElementById('fp-hash').value = result.hash;
      });
    });
  `;

  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
        <script>${fpScript}</script>
      </head>
      <body>
        <form action="/verify" method="POST">
          <!-- Turnstile 无感验证 -->
          <div class="cf-turnstile" data-sitekey="${SITE_KEY}" data-callback="onSubmit"></div>
          
          <!-- 蜜罐陷阱 -->
          <input type="email" name="email" style="display:none;">
          
          <!-- 浏览器指纹 -->
          <input type="hidden" name="fp" id="fp-hash">
        </form>

        <script>
          // 验证通过后自动提交表单
          function onSubmit(token) {
            document.forms[0].submit();
          }
        </script>
      </body>
    </html>
  `;

  return new Response(html, { headers: { "Content-Type": "text/html" } });
}

// --- 工具函数 ---
async function verifyTurnstile(token, ip) {
  const formData = new URLSearchParams();
  formData.append('secret', TURNSTILE_SECRET_KEY);
  formData.append('response', token);
  formData.append('remoteip', ip);

  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body: formData,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  });

  const data = await response.json();
  return data.success;
}

function generateSecureToken(ip) {
  const randomPart = crypto.randomUUID();
  const timePart = Date.now().toString(36);
  return btoa(`${ip}|${randomPart}|${timePart}`);
}

async function validateToken(token, ip) {
  const record = await KV_NAMESPACE.get(token);
  if (!record) return false;
  const { valid, ip: storedIP } = JSON.parse(record);
  return valid && storedIP === ip;
}

async function calculateRiskScore(fpHash, ip) {
  // 示例：从 KV 查询历史指纹记录（复杂模型可调用外部 API）
  const history = await KV_NAMESPACE.get(`fp_${fpHash}`);
  return history ? 0.9 : 0.2; // 假设重复指纹高风险
}

async function logMaliciousRequest(ip, reason) {
  // 记录到 KV 或日志系统
  await KV_NAMESPACE.put(`malicious_${ip}`, reason, { expirationTtl: 86400 });
}

function blockRequest(ip) {
  // 可触发 Cloudflare 防火墙规则
  return new Response("请求异常", { status: 403 });
}

function forceInteractiveChallenge() {
  // 跳转到更高强度验证（如传统验证码）
  return Response.redirect("/captcha", 302);
}

// Worker 入口
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});
