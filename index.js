// 配置项
const TURNSTILE_SECRET_KEY = "0x4AAAAAABM4ehiS0ZNJcU-Q";
const SITE_KEY = "0x4AAAAAABM4egLEzJzXx4-PzCoEi9t0_AE"; // 确认与 Cloudflare 控制台对应
const TARGET_URL = "welconme.pages.dev"; // 修正 URL 拼写
const COOKIE_NAME = "secure_token";
const BLOCK_THRESHOLD = 0.8;

// 主逻辑（改用 Module Worker 格式）
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const cookie = request.headers.get("Cookie") || "";
  const userIP = request.headers.get("CF-Connecting-IP");

  try {
    // --- 情况1：已通过验证 → 透传 ---
    if (cookie.includes(`${COOKIE_NAME}=`)) {
      const token = cookie.match(new RegExp(`${COOKIE_NAME}=([^;]+)`))[1];
      const isValid = await validateToken(token, userIP, env);
      if (isValid) return Response.redirect(TARGET_URL, 302);
    }

    // --- 情况2：提交验证（POST）---
    if (url.pathname === "/verify" && request.method === "POST") {
      return handleVerification(request, userIP, env);
    }

    // --- 情况3：首次访问 → 挑战页面 ---
    return generateChallengePage(request, userIP);
  } catch (err) {
    return new Response(`服务器错误: ${err.message}`, { status: 500 });
  }
}

// 处理验证请求（添加 env 参数）
async function handleVerification(request, userIP, env) {
  const formData = await request.formData();
  const turnstileToken = formData.get('cf-turnstile-response');
  const honeypot = formData.get('email');
  const fpHash = formData.get('fp') || 'empty';

  // 强化蜜罐检测
  if (honeypot) {
    await logMaliciousRequest(userIP, "蜜罐触发", env);
    return blockRequest(userIP);
  }

  // 验证 Turnstile
  const isHuman = await verifyTurnstile(turnstileToken, userIP);
  if (!isHuman) return new Response("人机验证失败", { status: 403 });

  // 风险评分
  const riskScore = await calculateRiskScore(fpHash, userIP, env);
  if (riskScore > BLOCK_THRESHOLD) {
    return forceInteractiveChallenge(); 
  }

  // 下发令牌
  const token = generateSecureToken(userIP);
  await env.ANTI_BOT_KV.put(token, JSON.stringify({ valid: true, ip: userIP }), { 
    expirationTtl: 3600 
  });

  return new Response(null, {
    status: 302,
    headers: {
      "Location": TARGET_URL,
      "Set-Cookie": `${COOKIE_NAME}=${token}; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax`
    }
  });
}

// 挑战页面（修正指纹脚本）
async function generateChallengePage(request, userIP) {
  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
        <script type="module">
          import('https://openfpcdn.io/fingerprintjs/v3')
            .then(module => module.default)
            .then(FingerprintJS => FingerprintJS.load())
            .then(fp => fp.get())
            .then(result => {
              document.getElementById('fp-hash').value = result.hash;
            })
            .catch(() => {
              document.getElementById('fp-hash').value = 'error';
            });
        </script>
      </head>
      <body>
        <form action="/verify" method="POST">
          <div class="cf-turnstile" data-sitekey="${SITE_KEY}" data-callback="onSubmit"></div>
          <input type="email" name="email" style="display:none;" aria-hidden="true">
          <input type="hidden" name="fp" id="fp-hash">
        </form>
        <script>
          function onSubmit(token) {
            document.forms[0].submit();
          }
        </script>
      </body>
    </html>
  `;

  return new Response(html, { 
    headers: { 
      "Content-Type": "text/html",
      "Cache-Control": "no-store" // 禁止缓存
    } 
  });
}

// --- 工具函数（确保传递 env）---
async function verifyTurnstile(token, ip) { /* 原逻辑 */ }

function generateSecureToken(ip) { /* 原逻辑 */ }

async function validateToken(token, ip, env) {
  const record = await env.ANTI_BOT_KV.get(token);
  if (!record) return false;
  const { valid, ip: storedIP } = JSON.parse(record);
  return valid && storedIP === ip;
}

async function calculateRiskScore(fpHash, ip, env) {
  const history = await env.ANTI_BOT_KV.get(`fp_${fpHash}`);
  return history ? 0.9 : 0.2;
}

async function logMaliciousRequest(ip, reason, env) {
  await env.ANTI_BOT_KV.put(`malicious_${ip}`, reason, { expirationTtl: 86400 });
}

function blockRequest(ip) { /* 原逻辑 */ }

function forceInteractiveChallenge() { /* 原逻辑 */ }

// 使用 Module Worker 格式（关键修改！）
export default {
  fetch: (request, env, ctx) => handleRequest(request, env)
};
