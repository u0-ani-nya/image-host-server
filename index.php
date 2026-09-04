<?php
require __DIR__ . '/config.php';

// ─── 工具函数 ───

function json_response($data, $status = 200) {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function error_response($message, $status = 400) {
    json_response(['error' => $message], $status);
}

function get_auth_token() {
    $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (str_starts_with($auth, 'Bearer ')) {
        return trim(substr($auth, 7));
    }
    return '';
}

function load_keys() {
    if (!file_exists(KEYS_FILE)) return [];
    $data = json_decode(file_get_contents(KEYS_FILE), true);
    return is_array($data['keys'] ?? null) ? $data['keys'] : [];
}

function save_keys($keys) {
    $dir = dirname(KEYS_FILE);
    if (!is_dir($dir)) mkdir($dir, 0755, true);
    $ok = @file_put_contents(KEYS_FILE, json_encode(['keys' => $keys], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
    if ($ok === false) error_response('写入密钥文件失败，请检查 data/ 目录权限', 500);
}

function is_valid_key($token) {
    foreach (load_keys() as $k) {
        if ($k['key'] === $token) return true;
    }
    return false;
}

function generate_filename($ext) {
    return bin2hex(random_bytes(8)) . '.' . $ext;
}

function get_base_url() {
    $proto = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? (($_SERVER['HTTPS'] ?? 'off') === 'on' ? 'https' : 'http');
    $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
    $scriptDir = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/');
    return $proto . '://' . $host . $scriptDir;
}

function get_self() {
    return $_SERVER['SCRIPT_NAME'];
}

// 解析路由：支持 PATH_INFO 和 query string 两种方式
function get_route() {
    // 方式1: PATH_INFO (Nginx 配置了 fastcgi_split_path_info)
    $path = $_SERVER['PATH_INFO'] ?? '';
    if ($path) return $path;
    // 方式2: query string _route 参数
    if (isset($_GET['_route'])) return $_GET['_route'];
    // 方式3: 从 REQUEST_URI 中去掉 SCRIPT_NAME
    $requestUri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $scriptName = $_SERVER['SCRIPT_NAME'];
    if ($requestUri !== $scriptName && str_starts_with($requestUri, $scriptName)) {
        return substr($requestUri, strlen($scriptName)) ?: '/';
    }
    return '/';
}

function check_admin_auth() {
    if (session_status() !== PHP_SESSION_ACTIVE) session_start();
    return !empty($_SESSION['admin']);
}

// ─── 路由 ───

$method = $_SERVER['REQUEST_METHOD'];
$route = get_route();

// ─── 管理页面登录 ───

if ($method === 'POST' && ($route === '/api/login' || $route === '/api/login/')) {
    $input = json_decode(file_get_contents('php://input'), true);
    $password = $input['password'] ?? '';
    if ($password !== ADMIN_PASSWORD) {
        error_response('密码错误', 401);
    }
    session_start();
    $_SESSION['admin'] = true;
    json_response(['ok' => true]);
}

if ($method === 'POST' && ($route === '/api/logout' || $route === '/api/logout/')) {
    session_start();
    session_destroy();
    json_response(['ok' => true]);
}

// ─── 管理页面 ───

if ($method === 'GET' && ($route === '/' || $route === '')) {
    session_start();
    $logged_in = !empty($_SESSION['admin']);
    if (!$logged_in) { show_login_page(); exit; }
    show_admin_page();
    exit;
}

// ─── API: 列出密钥 ───

if ($method === 'GET' && ($route === '/api/keys' || $route === '/api/keys/')) {
    if (!check_admin_auth()) error_response('未登录', 401);
    $keys = load_keys();
    $file_count = 0;
    if (is_dir(UPLOADS_DIR)) {
        $file_count = count(array_filter(scandir(UPLOADS_DIR), fn($f) => !str_starts_with($f, '.')));
    }
    json_response(['keys' => $keys, 'fileCount' => $file_count]);
}

// ─── API: 生成密钥 ───

if ($method === 'POST' && ($route === '/api/keys' || $route === '/api/keys/')) {
    if (!check_admin_auth()) error_response('未登录', 401);
    $input = json_decode(file_get_contents('php://input'), true);
    $note = mb_substr(trim($input['note'] ?? ''), 0, 100);
    $key = bin2hex(random_bytes(16));
    $key = sprintf('%s-%s-%s-%s-%s',
        substr($key, 0, 8), substr($key, 8, 4), substr($key, 12, 4),
        substr($key, 16, 4), substr($key, 20, 12)
    );
    $keys = load_keys();
    $keys[] = ['key' => $key, 'createdAt' => date('c'), 'note' => $note];
    save_keys($keys);
    json_response(['key' => $key]);
}

// ─── API: 删除密钥 ───

if ($method === 'DELETE' && str_starts_with($route, '/api/keys/')) {
    if (!check_admin_auth()) error_response('未登录', 401);
    $key = substr($route, strlen('/api/keys/'));
    $keys = load_keys();
    $filtered = array_values(array_filter($keys, fn($k) => $k['key'] !== $key));
    if (count($filtered) === count($keys)) error_response('密钥不存在', 404);
    save_keys($filtered);
    json_response(['ok' => true]);
}

// ─── 上传图片（兼容 ImgBed API 格式）───

if ($method === 'POST' && ($route === '/upload' || $route === '/upload/')) {
    $token = get_auth_token();
    if (!$token || !is_valid_key($token)) {
        error_response('无效的上传密钥', 401);
    }

    if (!isset($_FILES['file'])) {
        error_response('未找到文件字段');
    }

    $file = $_FILES['file'];
    if ($file['error'] !== UPLOAD_ERR_OK) {
        error_response('上传错误: ' . $file['error']);
    }

    if ($file['size'] > MAX_FILE_SIZE) {
        error_response('文件过大，最大 ' . (MAX_FILE_SIZE / 1024 / 1024) . 'MB');
    }

    $mime = mime_content_type($file['tmp_name']);
    if (!isset(ALLOWED_TYPES[$mime])) {
        error_response('仅支持 PNG、JPEG、WebP 格式');
    }

    $ext = ALLOWED_TYPES[$mime];
    $filename = generate_filename($ext);
    $dest = UPLOADS_DIR . $filename;

    if (!is_dir(UPLOADS_DIR)) mkdir(UPLOADS_DIR, 0755, true);
    if (!move_uploaded_file($file['tmp_name'], $dest)) {
        error_response('保存文件失败', 500);
    }

    $base = get_base_url();
    $directUrl = $base . '/images/' . $filename;

    // 兼容 CloudFlare ImgBed 响应格式
    // uploadToCfBed() 读取: item.publicUrl || item.url || item.src
    json_response([[
        'url'       => $directUrl,
        'src'       => '/images/' . $filename,
        'publicUrl' => $directUrl,
    ]]);
}

// ─── 删除图片 ───

if ($method === 'DELETE' && str_starts_with($route, '/file/')) {
    $token = get_auth_token();
    if (!$token || !is_valid_key($token)) {
        error_response('无效的上传密钥', 401);
    }

    $filename = basename(substr($route, strlen('/file/')));
    $filepath = UPLOADS_DIR . $filename;
    if (!file_exists($filepath)) error_response('文件不存在', 404);

    unlink($filepath);
    json_response(['ok' => true]);
}

// ─── 访问图片 ───

if ($method === 'GET' && str_starts_with($route, '/images/')) {
    $filename = basename(substr($route, strlen('/images/')));
    $filepath = UPLOADS_DIR . $filename;
    if (!file_exists($filepath)) {
        http_response_code(404);
        echo 'Not Found';
        exit;
    }

    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $mime = ['png' => 'image/png', 'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'webp' => 'image/webp'][$ext] ?? 'application/octet-stream';

    header('Content-Type: ' . $mime);
    header('Content-Length: ' . filesize($filepath));
    header('Cache-Control: public, max-age=31536000');
    readfile($filepath);
    exit;
}

// ─── 404 ───

http_response_code(404);
header('Content-Type: application/json; charset=utf-8');
echo json_encode(['error' => 'Not Found', 'route' => $route, 'script' => $_SERVER['SCRIPT_NAME'], 'request_uri' => $_SERVER['REQUEST_URI']]);

// ═══════════════════════════════════════════
//  页面渲染
// ═══════════════════════════════════════════

function show_login_page() {
$self = get_self();
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>图床管理 - 登录</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,system-ui,sans-serif;background:#f5f5f5;display:flex;align-items:center;justify-content:center;min-height:100vh}
.login-box{background:#fff;padding:32px;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);width:320px}
h1{font-size:18px;margin-bottom:20px;text-align:center}
input{width:100%;padding:10px 14px;border:1px solid #ddd;border-radius:8px;font-size:14px;margin-bottom:12px}
button{width:100%;padding:10px;border:none;border-radius:8px;background:#333;color:#fff;font-size:14px;cursor:pointer}
button:hover{background:#555}
button:disabled{background:#999;cursor:not-allowed}
.toast{position:fixed;top:20px;left:50%;transform:translateX(-50%);padding:12px 20px;border-radius:8px;font-size:13px;z-index:999;opacity:0;transition:.3s;pointer-events:none;max-width:80vw;text-align:center}
.toast.show{opacity:1}
.toast.error{background:#fee;color:#c00;border:1px solid #fcc}
.toast.success{background:#efe;color:#060;border:1px solid #cfc}
</style>
</head>
<body>
<div class="login-box">
  <h1>🖨️ 图床管理</h1>
  <input type="password" id="pwd" placeholder="管理密码" autofocus>
  <button type="button" id="loginBtn">登录</button>
</div>
<div class="toast" id="toast"></div>
<script type="text/javascript">
(function(){
  var self = <?= json_encode($self) ?>;
  var btn = document.getElementById('loginBtn');
  var pwdInput = document.getElementById('pwd');

  btn.addEventListener('click', doLogin);
  pwdInput.addEventListener('keydown', function(e) { if(e.key==='Enter') doLogin(); });

  function toast(msg, type) {
    var el = document.getElementById('toast');
    el.textContent = msg;
    el.className = 'toast ' + (type || 'error');
    el.classList.add('show');
    setTimeout(function(){ el.classList.remove('show'); }, 4000);
  }

  async function doLogin() {
    var pwd = pwdInput.value;
    if (!pwd) { toast('请输入密码', 'error'); return; }
    btn.disabled = true;
    btn.textContent = '登录中...';
    try {
      var res = await fetch(self + '?_route=/api/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({password: pwd})
      });
      var text = await res.text();
      var data;
      try { data = JSON.parse(text); } catch(e) {
        toast('服务器返回了非 JSON (' + res.status + ')', 'error');
        console.error('Response:', text.substring(0, 500));
        return;
      }
      if (res.ok) {
        toast('登录成功', 'success');
        setTimeout(function(){ location.reload(); }, 500);
      } else {
        toast(data.error || '登录失败 (' + res.status + ')', 'error');
      }
    } catch (e) {
      toast('网络错误: ' + e.message, 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = '登录';
    }
  }
})();
</script>
</body>
</html>
<?php
}

function show_admin_page() {
    $self = get_self();
    $base = get_base_url();
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>图床管理</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,system-ui,sans-serif;background:#f5f5f5;color:#333;min-height:100vh}
.container{max-width:640px;margin:0 auto;padding:24px}
h1{font-size:20px;margin-bottom:4px}
.subtitle{color:#888;font-size:13px;margin-bottom:24px}
.card{background:#fff;border-radius:12px;padding:20px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.card h2{font-size:15px;margin-bottom:12px;display:flex;align-items:center;gap:8px}
.key-list{list-style:none}
.key-list li{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid #f0f0f0;font-size:13px}
.key-list li:last-child{border:none}
.key-value{font-family:monospace;font-size:12px;word-break:break-all;flex:1;margin-right:12px;color:#555}
.key-meta{color:#999;font-size:11px;white-space:nowrap}
.btn{padding:8px 16px;border:none;border-radius:8px;cursor:pointer;font-size:13px;transition:.15s}
.btn-primary{background:#333;color:#fff}
.btn-primary:hover{background:#555}
.btn-danger{background:#fff;color:#e44;border:1px solid #e44}
.btn-danger:hover{background:#fee}
.btn-sm{padding:4px 10px;font-size:12px}
.input-row{display:flex;gap:8px;margin-bottom:12px}
.input-row input{flex:1;padding:8px 12px;border:1px solid #ddd;border-radius:8px;font-size:13px}
.server-url{background:#f9f9f9;padding:10px 14px;border-radius:8px;font-family:monospace;font-size:12px;word-break:break-all;margin-bottom:12px;border:1px dashed #ddd}
.empty{color:#aaa;font-size:13px;text-align:center;padding:20px}
.toast{position:fixed;top:20px;left:50%;transform:translateX(-50%);padding:12px 20px;border-radius:8px;font-size:13px;z-index:999;opacity:0;transition:.3s;pointer-events:none;max-width:80vw;text-align:center}
.toast.show{opacity:1}
.toast.error{background:#fee;color:#c00;border:1px solid #fcc}
.toast.success{background:#efe;color:#060;border:1px solid #cfc}
.stats{display:flex;gap:16px;margin-bottom:16px;font-size:13px;color:#666}
.stats span{background:#f0f0f0;padding:4px 10px;border-radius:6px}
.top-bar{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.logout{color:#888;font-size:12px;cursor:pointer}
.logout:hover{color:#333}
</style>
</head>
<body>
<div class="container">
  <div class="top-bar">
    <div>
      <h1>🖨️ 图床管理</h1>
      <p class="subtitle">生成密钥后，在 WeChat Printer 图床设置中填入服务器地址和密钥即可使用。</p>
    </div>
    <span class="logout" id="logoutBtn">退出登录</span>
  </div>

  <div class="stats" id="stats"></div>

  <div class="card">
    <h2>🔑 上传密钥</h2>
    <div class="input-row">
      <input type="text" id="noteInput" placeholder="备注（可选，如：给小明的密钥）">
      <button class="btn btn-primary" id="genBtn">生成新密钥</button>
    </div>
    <ul class="key-list" id="keyList"></ul>
    <div class="empty" id="emptyHint">暂无密钥，点击上方按钮生成</div>
  </div>

  <div class="card">
    <h2>📋 客户端配置</h2>
    <div class="server-url"><?= htmlspecialchars($base) ?></div>
    <p style="font-size:12px;color:#888">在 WeChat Printer → 设置 → 图床设置 → 选择「自定义图床」，填入上方地址和你生成的密钥。</p>
  </div>
</div>

<div class="toast" id="toast"></div>

<script type="text/javascript">
(function(){
  var self = <?= json_encode($self) ?>;

  function toast(msg, type) {
    var el = document.getElementById('toast');
    el.textContent = msg;
    el.className = 'toast ' + (type || 'error');
    el.classList.add('show');
    setTimeout(function(){ el.classList.remove('show'); }, 3000);
  }

  function api(path, opts) {
    return fetch(self + '?_route=' + encodeURIComponent(path), opts || {});
  }

  document.getElementById('logoutBtn').addEventListener('click', function() {
    api('/api/logout', {method:'POST'}).then(function(){ location.reload(); });
  });
  document.getElementById('genBtn').addEventListener('click', generateKey);
  document.getElementById('noteInput').addEventListener('keydown', function(e) { if(e.key==='Enter') generateKey(); });

  async function loadKeys() {
    var res = await api('/api/keys');
    if (res.status === 401) { location.reload(); return; }
    var data = await res.json();
    var list = document.getElementById('keyList');
    var empty = document.getElementById('emptyHint');
    var stats = document.getElementById('stats');

    if (!data.keys.length) {
      list.innerHTML = '';
      empty.style.display = 'block';
      stats.innerHTML = '';
      return;
    }
    empty.style.display = 'none';
    stats.innerHTML = '<span>共 ' + data.keys.length + ' 个密钥</span><span>' + (data.fileCount || 0) + ' 张图片</span>';
    list.innerHTML = data.keys.map(function(k) {
      return '<li>' +
        '<div style="flex:1;margin-right:12px">' +
        '<div class="key-value">' + k.key + '</div>' +
        '<div class="key-meta">' + (k.note ? k.note + ' · ' : '') + '创建于 ' + new Date(k.createdAt).toLocaleString('zh-CN') + '</div>' +
        '</div>' +
        '<button class="btn btn-danger btn-sm" data-copy="' + k.key + '">复制</button>' +
        '<button class="btn btn-danger btn-sm" data-del="' + k.key + '" style="margin-left:4px">删除</button>' +
        '</li>';
    }).join('');

    list.querySelectorAll('[data-copy]').forEach(function(btn) {
      btn.addEventListener('click', function() {
        navigator.clipboard.writeText(btn.getAttribute('data-copy')).then(function(){ toast('已复制到剪贴板', 'success'); });
      });
    });
    list.querySelectorAll('[data-del]').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var key = btn.getAttribute('data-del');
        if (!confirm('确定删除此密钥？')) return;
        api('/api/keys/' + key, { method: 'DELETE' }).then(function(){ toast('密钥已删除', 'success'); loadKeys(); });
      });
    });
  }

  async function generateKey() {
    var note = document.getElementById('noteInput').value.trim();
    var res = await api('/api/keys', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({note: note}) });
    var data = await res.json();
    if (data.key) {
      document.getElementById('noteInput').value = '';
      toast('密钥已生成', 'success');
      loadKeys();
    }
  }

  loadKeys();
})();
</script>
</body>
</html>
<?php
}
