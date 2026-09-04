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
    if (str_starts_with($auth, 'Bearer ')) return trim(substr($auth, 7));
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
    foreach (load_keys() as $k) { if ($k['key'] === $token) return true; }
    return false;
}

function generate_filename($ext) { return bin2hex(random_bytes(8)) . '.' . $ext; }

function get_base_url() {
    $proto = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? (($_SERVER['HTTPS'] ?? 'off') === 'on' ? 'https' : 'http');
    $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost';
    return $proto . '://' . $host . rtrim(dirname($_SERVER['SCRIPT_NAME']), '/');
}

function get_self() { return $_SERVER['SCRIPT_NAME']; }

function get_route() {
    $path = $_SERVER['PATH_INFO'] ?? '';
    if ($path) return $path;
    if (isset($_GET['_route'])) return $_GET['_route'];
    $req = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    $scr = $_SERVER['SCRIPT_NAME'];
    if ($req !== $scr && str_starts_with($req, $scr)) return substr($req, strlen($scr)) ?: '/';
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
    if (($input['password'] ?? '') !== ADMIN_PASSWORD) error_response('密码错误', 401);
    session_start(); $_SESSION['admin'] = true;
    json_response(['ok' => true]);
}

if ($method === 'POST' && ($route === '/api/logout' || $route === '/api/logout/')) {
    session_start(); session_destroy();
    json_response(['ok' => true]);
}

// ─── 管理页面 ───

if ($method === 'GET' && ($route === '/' || $route === '')) {
    session_start();
    if (empty($_SESSION['admin'])) { show_login_page(); exit; }
    show_admin_page();
    exit;
}

// ─── API: 列出密钥 ───

if ($method === 'GET' && ($route === '/api/keys' || $route === '/api/keys/')) {
    if (!check_admin_auth()) error_response('未登录', 401);
    $keys = load_keys();
    $fc = is_dir(UPLOADS_DIR) ? count(array_filter(scandir(UPLOADS_DIR), fn($f) => !str_starts_with($f, '.'))) : 0;
    json_response(['keys' => $keys, 'fileCount' => $fc]);
}

// ─── API: 生成密钥 ───

if ($method === 'POST' && ($route === '/api/keys' || $route === '/api/keys/')) {
    if (!check_admin_auth()) error_response('未登录', 401);
    $input = json_decode(file_get_contents('php://input'), true);
    $note = mb_substr(trim($input['note'] ?? ''), 0, 100);
    $key = bin2hex(random_bytes(16));
    $key = sprintf('%s-%s-%s-%s-%s', substr($key,0,8), substr($key,8,4), substr($key,12,4), substr($key,16,4), substr($key,20,12));
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

// ─── API: 列出图片（管理用）───

if ($method === 'GET' && ($route === '/api/images' || $route === '/api/images/')) {
    if (!check_admin_auth()) error_response('未登录', 401);
    $images = [];
    if (is_dir(UPLOADS_DIR)) {
        $files = array_filter(scandir(UPLOADS_DIR), fn($f) => !str_starts_with($f, '.'));
        foreach ($files as $f) {
            $path = UPLOADS_DIR . $f;
            $images[] = [
                'filename' => $f,
                'size' => filesize($path),
                'time' => filemtime($path),
                'mime' => mime_content_type($path),
            ];
        }
        usort($images, fn($a, $b) => $b['time'] - $a['time']);
    }
    json_response(['images' => $images]);
}

// ─── API: 删除图片（管理用）───

if ($method === 'DELETE' && str_starts_with($route, '/api/images/')) {
    if (!check_admin_auth()) error_response('未登录', 401);
    $filename = basename(substr($route, strlen('/api/images/')));
    $filepath = UPLOADS_DIR . $filename;
    if (!file_exists($filepath)) error_response('文件不存在', 404);
    unlink($filepath);
    json_response(['ok' => true]);
}

// ─── 上传图片（兼容 ImgBed API）───

if ($method === 'POST' && ($route === '/upload' || $route === '/upload/')) {
    $token = get_auth_token();
    if (!$token || !is_valid_key($token)) error_response('无效的上传密钥', 401);
    if (!isset($_FILES['file'])) error_response('未找到文件字段');
    $file = $_FILES['file'];
    if ($file['error'] !== UPLOAD_ERR_OK) error_response('上传错误: ' . $file['error']);
    if ($file['size'] > MAX_FILE_SIZE) error_response('文件过大，最大 ' . (MAX_FILE_SIZE / 1024 / 1024) . 'MB');
    $mime = mime_content_type($file['tmp_name']);
    if (!isset(ALLOWED_TYPES[$mime])) error_response('仅支持 PNG、JPEG、WebP 格式');
    $ext = ALLOWED_TYPES[$mime];
    $filename = generate_filename($ext);
    $dest = UPLOADS_DIR . $filename;
    if (!is_dir(UPLOADS_DIR)) mkdir(UPLOADS_DIR, 0755, true);
    if (!move_uploaded_file($file['tmp_name'], $dest)) error_response('保存文件失败', 500);
    $base = get_base_url();
    $directUrl = $base . '/images/' . $filename;
    // 兼容 CloudFlare ImgBed 响应格式
    json_response([['url' => $directUrl, 'src' => '/images/' . $filename, 'publicUrl' => $directUrl]]);
}

// ─── 删除图片（ImgBed 兼容）───

if ($method === 'DELETE' && str_starts_with($route, '/file/')) {
    $token = get_auth_token();
    if (!$token || !is_valid_key($token)) error_response('无效的上传密钥', 401);
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
    if (!file_exists($filepath)) { http_response_code(404); echo 'Not Found'; exit; }
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $mime = ['png'=>'image/png','jpg'=>'image/jpeg','jpeg'=>'image/jpeg','webp'=>'image/webp'][$ext] ?? 'application/octet-stream';
    header('Content-Type: ' . $mime);
    header('Content-Length: ' . filesize($filepath));
    header('Cache-Control: public, max-age=31536000');
    readfile($filepath);
    exit;
}

// ─── 404 ───

http_response_code(404);
header('Content-Type: application/json; charset=utf-8');
echo json_encode(['error' => 'Not Found', 'route' => $route]);

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
  var self=<?=json_encode($self)?>;
  var btn=document.getElementById('loginBtn'),pwd=document.getElementById('pwd');
  btn.addEventListener('click',doLogin);
  pwd.addEventListener('keydown',function(e){if(e.key==='Enter')doLogin()});
  function toast(m,t){var e=document.getElementById('toast');e.textContent=m;e.className='toast '+(t||'error');e.classList.add('show');setTimeout(function(){e.classList.remove('show')},4000)}
  async function doLogin(){
    if(!pwd.value){toast('请输入密码','error');return}
    btn.disabled=true;btn.textContent='登录中...';
    try{
      var r=await fetch(self+'?_route=/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pwd.value})});
      var t=await r.text(),d;try{d=JSON.parse(t)}catch(e){toast('服务器返回非 JSON ('+r.status+')','error');return}
      if(r.ok){toast('登录成功','success');setTimeout(function(){location.reload()},500)}
      else toast(d.error||'登录失败','error')
    }catch(e){toast('网络错误: '+e.message,'error')}
    finally{btn.disabled=false;btn.textContent='登录'}
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
.container{max-width:900px;margin:0 auto;padding:24px}
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
.gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px}
.gallery-item{border:1px solid #eee;border-radius:8px;overflow:hidden;background:#fafafa;position:relative}
.gallery-item img{width:100%;height:140px;object-fit:cover;display:block;cursor:pointer}
.gallery-info{padding:8px;font-size:11px;color:#666}
.gallery-info .name{font-family:monospace;word-break:break-all;color:#333;margin-bottom:4px}
.gallery-info .meta{display:flex;justify-content:space-between;align-items:center}
.gallery-actions{display:flex;gap:4px;padding:0 8px 8px}
.preview-overlay{position:fixed;inset:0;background:rgba(0,0,0,.85);z-index:1000;display:flex;align-items:center;justify-content:center;cursor:pointer}
.preview-overlay img{max-width:90vw;max-height:90vh;object-fit:contain;border-radius:4px}
.tab-bar{display:flex;gap:0;margin-bottom:16px;border-bottom:2px solid #eee}
.tab{padding:8px 16px;cursor:pointer;font-size:13px;color:#888;border-bottom:2px solid transparent;margin-bottom:-2px}
.tab.active{color:#333;border-bottom-color:#333}
</style>
</head>
<body>
<div class="container">
  <div class="top-bar">
    <div>
      <h1>🖨️ 图床管理</h1>
      <p class="subtitle">管理上传密钥和已上传的图片。</p>
    </div>
    <span class="logout" id="logoutBtn">退出登录</span>
  </div>

  <div class="stats" id="stats"></div>

  <div class="tab-bar">
    <div class="tab active" data-tab="keys">🔑 上传密钥</div>
    <div class="tab" data-tab="images">🖼️ 图片管理</div>
  </div>

  <div id="tabKeys">
    <div class="card">
      <h2>上传密钥</h2>
      <div class="input-row">
        <input type="text" id="noteInput" placeholder="备注（可选，如：给小明的密钥）">
        <button class="btn btn-primary" id="genBtn">生成新密钥</button>
      </div>
      <ul class="key-list" id="keyList"></ul>
      <div class="empty" id="keyEmpty">暂无密钥，点击上方按钮生成</div>
    </div>
    <div class="card">
      <h2>📋 客户端配置</h2>
      <div class="server-url"><?= htmlspecialchars($base) ?></div>
      <p style="font-size:12px;color:#888">在 WeChat Printer → 设置 → 图床设置 → 选择「CloudFlare ImgBed」，站点地址填上方地址，Token 填你的密钥。</p>
    </div>
  </div>

  <div id="tabImages" style="display:none">
    <div class="card">
      <h2>已上传图片 <span id="imgCount" style="font-weight:normal;color:#888;font-size:13px"></span></h2>
      <div class="gallery" id="gallery"></div>
      <div class="empty" id="imgEmpty">暂无图片</div>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script type="text/javascript">
(function(){
  var self=<?=json_encode($self)?>,base=<?=json_encode($base)?>;

  function toast(m,t){var e=document.getElementById('toast');e.textContent=m;e.className='toast '+(t||'error');e.classList.add('show');setTimeout(function(){e.classList.remove('show')},3000)}
  function api(p,o){return fetch(self+'?_route='+encodeURIComponent(p),o||{})}

  // Tab switching
  document.querySelectorAll('.tab').forEach(function(tab){
    tab.addEventListener('click',function(){
      document.querySelectorAll('.tab').forEach(function(t){t.classList.remove('active')});
      tab.classList.add('active');
      document.getElementById('tabKeys').style.display=tab.dataset.tab==='keys'?'':'none';
      document.getElementById('tabImages').style.display=tab.dataset.tab==='images'?'':'none';
      if(tab.dataset.tab==='images') loadImages();
    });
  });

  document.getElementById('logoutBtn').addEventListener('click',function(){api('/api/logout',{method:'POST'}).then(function(){location.reload()})});
  document.getElementById('genBtn').addEventListener('click',generateKey);
  document.getElementById('noteInput').addEventListener('keydown',function(e){if(e.key==='Enter')generateKey()});

  function fmtSize(b){if(b<1024)return b+'B';if(b<1048576)return(b/1024).toFixed(1)+'KB';return(b/1048576).toFixed(1)+'MB'}

  async function loadKeys(){
    var r=await api('/api/keys');if(r.status===401){location.reload();return}
    var d=await r.json(),list=document.getElementById('keyList'),empty=document.getElementById('keyEmpty'),stats=document.getElementById('stats');
    if(!d.keys.length){list.innerHTML='';empty.style.display='block';stats.innerHTML='';return}
    empty.style.display='none';
    stats.innerHTML='<span>共 '+d.keys.length+' 个密钥</span><span>'+(d.fileCount||0)+' 张图片</span>';
    list.innerHTML=d.keys.map(function(k){
      return '<li><div style="flex:1;margin-right:12px"><div class="key-value">'+k.key+'</div><div class="key-meta">'+(k.note?k.note+' · ':'')+'创建于 '+new Date(k.createdAt).toLocaleString('zh-CN')+'</div></div><button class="btn btn-sm" data-copy="'+k.key+'">复制</button><button class="btn btn-danger btn-sm" data-del="'+k.key+'" style="margin-left:4px">删除</button></li>'
    }).join('');
    list.querySelectorAll('[data-copy]').forEach(function(b){b.addEventListener('click',function(){navigator.clipboard.writeText(b.getAttribute('data-copy')).then(function(){toast('已复制','success')})})});
    list.querySelectorAll('[data-del]').forEach(function(b){b.addEventListener('click',function(){if(!confirm('确定删除此密钥？'))return;api('/api/keys/'+b.getAttribute('data-del'),{method:'DELETE'}).then(function(){toast('已删除','success');loadKeys()})})});
  }

  async function generateKey(){
    var n=document.getElementById('noteInput').value.trim();
    var r=await api('/api/keys',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({note:n})});
    var d=await r.json();if(d.key){document.getElementById('noteInput').value='';toast('密钥已生成','success');loadKeys()}
  }

  async function loadImages(){
    var r=await api('/api/images');if(r.status===401){location.reload();return}
    var d=await r.json(),g=document.getElementById('gallery'),empty=document.getElementById('imgEmpty'),cnt=document.getElementById('imgCount');
    if(!d.images.length){g.innerHTML='';empty.style.display='block';cnt.textContent='';return}
    empty.style.display='none';
    cnt.textContent='('+d.images.length+' 张)';
    g.innerHTML=d.images.map(function(img){
      var url=base+'/images/'+img.filename;
      return '<div class="gallery-item" data-file="'+img.filename+'">'+
        '<img src="'+url+'" loading="lazy" onclick="window._preview(this.src)">'+
        '<div class="gallery-info"><div class="name">'+img.filename+'</div><div class="meta"><span>'+fmtSize(img.size)+'</span><span>'+new Date(img.time*1000).toLocaleDateString('zh-CN')+'</span></div></div>'+
        '<div class="gallery-actions"><button class="btn btn-sm" data-copy-url="'+url+'">复制链接</button><button class="btn btn-danger btn-sm" data-del-img="'+img.filename+'">删除</button></div></div>'
    }).join('');
    g.querySelectorAll('[data-copy-url]').forEach(function(b){b.addEventListener('click',function(){navigator.clipboard.writeText(b.getAttribute('data-copy-url')).then(function(){toast('链接已复制','success')})})});
    g.querySelectorAll('[data-del-img]').forEach(function(b){b.addEventListener('click',function(){
      var f=b.getAttribute('data-del-img');
      if(!confirm('确定删除 '+f+'？'))return;
      api('/api/images/'+f,{method:'DELETE'}).then(function(r){return r.json()}).then(function(d){
        if(d.ok){toast('已删除','success');loadImages();loadKeys()}
        else toast(d.error||'删除失败','error')
      })
    })});
  }

  // Image preview
  window._preview=function(src){
    var ov=document.createElement('div');ov.className='preview-overlay';
    var img=document.createElement('img');img.src=src;
    ov.appendChild(img);ov.addEventListener('click',function(){ov.remove()});
    document.body.appendChild(ov);
  };

  loadKeys();
})();
</script>
</body>
</html>
<?php
}
