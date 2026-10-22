<?php
declare(strict_types=1);

namespace app\lib;

use think\facade\Db;

/** Optional loopback identity-agent adapter. Never accepts a browser identity header. */
class SsoBridge
{
    public static function configured(): bool
    {
        return is_file(app()->getRootPath().'.sso.json') || is_file(app()->getRootPath().'.sso-required');
    }

    public static function machinePath(string $path): bool
    {
        // These routes retain their own upstream signed API / task authentication.
        if (str_contains($path, '%') || str_contains($path, '\\') || preg_match('~(?:^|/)\.{1,2}(?:/|$)~', $path)) return false;
        return str_starts_with($path, '/api/') || in_array($path, ['/cron', '/dmtask/status', '/optimizeip/status', '/qqbot/webhook'], true);
    }

    public static function mappedUserId(array $profile, array $bindings): int
    {
        $sub = $profile['subject'] ?? '';
        $roles = $profile['roles'] ?? [];
        if (!is_string($sub) || !isset($bindings[$sub]) || !is_array($roles) || !array_intersect(['admin', 'root'], $roles)) {
            throw new \RuntimeException('Forbidden', 403);
        }
        $id = $bindings[$sub];
        if (!is_int($id) || $id < 1) throw new \RuntimeException('Invalid identity binding', 503);
        return $id;
    }

    protected function config(): array
    {
        $raw = @file_get_contents(app()->getRootPath().'.sso.json');
        $c = is_string($raw) ? json_decode($raw, true) : null;
        if (!is_array($c) || !preg_match('~^https://[a-z0-9.-]+$~D', $c['origin'] ?? '') ||
            !is_string($c['key'] ?? null) || strlen($c['key']) < 32 || empty($c['bindings']) ||
            !preg_match('~^https://[a-z0-9.-]+/portal$~D', $c['accountUrl'] ?? '')) {
            throw new \RuntimeException('SSO configuration unavailable', 503);
        }
        return $c;
    }

    protected function rpc(string $op, $request, array $c, array $extra=[]): array
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        if (!filter_var($ip, FILTER_VALIDATE_IP)) throw new \RuntimeException('Invalid source', 400);
        $body = array_merge([
            'ip'=>$ip, 'cookie'=>$_SERVER['HTTP_COOKIE'] ?? '', 'method'=>$request->method(),
            'origin'=>$request->header('origin', ''),
            'csrf'=>$request->header('x-csrf-token', '') ?: ($_POST['_sso_csrf'] ?? ''),
        ], $extra);
        $ch = curl_init('http://127.0.0.1:9788/dns/'.$op);
        curl_setopt_array($ch, [CURLOPT_POST=>true, CURLOPT_POSTFIELDS=>json_encode($body, JSON_THROW_ON_ERROR),
            CURLOPT_HTTPHEADER=>['Content-Type: application/json', 'Authorization: Bearer '.$c['key']],
            CURLOPT_RETURNTRANSFER=>true, CURLOPT_FOLLOWLOCATION=>false, CURLOPT_PROXY=>'',
            CURLOPT_CONNECTTIMEOUT=>2, CURLOPT_TIMEOUT=>15, CURLOPT_PROTOCOLS=>CURLPROTO_HTTP]);
        $raw = curl_exec($ch); $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE); curl_close($ch);
        $result = is_string($raw) ? json_decode($raw, true) : null;
        if ($status !== 200 || !is_array($result)) {
            throw new \RuntimeException('Identity verification failed', in_array($status,[400,401,403,405,429],true) ? $status : 503);
        }
        return $result;
    }

    private function withCookies($response, array $result)
    {
        foreach ($result['cookies'] ?? [] as $cookie) {
            if (!is_string($cookie) || preg_match('/[\r\n]/', $cookie) || !str_starts_with($cookie, '__Host-chitanda_dns_')) {
                throw new \RuntimeException('Invalid identity response', 503);
            }
            header('Set-Cookie: '.$cookie, false);
        }
        return $response;
    }

    private function page(string $title, string $body, int $status=200)
    {
        $title=htmlspecialchars($title, ENT_QUOTES, 'UTF-8');
        return response('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'.$title.'</title><style>body{background:#faf7f2;color:#51445f;font:18px "Times New Roman","STKaiti",serif;display:grid;place-items:center;min-height:90vh;margin:0}main{padding:48px;border:1px solid #e5d9ed;border-radius:24px;background:#fffcf8;max-width:420px}h1{font-size:26px}a,button{color:#75628a}button,a.action{display:inline-flex;gap:12px;align-items:center;background:#9582a5;border:0;border-radius:12px;color:white;padding:14px 24px;font:inherit;text-decoration:none;cursor:pointer}svg{width:24px;height:24px}p{line-height:1.8}</style><main><h1>'.$title.'</h1>'.$body.'</main></html>', $status)->header(['Content-Type'=>'text/html; charset=utf-8','Cache-Control'=>'no-store','Referrer-Policy'=>'same-origin','X-Frame-Options'=>'DENY']);
    }

    public function handle($request, \Closure $next)
    {
        $request->islogin=false; $request->user=null;
        // Use ThinkPHP's routed PATH_INFO (including index.php?s=...), not raw REQUEST_URI.
        $path='/'.trim(strtolower($request->pathinfo()), '/');
        try {
            if (self::machinePath($path)) return $next($request);
            $c=$this->config();
            if (strtolower($request->host()) !== parse_url($c['origin'], PHP_URL_HOST)) return response('Invalid host',400);
            if (in_array($path,['/quicklogin','/install','/auth/totp','/verifycode'],true)) return json(['code'=>-1,'msg'=>'请使用统一账号登录'])->code(410);
            if (in_array($path,['/login','/sso/start'],true)) {
                if (!$request->isGet()) return json(['code'=>-1,'msg'=>'请使用统一账号登录'])->code(410);
                if ($path==='/login' || $request->get('loggedout')==='1') {
                    return $this->page('DNS 管理系统', '<p>使用 Chitanda 统一账号登录，原有域名与证书权限保留。</p><a class="action" href="/sso/start"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M12 3 3 7.5 12 12l9-4.5L12 3ZM3 12l9 4.5 9-4.5M3 16.5l9 4.5 9-4.5"/></svg>Chitanda 统一登录</a>');
                }
                $r=$this->rpc('start',$request,$c);
                return $this->withCookies(redirect($r['location']),$r);
            }
            if ($path==='/sso/callback') {
                if (!$request->isGet()) return response('Method not allowed',405);
                if ($request->get('loggedout')==='1') return redirect('/login');
                $r=$this->rpc('callback',$request,$c,['query'=>$_SERVER['QUERY_STRING'] ?? '']);
                return $this->withCookies(redirect('/'),$r);
            }
            // Cross-site GETs cannot trigger the upstream's few state-changing GET handlers.
            if ($path!=='/' && in_array($request->header('sec-fetch-site'),['cross-site','same-site'],true)) return response('Invalid request source',403);
            $profile=$this->rpc('validate',$request,$c);
            $user=Db::name('user')->where('id',self::mappedUserId($profile,$c['bindings']))->find();
            if (!$user || (int)$user['status']!==1) throw new \RuntimeException('Account unavailable',403);
            $user['type']='user'; $user['permission']=[];
            if ((int)$user['level']===1) $user['permission']=Db::name('permission')->where('uid',$user['id'])->column('domain');
            $request->user=$user; $request->islogin=true;
            if ($path==='/logout') {
                if ($request->isGet()) return $this->page('退出登录','<p>退出 Chitanda 统一账号及关联的管理会话。</p><form method="post" action="/logout"><input type="hidden" name="_sso_csrf" value="'.htmlspecialchars($profile['csrfToken'],ENT_QUOTES,'UTF-8').'"><button>确认退出</button></form>');
                $r=$this->rpc('logout',$request,$c);
                return $this->withCookies(redirect($r['redirect_to']),$r);
            }
            if (in_array($path,['/setpwd','/sso/account'],true) || str_starts_with($path,'/totp/')) {
                return $request->isGet() ? redirect($c['accountUrl']) : json(['code'=>-1,'msg'=>'请在统一账号中心管理密码和两步验证'])->code(410);
            }
            $response=$next($request);
            $content=$response->getContent();
            if (is_string($content) && stripos($content,'</head>')!==false) {
                $response->content(str_ireplace('</head>','<script src="/static/js/sso-bridge.js?v=1"></script></head>',$content));
            }
            return $response->header(['Cache-Control'=>'no-store','X-Frame-Options'=>'SAMEORIGIN','Referrer-Policy'=>'same-origin']);
        } catch (\RuntimeException $e) {
            $status=in_array($e->getCode(),[400,401,403,405,429,503],true)?$e->getCode():503;
            if ($status===401 && $request->isGet() && !$request->isAjax()) return redirect('/login');
            if ($request->isAjax() || !$request->isGet()) return json(['code'=>-1,'msg'=>$status===401?'请重新统一登录':'统一身份验证未通过，请稍后重试'])->code($status);
            return $this->page('暂时无法进入', '<p>统一身份验证未通过，或此账号尚未获准访问。</p><a href="/login">返回登录</a>', $status);
        }
    }
}
