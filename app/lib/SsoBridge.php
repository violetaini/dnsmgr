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

    private function page(string $title, string $message, int $status=200, string $csrf='')
    {
        return view('auth/sso', ['ssoTitle'=>$title, 'ssoMessage'=>$message, 'ssoLogoutCsrf'=>$csrf])
            ->code($status)->header(['Cache-Control'=>'no-store','Referrer-Policy'=>'same-origin','X-Frame-Options'=>'DENY']);
    }

    private function respond($request, \Closure $operation)
    {
        try {
            return $operation()->header(['Cache-Control'=>'no-store','Referrer-Policy'=>'same-origin']);
        } catch (\RuntimeException $e) {
            $status=in_array($e->getCode(),[400,401,403,405,429,503],true)?$e->getCode():503;
            if ($status===401 && $request->isGet() && !$request->isAjax()) return redirect('/login');
            if ($request->isAjax() || !$request->isGet()) return json(['code'=>-1,'msg'=>$status===401?'请重新统一登录':'统一身份验证未通过，请稍后重试'])->code($status);
            return $this->page('暂时无法进入', '统一身份验证未通过，或此账号尚未获准访问。', $status);
        }
    }

    public function login($request)
    {
        if (!$request->isGet()) return json(['code'=>-1,'msg'=>'请使用统一账号登录'])->code(410);
        if ($request->get('loggedout')==='1') return $this->page('已退出登录', '你已退出统一账号。需要继续管理时，可重新登录。');
        return $this->start($request);
    }

    public function start($request)
    {
        return $this->respond($request,function() use ($request) {
            if (!$request->isGet()) return response('Method not allowed',405);
            $r=$this->rpc('start',$request,$this->config());
            return $this->withCookies(redirect($r['location']),$r);
        });
    }

    public function callback($request)
    {
        return $this->respond($request,function() use ($request) {
            if (!$request->isGet()) return response('Method not allowed',405);
            if ($request->get('loggedout')==='1') return redirect('/login?loggedout=1');
            $r=$this->rpc('callback',$request,$this->config(),['query'=>$_SERVER['QUERY_STRING'] ?? '']);
            return $this->withCookies(redirect('/'),$r);
        });
    }

    public function logout($request)
    {
        return $this->respond($request,function() use ($request) {
            if ($request->isGet()) return $this->page('退出登录','退出 Chitanda 统一账号及关联的管理会话。',200,$request->ssoCsrfToken);
            $r=$this->rpc('logout',$request,$this->config());
            return $this->withCookies(redirect($r['redirect_to']),$r);
        });
    }

    public function account($request)
    {
        return $this->respond($request,function() use ($request) {
            return $request->isGet() ? redirect($this->config()['accountUrl']) : json(['code'=>-1,'msg'=>'请在统一账号中心管理密码和两步验证'])->code(410);
        });
    }

    public function handle($request, \Closure $next)
    {
        $request->islogin=false; $request->user=null;
        $request->ssoEnabled=true; $request->ssoCsrfToken='';
        // Use ThinkPHP's routed PATH_INFO (including index.php?s=...), not raw REQUEST_URI.
        $path='/'.trim(strtolower($request->pathinfo()), '/');
        return $this->respond($request,function() use ($request,$next,$path) {
            if (self::machinePath($path)) return $next($request);
            $c=$this->config();
            if (strtolower($request->host()) !== parse_url($c['origin'], PHP_URL_HOST)) return response('Invalid host',400);
            if (in_array($path,['/quicklogin','/install','/auth/totp','/verifycode'],true)) return json(['code'=>-1,'msg'=>'请使用统一账号登录'])->code(410);
            // Public authentication endpoints are implemented by native controllers.
            if (in_array($path,['/login','/sso/start','/sso/callback'],true)) return $next($request);
            // Cross-site GETs cannot trigger the upstream's few state-changing GET handlers.
            if ($path!=='/' && in_array($request->header('sec-fetch-site'),['cross-site','same-site'],true)) return response('Invalid request source',403);
            $profile=$this->rpc('validate',$request,$c);
            $user=Db::name('user')->where('id',self::mappedUserId($profile,$c['bindings']))->find();
            if (!$user || (int)$user['status']!==1) throw new \RuntimeException('Account unavailable',403);
            $user['type']='user'; $user['permission']=[];
            if ((int)$user['level']===1) $user['permission']=Db::name('permission')->where('uid',$user['id'])->column('domain');
            $request->user=$user; $request->islogin=true;
            $request->ssoCsrfToken=$profile['csrfToken'];
            return $next($request)->header(['X-Frame-Options'=>'SAMEORIGIN']);
        });
    }
}
