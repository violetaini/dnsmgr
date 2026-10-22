<?php
declare(strict_types=1);

namespace think\facade {
    class Db {
        public static array $user=['id'=>7,'status'=>1,'level'=>1];
        public static function name($name) { return new class($name) {
            public function __construct(public string $name) {}
            public function where(...$args) { return $this; }
            public function find() { return Db::$user; }
            public function column($name) { return ['example.com']; }
        }; }
    }
}
namespace {
require __DIR__.'/../app/lib/SsoBridge.php';
class FakeResponse {
    public array $headers=[];
    public function __construct(public string $body='', public int $status=200) {}
    public function header($headers) { $this->headers+=$headers;return $this; }
    public function code($status) { $this->status=$status;return $this; }
    public function getContent() { return $this->body; }
    public function content($body) { $this->body=$body;return $this; }
}
function response($body='', $status=200) { return new FakeResponse($body,$status); }
function json($body) { return response(json_encode($body)); }
function redirect($url) { return response('',302)->header(['Location'=>$url]); }
function view($template,$vars) { return response(json_encode(['template'=>$template]+$vars)); }
class FakeRequest {
    public bool $islogin=false;
    public $user=null;
    public bool $ssoEnabled=false;
    public string $ssoCsrfToken='';
    public function __construct(public string $path, public string $verb='GET',public array $headers=[],public array $query=[]) {}
    public function pathinfo() { return $this->path; }
    public function method() { return $this->verb; }
    public function isGet() { return $this->verb==='GET'; }
    public function isAjax() { return ($this->headers['x-requested-with']??'')==='XMLHttpRequest'; }
    public function host() { return $this->headers['host']??'dns.example.com'; }
    public function header($name,$default=null) { return $this->headers[$name]??$default; }
    public function get($name) { return $this->query[$name]??null; }
}
class Bridge extends \app\lib\SsoBridge {
    public array $ops=[];
    public int $failure=0;
    public string $subject='subject-A';
    protected function config(): array { return ['origin'=>'https://dns.example.com','key'=>str_repeat('k',48),'bindings'=>['subject-A'=>7],'accountUrl'=>'https://identity.example.com/portal']; }
    protected function rpc(string $op,$request,array $c,array $extra=[]): array {
        $this->ops[]=$op;
        if($this->failure) throw new \RuntimeException('Unavailable',$this->failure);
        return ['subject'=>$this->subject,'roles'=>['admin'],'csrfToken'=>'csrf','location'=>'https://identity.example.com/oauth/authorize','redirect_to'=>'https://identity.example.com/oauth/logout'];
    }
}
$count=0;
function same($expected,$actual,$message) { global $count;$count++;if($expected!==$actual)throw new \RuntimeException($message); }
$next=fn($r)=>response('<html><head></head><body>DNS</body></html>');
foreach(['/api/record/update/1','/cron','/dmtask/status','/optimizeip/status','/qqbot/webhook'] as $p) {
    $b=new Bridge();$b->failure=503;$r=$b->handle(new FakeRequest($p,'POST'),$next);
    same(200,$r->status,'Machine authentication must stay upstream');same([],$b->ops,'No identity RPC for machine tasks');
}
foreach(['/api','/api-evil','/api/../user','/user'] as $p) {
    same(false,\app\lib\SsoBridge::machinePath($p),'API prefix boundary');
}
foreach(['/quicklogin','/install','/auth/totp','/verifycode'] as $p) same(410,(new Bridge())->handle(new FakeRequest($p),$next)->status,'Legacy login must be disabled');
same(410,(new Bridge())->login(new FakeRequest('/login','POST'))->status,'Password POST disabled');
$b=new Bridge();$r=$b->login(new FakeRequest('/login'));same(302,$r->status,'Login automatically redirects');same('https://identity.example.com/oauth/authorize',$r->headers['Location'],'No intermediate login button');
$r=(new Bridge())->start(new FakeRequest('/sso/start'));same('https://identity.example.com/oauth/authorize',$r->headers['Location'],'OIDC start');
$r=(new Bridge())->callback(new FakeRequest('/sso/callback','POST'));same(405,$r->status,'Callback GET only');
$b=new Bridge();$r=$b->login(new FakeRequest('/login','GET',[],['loggedout'=>'1']));same(200,$r->status,'Logout landing never automatically signs in');same([],$b->ops,'No OAuth restart after logout');same('auth/sso',json_decode($r->body,true)['template'],'Native template renders logout landing');
$r=(new Bridge())->callback(new FakeRequest('/sso/callback','GET',[],['loggedout'=>'1']));same('/login?loggedout=1',$r->headers['Location'],'Logout callback preserves signed-out state');
foreach(['/login','/sso/start','/sso/callback'] as $p){$b=new Bridge();$b->handle(new FakeRequest($p),$next);same([],$b->ops,'Native controller handles public auth route');}
$b=new Bridge();$b->failure=401;$r=$b->handle(new FakeRequest('/user'),$next);same('/login',$r->headers['Location'],'Invalid session redirects');
$r=$b->handle(new FakeRequest('/user/op','POST'),$next);same(401,$r->status,'Writes never redirect or fall back');
$b=new Bridge();$b->failure=503;same(503,$b->handle(new FakeRequest('/'),$next)->status,'Identity outage fails closed');
$b=new Bridge();$b->subject='other';same(403,$b->handle(new FakeRequest('/'),$next)->status,'No automatic username mapping');
\think\facade\Db::$user['status']=0;same(403,(new Bridge())->handle(new FakeRequest('/'),$next)->status,'Disabled local users stay disabled');\think\facade\Db::$user['status']=1;
$req=new FakeRequest('/');$r=(new Bridge())->handle($req,$next);same(true,$req->islogin,'Verified identity');same(['example.com'],$req->user['permission'],'Existing domain permissions');same('csrf',$req->ssoCsrfToken,'CSRF passed directly to native template');same('<html><head></head><body>DNS</body></html>',$r->body,'Middleware does not rewrite rendered HTML');
same(400,(new Bridge())->handle(new FakeRequest('/','GET',['host'=>'evil.example']),$next)->status,'Host mismatch');
same(403,(new Bridge())->handle(new FakeRequest('/cleancache','GET',['sec-fetch-site'=>'cross-site']),$next)->status,'Cross-site stateful GET blocked');
$req=new FakeRequest('/logout');$req->ssoCsrfToken='csrf';$r=(new Bridge())->logout($req);same(200,$r->status,'Legacy GET logout confirmation');same('csrf',json_decode($r->body,true)['ssoLogoutCsrf'],'Confirmation receives current CSRF');same('same-origin',$r->headers['Referrer-Policy'],'Form Origin must not become null in Chromium');
$r=(new Bridge())->account(new FakeRequest('/sso/account'));same('https://identity.example.com/portal',$r->headers['Location'],'Passwords managed centrally');
$r=(new Bridge())->account(new FakeRequest('/setpwd','POST'));same(410,$r->status,'Native password writes disabled');
foreach([['subject'=>'subject-A','roles'=>[]],['subject'=>'other','roles'=>['root']]] as $profile) {try{\app\lib\SsoBridge::mappedUserId($profile,['subject-A'=>7]);throw new \Exception('Unexpected grant');}catch(\RuntimeException $e){same(403,$e->getCode(),'Explicit binding and role required');}}
echo "SsoBridge: $count assertions passed\n";
}
