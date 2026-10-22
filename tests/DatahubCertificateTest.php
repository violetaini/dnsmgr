<?php
declare(strict_types=1);

namespace app { class BaseController {} }
namespace think\facade {
    class Db {
        public static array $row=['id'=>9,'status'=>3,'fullchain'=>'fixture-certificate','privatekey'=>'fixture-key','issuetime'=>'fixture','expiretime'=>'fixture'];
        public static function name($table) { return new class {
            public function where(...$args) { return $this; }
            public function whereIn(...$args) { return $this; }
            public function field(...$args) { return $this; }
            public function order(...$args) { return $this; }
            public function column(...$args) { return ['*.example.com']; }
            public function select() { return []; }
            public function find() { return Db::$row; }
        }; }
    }
}
namespace {
require __DIR__.'/../app/controller/DatahubCertificate.php';
class Result {
    public int $status=200;public array $headers=[];
    public function __construct(public array $data) {}
    public function code($v) { $this->status=$v;return $this; }
    public function header($v) { $this->headers=$v;return $this; }
}
$identity=(object)['isApi'=>true,'user'=>['id'=>7]];$orderId=9;
function request() { global $identity;return $identity; }
function input(...$args) { global $orderId;return $orderId; }
function json($data) { return new Result($data); }
$checks=0;
function expect($expected,$actual) { global $checks;$checks++;if($expected!==$actual) throw new \RuntimeException('Certificate scope regression'); }
$scope=__DIR__.'/../config/datahub-certificate-scopes.json';
if(file_exists($scope)) throw new \RuntimeException('Refusing to overwrite an existing scope configuration');
try {
    $controller=new \app\controller\DatahubCertificate();
    expect(403,$controller->order()->status);
    file_put_contents($scope,json_encode(['users'=>['7'=>[9]]]));
    $identity->isApi=false;expect(403,$controller->order()->status);expect(403,$controller->catalog()->status);
    $identity->isApi=true;$identity->user['id']=8;expect(403,$controller->order()->status);
    $identity->user['id']=7;$orderId=10;expect(403,$controller->order()->status);
    $orderId=9;$result=$controller->order();expect(200,$result->status);expect('no-store',$result->headers['Cache-Control']);expect('fixture-key',$result->data['data']['key']);
    \think\facade\Db::$row['status']=0;expect(409,$controller->order()->status);
    file_put_contents($scope,json_encode(['users'=>['7'=>['9']]]));expect(403,$controller->order()->status);
    file_put_contents($scope,json_encode(['users'=>['7'=>[]]]));expect(403,$controller->catalog()->status);
    echo "DatahubCertificate: $checks assertions passed\n";
} finally { if(file_exists($scope))unlink($scope); }
}
