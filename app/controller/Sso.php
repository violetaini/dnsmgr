<?php
declare(strict_types=1);

namespace app\controller;

use app\BaseController;
use app\lib\SsoBridge;

class Sso extends BaseController
{
    private function run(string $action)
    {
        if (!SsoBridge::configured()) return response('Not found',404);
        return (new SsoBridge())->$action($this->request);
    }

    public function start() { return $this->run('start'); }
    public function callback() { return $this->run('callback'); }
    public function account() { return $this->run('account'); }
}
