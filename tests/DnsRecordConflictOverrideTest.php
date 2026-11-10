<?php

if (file_exists(__DIR__ . '/../vendor/autoload.php')) {
    require_once __DIR__ . '/../vendor/autoload.php';
}
if (file_exists(__DIR__ . '/../app/common.php')) {
    require_once __DIR__ . '/../app/common.php';
}
if (!function_exists('isNullOrEmpty')) {
    function isNullOrEmpty($str)
    {
        return !isset($str) || $str === '';
    }
}
require_once __DIR__ . '/../app/lib/client/HuaweiCloud.php';
require_once __DIR__ . '/../app/lib/DnsInterface.php';
require_once __DIR__ . '/../app/lib/dns/huawei.php';
require_once __DIR__ . '/../app/lib/dns/cloudflare.php';

use app\lib\dns\huawei;
use app\lib\dns\cloudflare;
use app\lib\client\HuaweiCloud;

function assertCondition($condition, $message)
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function assertSameVal($expected, $actual, $message)
{
    if ($expected !== $actual) {
        throw new RuntimeException($message . "\nExpected: " . var_export($expected, true) . "\nActual: " . var_export($actual, true));
    }
}

class FakeHuaweiClient extends HuaweiCloud
{
    public function __construct()
    {
        parent::__construct('test-ak', 'test-sk', 'dns.myhuaweicloud.com', false);
    }

    public $requests = [];
    public $failFirstPost = false;
    public $firstPostError = "This record set name already exists. Conflicts with Record Set '_acme-challenge.api.example.com.' type 'TXT' in line 'default_view'.";
    public $postAttempts = 0;
    public $deletedRecords = [];

    public function request($method, $path, $query = null, $params = null)
    {
        $this->requests[] = ['method' => $method, 'path' => $path, 'query' => $query, 'params' => $params];
        if ($method === 'POST' && strpos($path, '/recordsets') !== false) {
            $this->postAttempts++;
            if ($this->failFirstPost && $this->postAttempts === 1) {
                throw new Exception($this->firstPostError);
            }
            return ['id' => 'new-cname-rec-id'];
        }
        if ($method === 'GET' && strpos($path, '/recordsets') !== false) {
            return [
                'metadata' => ['total_count' => 1],
                'recordsets' => [
                    [
                        'id' => 'old-txt-rec-id',
                        'name' => '_acme-challenge.api.example.com.',
                        'zone_name' => 'example.com.',
                        'type' => 'TXT',
                        'records' => ['"sample-token"'],
                        'line' => 'default_view',
                        'ttl' => 600,
                        'status' => 'ACTIVE',
                        'weight' => 1,
                        'description' => 'old txt',
                        'updated_at' => '2026-01-01T00:00:00Z',
                    ]
                ]
            ];
        }
        if ($method === 'DELETE' && strpos($path, '/recordsets/') !== false) {
            $parts = explode('/', $path);
            $recId = end($parts);
            $this->deletedRecords[] = $recId;
            return ['id' => $recId];
        }
        return [];
    }
}

class FakeCloudflareClient
{
    public $requests = [];
    public $failFirstPost = false;
    public $firstPostError = "An A, AAAA, or CNAME record with that host already exists.";
    public $postAttempts = 0;
    public $deletedRecords = [];

    public function request($method, $url, $params = null)
    {
        $this->requests[] = ['method' => $method, 'url' => $url, 'params' => $params];
        if ($method === 'POST' && strpos($url, '/dns_records') !== false) {
            $this->postAttempts++;
            if ($this->failFirstPost && $this->postAttempts === 1) {
                return ['success' => false, 'errors' => [['message' => $this->firstPostError]]];
            }
            return ['success' => true, 'result' => ['id' => 'cf-cname-rec-id']];
        }
        if ($method === 'GET' && strpos($url, '/dns_records') !== false) {
            return [
                'success' => true,
                'result_info' => ['total_count' => 1],
                'result' => [
                    [
                        'id' => 'cf-old-txt-id',
                        'name' => '_acme-challenge.img.example.com',
                        'type' => 'TXT',
                        'content' => 'cf-sample-txt',
                        'proxied' => false,
                        'ttl' => 1,
                    ]
                ]
            ];
        }
        if ($method === 'DELETE' && strpos($url, '/dns_records/') !== false) {
            $parts = explode('/', $url);
            $recId = end($parts);
            $this->deletedRecords[] = $recId;
            return ['success' => true, 'result' => ['id' => $recId]];
        }
        return ['success' => true, 'result' => []];
    }
}

function makeHuaweiTestDns(): huawei {
    return new huawei([
        'domain' => 'example.com',
        'domainid' => 'test-zone-id',
        'AccessKeyId' => 'test-ak',
        'SecretAccessKey' => 'test-sk',
    ]);
}

function makeCloudflareTestDns(): cloudflare {
    return new cloudflare([
        'domain' => 'example.org',
        'domainid' => 'cf-zone-id',
        'email' => 'user@example.com',
        'apikey' => 'api-key',
    ]);
}

$tests = [];

$tests['huawei: automatically deletes conflicting TXT when adding CNAME'] = function () {
    $dns = makeHuaweiTestDns();
    $client = new FakeHuaweiClient();
    $client->failFirstPost = true;

    $prop = new ReflectionProperty(huawei::class, 'client');
    $prop->setAccessible(true);
    $prop->setValue($dns, $client);

    $recId = $dns->addDomainRecord('_acme-challenge.api', 'CNAME', 'api.example.com.uuid.dcv.cloudflare.com', 'default_view', 600);

    assertSameVal('new-cname-rec-id', $recId, 'Should return the newly created CNAME record ID after resolving conflict');
    assertSameVal(['old-txt-rec-id'], $client->deletedRecords, 'Should have deleted the conflicting TXT record');
    assertSameVal(2, $client->postAttempts, 'Should have retried the POST request once after deleting the conflicting record');
};

$tests['huawei: normal creation without conflict succeeds directly'] = function () {
    $dns = makeHuaweiTestDns();
    $client = new FakeHuaweiClient();
    $client->failFirstPost = false;

    $prop = new ReflectionProperty(huawei::class, 'client');
    $prop->setAccessible(true);
    $prop->setValue($dns, $client);

    $recId = $dns->addDomainRecord('www', 'A', '1.1.1.1', 'default_view', 600);

    assertSameVal('new-cname-rec-id', $recId, 'Should return record ID on direct success');
    assertSameVal([], $client->deletedRecords, 'No records should be deleted on success');
    assertSameVal(1, $client->postAttempts, 'Only 1 POST attempt should be made');
};

$tests['cloudflare: automatically deletes conflicting TXT when adding CNAME'] = function () {
    $dns = makeCloudflareTestDns();
    $client = new FakeCloudflareClient();
    $client->failFirstPost = true;

    $prop = new ReflectionProperty(cloudflare::class, 'client');
    $prop->setAccessible(true);
    $prop->setValue($dns, $client);

    $recId = $dns->addDomainRecord('_acme-challenge.img', 'CNAME', 'img.example.org.uuid.dcv.cloudflare.com', '0', 600);

    assertSameVal('cf-cname-rec-id', $recId, 'Should return CF CNAME record ID after resolving conflict');
    assertSameVal(['cf-old-txt-id'], $client->deletedRecords, 'Should have deleted the conflicting CF TXT record');
    assertSameVal(2, $client->postAttempts, 'Should have retried the CF POST request');
};

$tests['cloudflare: returns existing record ID when identical CNAME already exists'] = function () {
    $dns = makeCloudflareTestDns();
    $client = new FakeCloudflareClient();
    $client->failFirstPost = true;
    $client->firstPostError = "An A, AAAA, or CNAME record with that host already exists.";

    // Mock GET to return existing CNAME with matching target
    $clientRef = new ReflectionClass($client);
    $origRequest = $clientRef->getMethod('request');

    // Subclass or anonymous class
    $customClient = new class extends FakeCloudflareClient {
        public function request($method, $url, $params = null) {
            if ($method === 'GET' && strpos($url, '/dns_records') !== false) {
                return [
                    'success' => true,
                    'result_info' => ['total_count' => 1],
                    'result' => [
                        [
                            'id' => 'existing-cname-id',
                            'name' => '_acme-challenge.status.example.org',
                            'type' => 'CNAME',
                            'content' => 'status.example.org.uuid.dcv.cloudflare.com',
                            'proxied' => false,
                            'ttl' => 600,
                        ]
                    ]
                ];
            }
            return parent::request($method, $url, $params);
        }
    };
    $customClient->failFirstPost = true;

    $prop = new ReflectionProperty(cloudflare::class, 'client');
    $prop->setAccessible(true);
    $prop->setValue($dns, $customClient);

    $recId = $dns->addDomainRecord('_acme-challenge.status', 'CNAME', 'status.example.org.uuid.dcv.cloudflare.com', '0', 600);

    assertSameVal('existing-cname-id', $recId, 'Should return existing CNAME record ID without error');
    assertSameVal([], $customClient->deletedRecords, 'Should not delete existing matching CNAME');
};

$tests['huawei: returns existing record ID when identical record already exists'] = function () {
    $dns = makeHuaweiTestDns();
    $customClient = new class extends FakeHuaweiClient {
        public function request($method, $path, $query = null, $params = null) {
            if ($method === 'GET' && strpos($path, '/recordsets') !== false) {
                return [
                    'metadata' => ['total_count' => 1],
                    'recordsets' => [
                        [
                            'id' => 'existing-hw-cname-id',
                            'name' => '_acme-challenge.status.example.com.',
                            'zone_name' => 'example.com.',
                            'type' => 'CNAME',
                            'records' => ['status.example.com.uuid.dcv.cloudflare.com.'],
                            'line' => 'default_view',
                            'ttl' => 600,
                            'status' => 'ACTIVE',
                            'weight' => 1,
                            'description' => 'Cloudflare DCV 委派',
                            'updated_at' => '2026-01-01T00:00:00Z',
                        ]
                    ]
                ];
            }
            return parent::request($method, $path, $query, $params);
        }
    };
    $customClient->failFirstPost = true;
    $customClient->firstPostError = "This record set name already exists. Conflicts with Record Set '_acme-challenge.status.example.com.' type 'CNAME' in line 'default_view'.";

    $prop = new ReflectionProperty(huawei::class, 'client');
    $prop->setAccessible(true);
    $prop->setValue($dns, $customClient);

    $recId = $dns->addDomainRecord('_acme-challenge.status', 'CNAME', 'status.example.com.uuid.dcv.cloudflare.com', 'default_view', 600);

    assertSameVal('existing-hw-cname-id', $recId, 'Should return existing Huawei CNAME record ID');
    assertSameVal([], $customClient->deletedRecords, 'Should not delete existing matching record');
};

$tests['huawei: handles Duplicate recordset exists error for existing TXT idempotently and cleans stale ACME TXT'] = function () {
    $dns = makeHuaweiTestDns();
    $customClient = new class extends FakeHuaweiClient {
        public function request($method, $path, $query = null, $params = null) {
            if ($method === 'GET' && strpos($path, '/recordsets') !== false) {
                return [
                    'metadata' => ['total_count' => 2],
                    'recordsets' => [
                        [
                            'id' => 'stale-txt-id',
                            'name' => '_acme-challenge.dns.example.com.',
                            'zone_name' => 'example.com.',
                            'type' => 'TXT',
                            'records' => ['"old-stale-token"'],
                            'line' => 'default_view',
                            'ttl' => 600,
                            'status' => 'ACTIVE',
                            'weight' => 1,
                            'description' => 'Cloudflare 证书验证',
                            'updated_at' => '2026-11-10T05:36:23Z',
                        ],
                        [
                            'id' => 'existing-dup-txt-id',
                            'name' => '_acme-challenge.dns.example.com.',
                            'zone_name' => 'example.com.',
                            'type' => 'TXT',
                            'records' => ['"u07kmfPoKRHlAtsN4x9aQqfj979rxRjoTCLmdzSVL9A"'],
                            'line' => 'default_view',
                            'ttl' => 600,
                            'status' => 'ACTIVE',
                            'weight' => 1,
                            'description' => 'Cloudflare 证书验证',
                            'updated_at' => '2026-11-10T05:38:21Z',
                        ],
                    ]
                ];
            }
            return parent::request($method, $path, $query, $params);
        }
    };
    $customClient->failFirstPost = true;
    $customClient->firstPostError = 'Duplicate recordset exists (name: _acme-challenge.dns.example.com., type: TXT, line: default_view, records: "u07kmfPoKRHlAtsN4x9aQqfj979rxRjoTCLmdzSVL9A")';

    $prop = new ReflectionProperty(huawei::class, 'client');
    $prop->setAccessible(true);
    $prop->setValue($dns, $customClient);

    $recId = $dns->addDomainRecord('_acme-challenge.dns', 'TXT', 'u07kmfPoKRHlAtsN4x9aQqfj979rxRjoTCLmdzSVL9A', 'default_view', 600, 1, null, 'Cloudflare 证书验证');

    assertSameVal('existing-dup-txt-id', $recId, 'Should return existing matching TXT ID on Duplicate recordset exists');
    assertSameVal(['stale-txt-id'], $customClient->deletedRecords, 'Should delete stale ACME TXT recordset on same line while preserving current one');
    assertSameVal(null, $dns->getError(), 'Error should be cleared on idempotent return');
};

$tests['huawei: overwrites stale Cloudflare cert verification TXT when POST succeeds alongside old recordset'] = function () {
    $dns = makeHuaweiTestDns();
    $customClient = new class extends FakeHuaweiClient {
        public function request($method, $path, $query = null, $params = null) {
            if ($method === 'GET' && strpos($path, '/recordsets') !== false) {
                return [
                    'metadata' => ['total_count' => 2],
                    'recordsets' => [
                        [
                            'id' => 'stale-txt-id',
                            'name' => '_acme-challenge.dns.example.com.',
                            'zone_name' => 'example.com.',
                            'type' => 'TXT',
                            'records' => ['"old-stale-token"'],
                            'line' => 'default_view',
                            'ttl' => 600,
                            'status' => 'ACTIVE',
                            'weight' => 1,
                            'description' => 'Cloudflare 证书验证',
                            'updated_at' => '2026-11-10T05:36:23Z',
                        ],
                        [
                            'id' => 'new-cname-rec-id',
                            'name' => '_acme-challenge.dns.example.com.',
                            'zone_name' => 'example.com.',
                            'type' => 'TXT',
                            'records' => ['"new-active-token"'],
                            'line' => 'default_view',
                            'ttl' => 600,
                            'status' => 'ACTIVE',
                            'weight' => 1,
                            'description' => 'Cloudflare 证书验证',
                            'updated_at' => '2026-11-10T05:38:21Z',
                        ],
                    ]
                ];
            }
            return parent::request($method, $path, $query, $params);
        }
    };
    $customClient->failFirstPost = false;

    $prop = new ReflectionProperty(huawei::class, 'client');
    $prop->setAccessible(true);
    $prop->setValue($dns, $customClient);

    $recId = $dns->addDomainRecord('_acme-challenge.dns', 'TXT', 'new-active-token', 'default_view', 600, 1, null, 'Cloudflare 证书验证');

    assertSameVal('new-cname-rec-id', $recId, 'Should return new TXT record ID');
    assertSameVal(['stale-txt-id'], $customClient->deletedRecords, 'Should delete stale cert TXT so weighted round-robin does not break validation');
};

$tests['huawei: isolates conflict deletion to the target line'] = function () {
    $dns = makeHuaweiTestDns();
    $customClient = new class extends FakeHuaweiClient {
        public function request($method, $path, $query = null, $params = null) {
            if ($method === 'GET' && strpos($path, '/recordsets') !== false) {
                return [
                    'metadata' => ['total_count' => 2],
                    'recordsets' => [
                        [
                            'id' => 'dianxin-txt-id',
                            'name' => '_acme-challenge.api.example.com.',
                            'zone_name' => 'example.com.',
                            'type' => 'TXT',
                            'records' => ['"dianxin-token"'],
                            'line' => 'Dianxin',
                            'ttl' => 600,
                            'status' => 'ACTIVE',
                            'weight' => 1,
                            'description' => '',
                            'updated_at' => '2026-01-01T00:00:00Z',
                        ],
                        [
                            'id' => 'default-txt-id',
                            'name' => '_acme-challenge.api.example.com.',
                            'zone_name' => 'example.com.',
                            'type' => 'TXT',
                            'records' => ['"default-token"'],
                            'line' => 'default_view',
                            'ttl' => 600,
                            'status' => 'ACTIVE',
                            'weight' => 1,
                            'description' => '',
                            'updated_at' => '2026-01-01T00:00:00Z',
                        ],
                    ]
                ];
            }
            return parent::request($method, $path, $query, $params);
        }
    };
    $customClient->failFirstPost = true;
    $customClient->firstPostError = "Conflicts with Record Set '_acme-challenge.api.example.com.' type 'TXT' in line 'default_view'.";

    $prop = new ReflectionProperty(huawei::class, 'client');
    $prop->setAccessible(true);
    $prop->setValue($dns, $customClient);

    $recId = $dns->addDomainRecord('_acme-challenge.api', 'CNAME', 'api.example.com.uuid.dcv.cloudflare.com', 'default_view', 600);

    assertSameVal('new-cname-rec-id', $recId, 'Should create CNAME after clearing only default_view conflict');
    assertSameVal(['default-txt-id'], $customClient->deletedRecords, 'Should delete only default_view conflict and keep Dianxin intact');
};

$passed = 0;
foreach ($tests as $name => $test) {
    $test();
    $passed++;
    echo "PASS: {$name}\n";
}

echo "{$passed}/" . count($tests) . " tests passed\n";
