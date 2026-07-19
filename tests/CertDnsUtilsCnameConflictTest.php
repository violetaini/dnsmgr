<?php

require_once __DIR__ . '/../app/utils/CertDnsUtils.php';

use app\utils\CertDnsUtils;

class FakeDns
{
    public $deleted = [];
    public $deleteResult = true;
    public $error = 'provider error';

    public function deleteDomainRecord($recordId)
    {
        $this->deleted[] = $recordId;
        return $this->deleteResult;
    }

    public function getError()
    {
        return $this->error;
    }
}

function assertSameValue($expected, $actual, $message)
{
    if ($expected !== $actual) {
        throw new RuntimeException($message . '\nExpected: ' . var_export($expected, true) . '\nActual: ' . var_export($actual, true));
    }
}

function invokeRemoveCnameConflicts($records, $row, $dns, $domain, &$logs)
{
    $method = new ReflectionMethod(CertDnsUtils::class, 'removeCnameConflicts');
    $method->setAccessible(true);
    return $method->invoke(null, $records, $row, $dns, $domain, function ($message) use (&$logs) {
        $logs[] = $message;
    });
}

$tests = [];

$tests['removes exact FQDN CNAME for root ACME TXT'] = function () {
    $dns = new FakeDns();
    $logs = [];
    $records = [
        ['Name' => '_acme-challenge.example.com.', 'Type' => 'CNAME', 'RecordId' => 'cname-1'],
        ['Name' => '_acme-challenge.example.com.', 'Type' => 'TXT', 'RecordId' => 'txt-1'],
    ];

    $result = invokeRemoveCnameConflicts(
        $records,
        ['name' => '_acme-challenge', 'type' => 'TXT'],
        $dns,
        '_acme-challenge.example.com',
        $logs
    );

    assertSameValue(['cname-1'], $dns->deleted, 'The conflicting CNAME should be deleted.');
    assertSameValue([1 => $records[1]], $result, 'Non-CNAME records should remain untouched.');
    assertSameValue(['Delete conflicting DNS Record: _acme-challenge.example.com CNAME'], $logs, 'Deletion should be logged.');
};

$tests['removes exact relative CNAME for nested ACME TXT'] = function () {
    $dns = new FakeDns();
    $logs = [];
    $records = [
        ['Name' => '_ACME-CHALLENGE.WWW.', 'Type' => 'cname', 'RecordId' => 'cname-2'],
    ];

    $result = invokeRemoveCnameConflicts(
        $records,
        ['name' => '_acme-challenge.www', 'type' => 'txt'],
        $dns,
        '_acme-challenge.www.example.com',
        $logs
    );

    assertSameValue(['cname-2'], $dns->deleted, 'Matching should be case-insensitive and ignore trailing dots.');
    assertSameValue([], $result, 'The matching CNAME should be removed from the cached list.');
};

$tests['keeps a different CNAME name'] = function () {
    $dns = new FakeDns();
    $logs = [];
    $records = [
        ['Name' => '_acme-challenge-other.example.com.', 'Type' => 'CNAME', 'RecordId' => 'cname-3'],
    ];

    $result = invokeRemoveCnameConflicts(
        $records,
        ['name' => '_acme-challenge', 'type' => 'TXT'],
        $dns,
        '_acme-challenge.example.com',
        $logs
    );

    assertSameValue([], $dns->deleted, 'A non-exact CNAME must not be deleted.');
    assertSameValue($records, $result, 'A non-exact CNAME should remain.');
};

$tests['does not act outside ACME names'] = function () {
    $dns = new FakeDns();
    $logs = [];
    $records = [
        ['Name' => 'verification.example.com.', 'Type' => 'CNAME', 'RecordId' => 'cname-4'],
    ];

    $result = invokeRemoveCnameConflicts(
        $records,
        ['name' => 'verification', 'type' => 'TXT'],
        $dns,
        'verification.example.com',
        $logs
    );

    assertSameValue([], $dns->deleted, 'Non-ACME records must not be deleted.');
    assertSameValue($records, $result, 'Non-ACME records should remain.');
};

$tests['does not act for non-TXT writes'] = function () {
    $dns = new FakeDns();
    $logs = [];
    $records = [
        ['Name' => '_acme-challenge.example.com.', 'Type' => 'CNAME', 'RecordId' => 'cname-5'],
    ];

    $result = invokeRemoveCnameConflicts(
        $records,
        ['name' => '_acme-challenge', 'type' => 'CAA'],
        $dns,
        '_acme-challenge.example.com',
        $logs
    );

    assertSameValue([], $dns->deleted, 'Only ACME TXT writes may remove a conflict.');
    assertSameValue($records, $result, 'The CNAME should remain for non-TXT writes.');
};

$tests['throws when provider deletion fails'] = function () {
    $dns = new FakeDns();
    $dns->deleteResult = false;
    $logs = [];
    $records = [
        ['Name' => '_acme-challenge.example.com.', 'Type' => 'CNAME', 'RecordId' => 'cname-6'],
    ];

    try {
        invokeRemoveCnameConflicts(
            $records,
            ['name' => '_acme-challenge', 'type' => 'TXT'],
            $dns,
            '_acme-challenge.example.com',
            $logs
        );
    } catch (Exception $e) {
        assertSameValue(
            '删除_acme-challenge.example.com冲突的CNAME解析记录失败，provider error',
            $e->getMessage(),
            'The provider error should be surfaced.'
        );
        return;
    }

    throw new RuntimeException('Expected a deletion failure exception.');
};

$passed = 0;
foreach ($tests as $name => $test) {
    $test();
    $passed++;
    echo "PASS: {$name}\n";
}

echo "{$passed}/" . count($tests) . " tests passed\n";
