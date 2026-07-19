<?php

require_once __DIR__ . '/../app/utils/UpdateUtils.php';

use app\utils\UpdateUtils;

function assertUpdateSame($expected, $actual, $message)
{
    if ($expected !== $actual) {
        throw new RuntimeException($message . '\nExpected: ' . var_export($expected, true) . '\nActual: ' . var_export($actual, true));
    }
}

$tests = [];

$tests['reports the current release as up to date'] = function () {
    $result = UpdateUtils::parseRelease([
        'tag_name' => '2.18.1001',
        'html_url' => 'https://github.com/violetaini/dnsmgr/releases/tag/2.18.1001',
        'assets' => [[
            'name' => 'dnsmgr_2.18.1001.zip',
            'browser_download_url' => 'https://github.com/violetaini/dnsmgr/releases/download/2.18.1001/dnsmgr_2.18.1001.zip',
        ]],
    ], '2.18.1001');

    assertUpdateSame(false, $result['update_available'], 'Equal versions must not report an update.');
    assertUpdateSame('2.18.1001', $result['latest_version'], 'The latest version should be normalized.');
    assertUpdateSame(
        'https://github.com/violetaini/dnsmgr/releases/download/2.18.1001/dnsmgr_2.18.1001.zip',
        $result['download_url'],
        'The matching package should be selected.'
    );
};

$tests['accepts a leading v and reports a newer release'] = function () {
    $result = UpdateUtils::parseRelease([
        'tag_name' => 'v2.18.1002',
        'html_url' => 'https://github.com/violetaini/dnsmgr/releases/tag/2.18.1002',
        'assets' => [],
    ], '2.18.1001');

    assertUpdateSame(true, $result['update_available'], 'A newer patch version should report an update.');
    assertUpdateSame('2.18.1002', $result['latest_version'], 'A leading v should be removed.');
    assertUpdateSame($result['release_url'], $result['download_url'], 'The release page should be used when no package exists.');
};

$tests['does not downgrade to an older release'] = function () {
    $result = UpdateUtils::parseRelease([
        'tag_name' => '2.18.1000',
        'html_url' => 'https://github.com/violetaini/dnsmgr/releases/tag/2.18.1000',
    ], '2.18.1001');

    assertUpdateSame(false, $result['update_available'], 'An older release must not report an update.');
};

$tests['ignores a package with the wrong name'] = function () {
    $result = UpdateUtils::parseRelease([
        'tag_name' => '2.18.1002',
        'html_url' => 'https://github.com/violetaini/dnsmgr/releases/tag/2.18.1002',
        'assets' => [[
            'name' => 'source.zip',
            'browser_download_url' => 'https://github.com/violetaini/dnsmgr/releases/download/2.18.1002/source.zip',
        ]],
    ], '2.18.1001');

    assertUpdateSame($result['release_url'], $result['download_url'], 'Only the expected package name should be selected.');
};

$tests['rejects an invalid release version'] = function () {
    try {
        UpdateUtils::parseRelease([
            'tag_name' => 'latest',
            'html_url' => 'https://github.com/violetaini/dnsmgr/releases/latest',
        ], '2.18.1001');
    } catch (UnexpectedValueException $e) {
        return;
    }
    throw new RuntimeException('Expected an invalid version exception.');
};

$tests['rejects a non-GitHub download URL'] = function () {
    try {
        UpdateUtils::parseRelease([
            'tag_name' => '2.18.1002',
            'html_url' => 'https://github.com/violetaini/dnsmgr/releases/tag/2.18.1002',
            'assets' => [[
                'name' => 'dnsmgr_2.18.1002.zip',
                'browser_download_url' => 'https://example.com/dnsmgr_2.18.1002.zip',
            ]],
        ], '2.18.1001');
    } catch (UnexpectedValueException $e) {
        return;
    }
    throw new RuntimeException('Expected an invalid URL exception.');
};

$passed = 0;
foreach ($tests as $name => $test) {
    $test();
    $passed++;
    echo "PASS: {$name}\n";
}

echo "{$passed}/" . count($tests) . " tests passed\n";
