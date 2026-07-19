<?php

namespace app\utils;

use UnexpectedValueException;

class UpdateUtils
{
    public static function parseRelease(array $release, string $currentVersion): array
    {
        $currentVersion = self::normalizeVersion($currentVersion);
        $latestVersion = self::normalizeVersion($release['tag_name'] ?? '');
        $releaseUrl = self::requireGithubUrl($release['html_url'] ?? '');
        $downloadUrl = $releaseUrl;
        $expectedAsset = 'dnsmgr_' . $latestVersion . '.zip';

        if (isset($release['assets']) && is_array($release['assets'])) {
            foreach ($release['assets'] as $asset) {
                if (!is_array($asset) || ($asset['name'] ?? '') !== $expectedAsset) {
                    continue;
                }
                $downloadUrl = self::requireGithubUrl($asset['browser_download_url'] ?? '');
                break;
            }
        }

        return [
            'current_version' => $currentVersion,
            'latest_version' => $latestVersion,
            'update_available' => version_compare($latestVersion, $currentVersion, '>'),
            'release_url' => $releaseUrl,
            'download_url' => $downloadUrl,
        ];
    }

    private static function normalizeVersion(string $version): string
    {
        $version = preg_replace('/^[vV]/', '', trim($version));
        if (!preg_match('/^\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$/', $version)) {
            throw new UnexpectedValueException('Release version is invalid');
        }
        return $version;
    }

    private static function requireGithubUrl(string $url): string
    {
        $parts = parse_url($url);
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || ($parts['host'] ?? '') !== 'github.com') {
            throw new UnexpectedValueException('Release URL is invalid');
        }
        return $url;
    }
}
