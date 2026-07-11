<?php
/**
 * Spotify Token Generator - PHP Version
 * Yalnızca eğitim amaçlıdır.
 */

header('Content-Type: application/json');

// ─── Sabitler ───────────────────────────────────────────────────────────────
define('USER_AGENT', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36');
define('TOKEN_URL',       'https://open.spotify.com/api/token');
define('SERVER_TIME_URL', 'https://open.spotify.com/api/server-time');
define('SECRETS_URL',     'https://raw.githubusercontent.com/newaxd/babapro/refs/heads/main/secrets/secretDict.json?raw=true');
define('SPOTIFY_URL',     'https://open.spotify.com/');

// ─── HTTP yardımcısı ────────────────────────────────────────────────────────
function httpGet(string $url, array $params = []): array {
    if ($params) {
        $url .= '?' . http_build_query($params);
    }

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_HTTPHEADER     => [
            'User-Agent: ' . USER_AGENT,
            'Accept: application/json',
            'Referer: https://open.spotify.com/',
            'Origin: https://open.spotify.com',
        ],
    ]);

    $body   = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($body === false || $status < 200 || $status > 299) {
        throw new RuntimeException("HTTP isteği başarısız: $status — $url");
    }

    return ['status' => $status, 'body' => $body];
}

// ─── Sunucu zamanı ──────────────────────────────────────────────────────────
function getServerTimestamp(): int {
    $res  = httpGet(SERVER_TIME_URL);
    $data = json_decode($res['body'], true);

    if (!isset($data['serverTime'])) {
        throw new RuntimeException('serverTime alınamadı.');
    }

    return (int) $data['serverTime'];
}

// ─── Gizli anahtar ──────────────────────────────────────────────────────────
function fetchSecrets(): array {
    // 1) GitHub'dan dene
    try {
        $res  = httpGet(SECRETS_URL);
        $dict = json_decode($res['body'], true);

        if (is_array($dict) && count($dict) > 0) {
            $latestVersion = (int) max(array_keys($dict));
            return ['version' => $latestVersion, 'secret' => $dict[(string) $latestVersion]];
        }
    } catch (Exception $e) {
        // GitHub başarısız olursa Spotify'dan çek
    }

    // 2) Spotify'dan canlı çek
    return extractSecretsFromSpotify();
}

function extractSecretsFromSpotify(): array {
    $res  = httpGet(SPOTIFY_URL);
    $html = $res['body'];

    if (!preg_match('/"(https:\/\/[^" ]+\/web-player\.[0-9a-f]+\.js)"/', $html, $m)) {
        throw new RuntimeException('Player JS URL bulunamadı.');
    }

    $jsRes = httpGet($m[1]);
    $js    = $jsRes['body'];

    preg_match_all(
        '/\{\s*secret\s*:\s*(["\'])(.*?)\1\s*,\s*version\s*:\s*(\d+)\s*\}/s',
        $js,
        $matches,
        PREG_SET_ORDER
    );

    if (empty($matches)) {
        throw new RuntimeException('Gizli anahtarlar JS içinde bulunamadı.');
    }

    $dict = [];
    foreach ($matches as $match) {
        $version       = (int) $match[3];
        $dict[$version] = array_map('ord', str_split($match[2]));
    }

    $latestVersion = max(array_keys($dict));
    return ['version' => $latestVersion, 'secret' => $dict[$latestVersion]];
}

// ─── Base32 ─────────────────────────────────────────────────────────────────
function encodeBase32(string $bytes): string {
    $chars  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits   = 0;
    $value  = 0;
    $output = '';

    for ($i = 0, $len = strlen($bytes); $i < $len; $i++) {
        $value = ($value << 8) | ord($bytes[$i]);
        $bits += 8;

        while ($bits >= 5) {
            $output .= $chars[($value >> ($bits - 5)) & 31];
            $bits   -= 5;
        }
    }

    if ($bits > 0) {
        $output .= $chars[($value << (5 - $bits)) & 31];
    }

    return $output;
}

// ─── TOTP ───────────────────────────────────────────────────────────────────
function generateTOTP(int $timestampSeconds, array $secretArray): string {
    // Diziyi dönüştür
    $transformed = [];
    foreach ($secretArray as $index => $element) {
        $transformed[] = $element ^ (($index % 33) + 9);
    }

    $joinedSecret = implode('', $transformed);
    $hexSecret    = bin2hex($joinedSecret);
    $secretBytes  = hex2bin($hexSecret);

    // Counter (30 saniyelik adım)
    $counter = (int) floor($timestampSeconds / 30);

    // 8 baytlık big-endian counter
    $counterBytes = pack('J', $counter); // 'J' = unsigned 64-bit big-endian

    // HMAC-SHA1
    $hmac   = hash_hmac('sha1', $counterBytes, $secretBytes, true);
    $offset = ord($hmac[strlen($hmac) - 1]) & 0xf;

    $code =
        ((ord($hmac[$offset])     & 0x7f) << 24) |
        ((ord($hmac[$offset + 1]) & 0xff) << 16) |
        ((ord($hmac[$offset + 2]) & 0xff) << 8)  |
         (ord($hmac[$offset + 3]) & 0xff);

    return str_pad((string) ($code % 1_000_000), 6, '0', STR_PAD_LEFT);
}

// ─── Ana akış ───────────────────────────────────────────────────────────────
try {
    $timestamp             = getServerTimestamp();
    ['version' => $version, 'secret' => $secret] = fetchSecrets();
    $totp                  = generateTOTP($timestamp, $secret);

    $params = [
        'reason'      => 'init',
        'productType' => 'web-player',
        'totp'        => $totp,
        'totpVer'     => $version,
        'ts'          => $timestamp,
    ];

    $res  = httpGet(TOKEN_URL, $params);
    http_response_code($res['status']);
    echo $res['body'];

} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
