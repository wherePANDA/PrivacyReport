<?php
/**
 * PrivacyReport — Generate comprehensive privacy reports for websites.
 * Single-file PHP app. Requires PHP 8.0+ with cURL, DOM, and OpenSSL extensions.
 * UI: clean, light, TailwindCSS (CDN).
 */

declare(strict_types=1);
ini_set('display_errors', '1');
error_reporting(E_ALL);

// ------------------------- utilities -------------------------
function post(string $key, $default = '') {
    return isset($_POST[$key]) ? (is_string($_POST[$key]) ? trim($_POST[$key]) : $_POST[$key]) : $default;
}
function normalize_url(string $url): string {
    $url = trim($url);
    if ($url === '') return '';
    if (!preg_match('~^https?://~i', $url)) $url = 'https://' . $url;
    // remove fragment
    $url = preg_replace('~#.*$~', '', $url);
    return $url;
}
function get_host(string $url): string {
    $parts = parse_url($url);
    return strtolower($parts['host'] ?? '');
}
function root_domain(string $host): string {
    // naive registrable domain (last 2 labels). Not PSL-accurate but good enough for a heuristic.
    $labels = array_values(array_filter(explode('.', $host)));
    $n = count($labels);
    if ($n >= 2) return $labels[$n-2] . '.' . $labels[$n-1];
    return $host;
}
function is_same_site(string $a, string $b): bool {
    return root_domain($a) === root_domain($b);
}
function unique_sorted(array $arr): array {
    $arr = array_values(array_unique($arr));
    sort($arr, SORT_STRING);
    return $arr;
}
function limit_str(string $s, int $n = 200): string {
    if (mb_strlen($s, 'UTF-8') <= $n) return $s;
    return mb_substr($s, 0, $n, 'UTF-8') . '…';
}
function bool_icon($b): string {
    return $b ? '✅' : '❌';
}
function grade_color(string $grade): string {
    return [
        'A+' => 'bg-emerald-100 text-emerald-800',
        'A'  => 'bg-emerald-100 text-emerald-800',
        'B'  => 'bg-lime-100 text-lime-800',
        'C'  => 'bg-amber-100 text-amber-800',
        'D'  => 'bg-orange-100 text-orange-800',
        'F'  => 'bg-red-100 text-red-800',
    ][$grade] ?? 'bg-gray-100 text-gray-800';
}
function safe_json_encode(array $data): string {
    return json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

// ------------------------- network helpers -------------------------
function curl_request(string $url, array $opts = []): array {
    $ch = curl_init();
    $headers = [];
    $default = [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_USERAGENT => 'PrivacyReport/1.0 (+https://example.local)',
        CURLOPT_HEADERFUNCTION => function($ch, $line) use (&$headers) {
            $len = strlen($line);
            $lineTrim = trim($line);
            if ($lineTrim === '') return $len;
            // new response block
            if (str_starts_with($lineTrim, 'HTTP/')) {
                $headers[] = [];
            } else {
                $parts = explode(':', $line, 2);
                if (count($parts) === 2) {
                    $k = strtolower(trim($parts[0]));
                    $v = trim($parts[1]);
                    $headers[count($headers) ? count($headers) - 1 : 0][$k][] = $v;
                }
            }
            return $len;
        },
    ];
    foreach ($opts as $k => $v) $default[$k] = $v;
    curl_setopt_array($ch, $default);

    $body = curl_exec($ch);
    $err  = curl_error($ch);
    $info = curl_getinfo($ch);
    curl_close($ch);

    return [
        'ok' => $err === '',
        'error' => $err,
        'info' => $info,
        'headers' => $headers,
        'body' => $body,
    ];
}

function head_request(string $url): array {
    return curl_request($url, [
        CURLOPT_NOBODY => true,
        CURLOPT_CUSTOMREQUEST => 'HEAD',
    ]);
}

function fetch_html_and_headers(string $url): array {
    $res = curl_request($url);
    if (!$res['ok']) return $res;
    // if misreported content type, still try to parse as HTML later
    return $res;
}

function tls_details(string $url): array {
    $parts = parse_url($url);
    $host = $parts['host'] ?? '';
    $port = ($parts['scheme'] ?? 'https') === 'https' ? 443 : 80;
    if ($port !== 443 || $host === '') return ['https' => false];
    $ctx = stream_context_create([
        "ssl" => [
            "capture_peer_cert" => true,
            "verify_peer" => false,
            "verify_peer_name" => false,
        ]
    ]);
    $client = @stream_socket_client("ssl://{$host}:{$port}", $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $ctx);
    if (!$client) return ['https' => true, 'cert' => null, 'error' => "$errno $errstr"];
    $params = stream_context_get_params($client);
    $certRes = $params['options']['ssl']['peer_certificate'] ?? null;
    $parsed = $certRes ? openssl_x509_parse($certRes) : null;
    $proto = stream_get_meta_data($client)['stream_type'] ?? '';
    @fclose($client);

    $validTo = null;
    if ($parsed && isset($parsed['validTo_time_t'])) $validTo = (int)$parsed['validTo_time_t'];
    $issuer = $parsed['issuer'] ?? null;
    $subject = $parsed['subject'] ?? null;
    return [
        'https' => true,
        'tls_protocol' => $proto,
        'valid_to' => $validTo,
        'issuer' => $issuer,
        'subject' => $subject,
    ];
}

// ------------------------- analysis -------------------------
function parse_html(string $html): DOMDocument {
    $dom = new DOMDocument();
    libxml_use_internal_errors(true);
    @$dom->loadHTML($html);
    libxml_clear_errors();
    return $dom;
}

function extract_links_scripts_iframes_images(DOMDocument $dom, string $baseHost): array {
    $xpath = new DOMXPath($dom);
    $getAttr = function(DOMNode $n, string $attr): ?string {
        /** @var DOMElement $n */
        return $n instanceof DOMElement ? $n->getAttribute($attr) : null;
    };

    $urls = [
        'scripts' => [],
        'links'   => [],
        'iframes' => [],
        'images'  => [],
        'fetches' => [], // <link rel=preconnect|dns-prefetch|preload> etc
    ];

    foreach ($xpath->query('//script[@src]') as $n)  $urls['scripts'][] = $getAttr($n, 'src');
    foreach ($xpath->query('//link[@href]') as $n)   $urls['links'][]   = $getAttr($n, 'href');
    foreach ($xpath->query('//iframe[@src]') as $n) $urls['iframes'][] = $getAttr($n, 'src');
    foreach ($xpath->query('//img[@src]') as $n)    $urls['images'][]  = $getAttr($n, 'src');

    // inline script tracker hints
    $inline_scripts = [];
    foreach ($xpath->query('//script[not(@src)]') as $n) {
        $inline_scripts[] = $n->textContent ?? '';
    }

    // absolutize heuristic and collect hosts
    $hostify = function(?string $u) use ($baseHost): ?string {
        if (!$u) return null;
        $u = trim($u);
        if ($u === '' || str_starts_with($u, 'data:') || str_starts_with($u, 'blob:') || str_starts_with($u, 'mailto:')) return null;
        if (str_starts_with($u, '//')) $u = 'https:' . $u;
        if (!preg_match('~^https?://~i', $u)) {
            if (str_starts_with($u, '/')) $u = 'https://' . $baseHost . $u;
            else $u = 'https://' . $baseHost . '/' . ltrim($u, './');
        }
        $h = get_host($u);
        return $h ?: null;
    };

    $all = array_merge($urls['scripts'], $urls['links'], $urls['iframes'], $urls['images']);
    $hosts = [];
    foreach ($all as $u) {
        $h = $hostify($u);
        if ($h) $hosts[] = $h;
    }

    return [
        'urls' => $urls,
        'inline_scripts' => $inline_scripts,
        'hosts' => unique_sorted(array_filter($hosts)),
    ];
}

function detect_cookie_banner(string $html): array {
    $hay = mb_strtolower($html, 'UTF-8');
    $keywords = [
        'cookie', 'cookies', 'consent', 'gdpr', 'we use cookies', 'accept all', 'manage preferences',
        'cookie settings', 'cookie policy', 'functional cookies', 'analytics cookies', 'reject all'
    ];
    $hits = [];
    foreach ($keywords as $k) {
        if (mb_strpos($hay, $k, 0, 'UTF-8') !== false) $hits[] = $k;
    }
    return unique_sorted($hits);
}

function detect_forms_collecting_pii(DOMDocument $dom): array {
    $xpath = new DOMXPath($dom);
    $forms = [];
    /** @var DOMElement $form */
    foreach ($xpath->query('//form') as $form) {
        $inputs = [];
        foreach ($form->getElementsByTagName('*') as $el) {
            if (!$el instanceof DOMElement) continue;
            $name = strtolower($el->getAttribute('name') . ' ' . $el->getAttribute('id') . ' ' . $el->getAttribute('placeholder'));
            $type = strtolower($el->getAttribute('type'));
            if (in_array($type, ['email','tel','password'], true)) $inputs[] = $type;
            foreach (['name','firstname','lastname','address','phone','mobile','ssn','passport'] as $kw) {
                if (str_contains($name, $kw)) $inputs[] = $kw;
            }
        }
        if ($inputs) {
            $action = $form->getAttribute('action') ?: '';
            $method = strtoupper($form->getAttribute('method') ?: 'GET');
            $forms[] = [
                'action' => $action,
                'method' => $method,
                'signals' => unique_sorted($inputs),
            ];
        }
    }
    return $forms;
}

function classify_trackers(array $hosts, array $inlineScripts): array {
    // simple domain-based and snippet-based detection
    $rules = [
        'Google Analytics' => ['www.google-analytics.com','ssl.google-analytics.com','analytics.google.com','gtag/js'],
        'Google Tag Manager' => ['www.googletagmanager.com','gtm.js'],
        'Google Ads' => ['googleads.g.doubleclick.net','adservice.google.com','doubleclick.net'],
        'Facebook Pixel' => ['connect.facebook.net','fbq(', 'fbevents.js'],
        'Hotjar' => ['static.hotjar.com','script.hotjar.com','hotjar.com'],
        'Segment' => ['cdn.segment.com','segment.com','analytics.load('],
        'Intercom' => ['widget.intercom.io','js.intercomcdn.com'],
        'Mixpanel' => ['cdn.mxpnl.com','api.mixpanel.com','mixpanel.init('],
        'Matomo' => ['matomo.js','piwik.js','/matomo.php','/piwik.php'],
        'Sentry' => ['browser.sentry-cdn.com','sentry.io','Sentry.init('],
        'Amplitude' => ['cdn.amplitude.com','amplitude.com'],
        'LinkedIn Insight' => ['snap.licdn.com'],
        'Twitter Pixel' => ['static.ads-twitter.com','analytics.twitter.com','twttr.conversion.trackPid'],
        'Microsoft Clarity' => ['www.clarity.ms','clarity.ms','clarity("set"'],
    ];
    $found = [];
    foreach ($rules as $name => $needles) {
        $hit = false;
        foreach ($needles as $n) {
            foreach ($hosts as $h) {
                if (str_contains($h, parse_url('https://'.$n, PHP_URL_HOST) ?: $n)) { $hit = true; break; }
            }
            if ($hit) break;
            foreach ($inlineScripts as $code) { if (str_contains($code, $n)) { $hit = true; break; } }
            if ($hit) break;
        }
        if ($hit) $found[] = $name;
    }
    sort($found);
    return $found;
}

function evaluate_security_headers(array $lastHeaderBlock): array {
    $h = [];
    foreach ($lastHeaderBlock as $k => $vals) {
        $h[strtolower($k)] = array_map('trim', $vals);
    }
    $get = fn(string $name) => $h[strtolower($name)] ?? null;

    $checks = [
        'Content-Security-Policy' => !!$get('content-security-policy'),
        'Strict-Transport-Security' => !!$get('strict-transport-security'),
        'X-Content-Type-Options' => in_array('nosniff', array_map('strtolower', $get('x-content-type-options') ?? []), true),
        'X-Frame-Options' => !!$get('x-frame-options'),
        'Referrer-Policy' => !!$get('referrer-policy'),
        'Permissions-Policy' => !!$get('permissions-policy'),
        'Cross-Origin-Resource-Policy' => !!$get('cross-origin-resource-policy'),
        'Cross-Origin-Opener-Policy' => !!$get('cross-origin-opener-policy'),
        'Cross-Origin-Embedder-Policy' => !!$get('cross-origin-embedder-policy'),
    ];

    $score = 0; $max = count($checks);
    foreach ($checks as $k => $ok) { if ($ok) $score++; }

    // grade
    $pct = $max ? ($score / $max) : 0;
    $grade = 'F';
    if ($pct >= 0.95) $grade = 'A+';
    elseif ($pct >= 0.8) $grade = 'A';
    elseif ($pct >= 0.65) $grade = 'B';
    elseif ($pct >= 0.5) $grade = 'C';
    elseif ($pct >= 0.35) $grade = 'D';
    else $grade = 'F';

    return ['checks' => $checks, 'score' => $score, 'max' => $max, 'grade' => $grade];
}

function evaluate_cookie_flags(array $setCookies): array {
    $parsed = [];
    foreach ($setCookies as $sc) {
        $parts = array_map('trim', explode(';', $sc));
        $kv = explode('=', array_shift($parts), 2);
        $name = $kv[0] ?? '';
        $value = $kv[1] ?? '';
        $flags = [
            'Secure' => false,
            'HttpOnly' => false,
            'SameSite' => 'None', // None/Lax/Strict/Unknown
        ];
        foreach ($parts as $attr) {
            [$k, $v] = array_map('trim', explode('=', $attr, 2) + [1 => '']);
            $kl = strtolower($k);
            if ($kl === 'secure') $flags['Secure'] = true;
            elseif ($kl === 'httponly') $flags['HttpOnly'] = true;
            elseif ($kl === 'samesite') $flags['SameSite'] = $v ?: 'Unknown';
        }
        $parsed[] = ['name' => $name, 'value_preview' => limit_str($value, 16), 'flags' => $flags];
    }
    return $parsed;
}

function quick_endpoints_checks(string $base): array {
    $targets = [
        'robots' => rtrim($base, '/') . '/robots.txt',
        'security' => rtrim($base, '/') . '/.well-known/security.txt',
        'privacy' => rtrim($base, '/') . '/privacy',
        'privacy_policy' => rtrim($base, '/') . '/privacy-policy',
    ];
    $out = [];
    foreach ($targets as $k => $url) {
        $r = head_request($url);
        $ok = $r['ok'] && in_array(($r['info']['http_code'] ?? 0), [200,204,206,301,302,303,307,308], true);
        $out[$k] = ['url' => $url, 'reachable' => $ok, 'status' => $r['info']['http_code'] ?? 0];
    }
    return $out;
}

function compile_recommendations(array $report): array {
    $recs = [];

    if (($report['security_headers']['score'] ?? 0) < ($report['security_headers']['max'] ?? 0)) {
        $missing = [];
        foreach ($report['security_headers']['checks'] as $h => $ok) if (!$ok) $missing[] = $h;
        if ($missing) $recs[] = 'Add / strengthen security headers: ' . implode(', ', $missing) . '.';
    }

    if (!empty($report['cookies']) && count($report['cookies'])) {
        foreach ($report['cookies'] as $c) {
            if (!$c['flags']['Secure'] || !$c['flags']['HttpOnly'] || (strtolower((string)$c['flags']['SameSite']) === 'none')) {
                $recs[] = "Harden cookie '{$c['name']}' with Secure, HttpOnly and an appropriate SameSite attribute.";
            }
        }
    }

    if (!($report['endpoints']['privacy']['reachable'] ?? false) && !($report['endpoints']['privacy_policy']['reachable'] ?? false)) {
        $recs[] = 'Publish a clear, accessible privacy policy (e.g., /privacy or /privacy-policy).';
    }

    $third = $report['third_parties']['third_party_hosts'] ?? [];
    if ($third && count($third) > 10) $recs[] = 'Reduce third-party requests; consider local hosting / consent-based loading.';

    $banner = $report['ui_signals']['cookie_banner_hits'] ?? [];
    if (!$banner) $recs[] = 'Add a cookie consent banner if tracking or non-essential cookies are used.';

    if (($report['trackers']['detected'] ?? [])) {
        $recs[] = 'Ensure trackers load only after consent and provide opt-out links.';
    }

    if (($report['forms']['count'] ?? 0) > 0) {
        $recs[] = 'Validate data minimization: only collect PII necessary for the stated purpose.';
    }

    if (!$recs) $recs[] = 'No critical issues detected. Maintain current posture and monitor periodically.';
    return unique_sorted($recs);
}

function overall_grade(array $report): string {
    // weight security headers, cookies, trackers, third parties, endpoints, banner
    $score = 0; $total = 100;

    // Security headers up to 30
    $sec = $report['security_headers'];
    $score += 30 * (($sec['score'] ?? 0) / max(1, ($sec['max'] ?? 1)));

    // Cookies up to 15 (deduct if weak)
    $cookiePenalty = 0;
    foreach ($report['cookies'] as $c) {
        if (!$c['flags']['Secure']) $cookiePenalty += 3;
        if (!$c['flags']['HttpOnly']) $cookiePenalty += 3;
        if (strtolower((string)$c['flags']['SameSite']) === 'none') $cookiePenalty += 2;
    }
    $score += max(0, 15 - min(15, $cookiePenalty));

    // Trackers up to 20 (fewer is better)
    $t = count($report['trackers']['detected'] ?? []);
    $score += max(0, 20 - min(20, $t * 3));

    // Third-party hosts up to 20 (fewer is better)
    $tp = count($report['third_parties']['third_party_hosts'] ?? []);
    $score += max(0, 20 - min(20, max(0, $tp - 2)));

    // Endpoints up to 10
    $ep = $report['endpoints'];
    $score += 5 * (int)($ep['privacy']['reachable'] ?? false);
    $score += 5 * (int)($ep['privacy_policy']['reachable'] ?? false);

    // Banner up to 5
    $score += min(5, count($report['ui_signals']['cookie_banner_hits'] ?? []) ? 5 : 0);

    // Map to grade
    $pct = $score / $total;
    if ($pct >= 0.95) return 'A+';
    if ($pct >= 0.85) return 'A';
    if ($pct >= 0.75) return 'B';
    if ($pct >= 0.65) return 'C';
    if ($pct >= 0.50) return 'D';
    return 'F';
}

// ------------------------- controller -------------------------
$action = post('action', '');
$resultReport = null;
$error = null;

if ($action === 'scan') {
    try {
        $input = post('target');
        $url = normalize_url((string)$input);
        if ($url === '') throw new RuntimeException('Please enter a website URL.');
        $host = get_host($url);
        if ($host === '') throw new RuntimeException('Invalid URL.');

        $fetch = fetch_html_and_headers($url);
        if (!$fetch['ok']) throw new RuntimeException('Fetch error: ' . $fetch['error']);
        $body = (string)$fetch['body'];
        $headersBlocks = $fetch['headers'];
        $lastHeaders = $headersBlocks ? end($headersBlocks) : [];

        $dom = parse_html($body);
        $ext = extract_links_scripts_iframes_images($dom, $host);

        $thirdPartyHosts = [];
        foreach ($ext['hosts'] as $h) {
            if (!is_same_site($host, $h)) $thirdPartyHosts[] = $h;
        }

        $cookieBanner = detect_cookie_banner($body);
        $forms = detect_forms_collecting_pii($dom);
        $trackers = classify_trackers($ext['hosts'], $ext['inline_scripts']);
        $secHeaders = evaluate_security_headers($lastHeaders);
        $tls = tls_details($url);
        $endpoints = quick_endpoints_checks('https://' . $host);

        $setCookies = [];
        foreach ($lastHeaders['set-cookie'] ?? [] as $sc) $setCookies[] = $sc;
        $cookies = evaluate_cookie_flags($setCookies);

        $report = [
            'scanned_at' => date('c'),
            'target' => $url,
            'host' => $host,
            'grade' => null, // set later
            'security_headers' => $secHeaders,
            'https' => $tls,
            'cookies' => $cookies,
            'endpoints' => $endpoints,
            'third_parties' => [
                'all_hosts' => $ext['hosts'],
                'third_party_hosts' => unique_sorted($thirdPartyHosts),
                'counts' => [
                    'scripts' => count($ext['urls']['scripts']),
                    'links'   => count($ext['urls']['links']),
                    'iframes' => count($ext['urls']['iframes']),
                    'images'  => count($ext['urls']['images']),
                ]
            ],
            'trackers' => [
                'detected' => $trackers
            ],
            'forms' => [
                'count' => count($forms),
                'pii_forms' => $forms,
            ],
            'ui_signals' => [
                'cookie_banner_hits' => $cookieBanner,
            ],
        ];
        $report['grade'] = overall_grade($report);
        $report['recommendations'] = compile_recommendations($report);
        $resultReport = $report;

        // Export helpers
        if (post('export') === 'json') {
            header('Content-Type: application/json');
            header('Content-Disposition: attachment; filename="privacy-report.json"');
            echo safe_json_encode($report);
            exit;
        }
        if (post('export') === 'markdown') {
            $md = [];
            $md[] = '# Privacy Report';
            $md[] = '';
            $md[] = '**Target:** ' . $report['target'] . '  ';
            $md[] = '**Scanned at:** ' . $report['scanned_at'] . '  ';
            $md[] = '**Grade:** ' . $report['grade'];
            $md[] = '';
            $md[] = '## Summary';
            $md[] = '- Security headers: ' . $report['security_headers']['score'] . '/' . $report['security_headers']['max'];
            $md[] = '- HTTPS: ' . ($report['https']['https'] ? 'yes' : 'no');
            $md[] = '- Cookies set: ' . count($report['cookies']);
            $md[] = '- Trackers detected: ' . count($report['trackers']['detected']);
            $md[] = '- Third-party hosts: ' . count($report['third_parties']['third_party_hosts']);
            $md[] = '';
            $md[] = '## Security Headers';
            foreach ($report['security_headers']['checks'] as $k=>$ok) $md[] = "- {$k}: " . ($ok ? 'present' : 'missing');
            $md[] = '';
            $md[] = '## Cookies';
            foreach ($report['cookies'] as $c) {
                $md[] = "- **{$c['name']}** — Secure: " . ($c['flags']['Secure']?'yes':'no') . ', HttpOnly: ' . ($c['flags']['HttpOnly']?'yes':'no') . ', SameSite: ' . $c['flags']['SameSite'];
            }
            if (!$report['cookies']) $md[] = '- none';
            $md[] = '';
            $md[] = '## Trackers';
            foreach ($report['trackers']['detected'] as $t) $md[] = "- {$t}";
            if (!$report['trackers']['detected']) $md[] = '- none detected';
            $md[] = '';
            $md[] = '## Third-Party Hosts';
            foreach ($report['third_parties']['third_party_hosts'] as $h) $md[] = "- {$h}";
            if (!$report['third_parties']['third_party_hosts']) $md[] = '- none';
            $md[] = '';
            $md[] = '## Endpoints';
            foreach ($report['endpoints'] as $k=>$v) $md[] = "- {$k}: " . ($v['reachable'] ? 'reachable' : 'not found') . ' (' . $v['status'] . ') — ' . $v['url'];
            $md[] = '';
            $md[] = '## Forms (PII signals)';
            foreach ($report['forms']['pii_forms'] as $f) $md[] = "- {$f['method']} {$f['action']} — signals: " . implode(', ', $f['signals']);
            if (!$report['forms']['pii_forms']) $md[] = '- none';
            $md[] = '';
            $md[] = '## UI Signals';
            $md[] = '- Cookie banner keywords: ' . (implode(', ', $report['ui_signals']['cookie_banner_hits']) ?: 'none');
            $md[] = '';
            $md[] = '## Recommendations';
            foreach ($report['recommendations'] as $r) $md[] = "- {$r}";
            $mdContent = implode("\n", $md);
            header('Content-Type: text/markdown; charset=utf-8');
            header('Content-Disposition: attachment; filename="privacy-report.md"');
            echo $mdContent;
            exit;
        }
    } catch (Throwable $e) {
        $error = $e->getMessage();
    }
}

?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>PrivacyReport — Website Privacy Audits</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    .mono { font-family: ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace; }
  </style>
</head>
<body class="bg-gray-50 text-gray-900">
  <div class="max-w-6xl mx-auto p-6">
    <header class="mb-6">
      <h1 class="text-3xl font-semibold">PrivacyReport</h1>
      <p class="text-gray-600">Generate comprehensive privacy reports for any website — headers, cookies, trackers, third-party calls, endpoints, and more.</p>
    </header>

    <?php if ($error): ?>
      <div class="rounded-xl bg-red-100 text-red-800 p-4 mb-4"><?= htmlspecialchars($error, ENT_QUOTES) ?></div>
    <?php endif; ?>

    <section class="bg-white rounded-2xl shadow p-5 mb-6">
      <form method="post" class="flex flex-col md:flex-row gap-3 items-start">
        <input type="hidden" name="action" value="scan">
        <input name="target" placeholder="https://example.com" class="flex-1 w-full rounded-xl border p-3" />
        <div class="flex gap-2">
          <button class="rounded-xl bg-gray-900 text-white px-4 py-3">Run Audit</button>
          <button name="export" value="json" class="rounded-xl bg-gray-200 text-gray-900 px-4 py-3">Export JSON</button>
          <button name="export" value="markdown" class="rounded-xl bg-gray-200 text-gray-900 px-4 py-3">Export Markdown</button>
        </div>
      </form>
      <p class="text-xs text-gray-500 mt-2">Tip: include scheme (https://). Some checks are heuristic.</p>
    </section>

    <?php if ($resultReport): ?>
      <?php
        $r = $resultReport;
      ?>
      <section class="mb-6">
        <div class="bg-white rounded-2xl shadow p-5">
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div class="text-sm text-gray-500">Target</div>
              <div class="font-medium"><?= htmlspecialchars($r['target'], ENT_QUOTES) ?></div>
              <div class="text-xs text-gray-500">Scanned at <?= htmlspecialchars($r['scanned_at'], ENT_QUOTES) ?></div>
            </div>
            <div class="text-right">
              <div class="text-sm text-gray-500">Overall Grade</div>
              <div class="inline-block px-3 py-1 rounded-lg text-sm <?= grade_color($r['grade']) ?>"><?= $r['grade'] ?></div>
            </div>
          </div>
        </div>
      </section>

      <div class="grid md:grid-cols-2 gap-6">
        <!-- Security Headers -->
        <section class="bg-white rounded-2xl shadow p-5">
          <h2 class="text-xl font-semibold mb-3">Security Headers</h2>
          <div class="text-sm text-gray-600 mb-2"><?= $r['security_headers']['score'] ?>/<?= $r['security_headers']['max'] ?> present</div>
          <ul class="space-y-2">
            <?php foreach ($r['security_headers']['checks'] as $k=>$ok): ?>
              <li class="flex items-center justify-between border rounded-lg p-2">
                <span><?= htmlspecialchars($k, ENT_QUOTES) ?></span>
                <span class="text-lg"><?= $ok ? '✅' : '❌' ?></span>
              </li>
            <?php endforeach; ?>
          </ul>
        </section>

        <!-- HTTPS / TLS -->
        <section class="bg-white rounded-2xl shadow p-5">
          <h2 class="text-xl font-semibold mb-3">TLS</h2>
          <div class="space-y-2 text-sm">
            <div class="flex items-center justify-between border rounded-lg p-2">
              <span>HTTPS</span><span><?= bool_icon($r['https']['https'] ?? false) ?></span>
            </div>
            <?php if (!empty($r['https']['valid_to'])): ?>
              <div class="flex items-center justify-between border rounded-lg p-2">
                <span>Certificate valid to</span><span><?= date('Y-m-d', (int)$r['https']['valid_to']) ?></span>
              </div>
            <?php endif; ?>
            <?php if (!empty($r['https']['issuer'])): ?>
              <div class="border rounded-lg p-2">
                <div class="text-xs text-gray-500">Issuer</div>
                <div class="mono text-xs"><?= htmlspecialchars(json_encode($r['https']['issuer'], JSON_UNESCAPED_SLASHES), ENT_QUOTES) ?></div>
              </div>
            <?php endif; ?>
          </div>
        </section>

        <!-- Cookies -->
        <section class="bg-white rounded-2xl shadow p-5">
          <h2 class="text-xl font-semibold mb-3">Cookies</h2>
          <?php if ($r['cookies']): ?>
            <div class="space-y-2">
              <?php foreach ($r['cookies'] as $c): ?>
                <div class="border rounded-lg p-3">
                  <div class="font-medium"><?= htmlspecialchars($c['name'], ENT_QUOTES) ?></div>
                  <div class="text-xs text-gray-500">value (preview): <span class="mono"><?= htmlspecialchars($c['value_preview'], ENT_QUOTES) ?></span></div>
                  <div class="flex gap-2 text-sm mt-2">
                    <span>Secure: <?= bool_icon($c['flags']['Secure']) ?></span>
                    <span>HttpOnly: <?= bool_icon($c['flags']['HttpOnly']) ?></span>
                    <span>SameSite: <span class="mono"><?= htmlspecialchars((string)$c['flags']['SameSite'], ENT_QUOTES) ?></span></span>
                  </div>
                </div>
              <?php endforeach; ?>
            </div>
          <?php else: ?>
            <div class="text-sm text-gray-600">No cookies set in the landing response.</div>
          <?php endif; ?>
        </section>

        <!-- Trackers -->
        <section class="bg-white rounded-2xl shadow p-5">
          <h2 class="text-xl font-semibold mb-3">Trackers</h2>
          <?php if ($r['trackers']['detected']): ?>
            <ul class="list-disc pl-5 text-sm">
              <?php foreach ($r['trackers']['detected'] as $t): ?>
                <li><?= htmlspecialchars($t, ENT_QUOTES) ?></li>
              <?php endforeach; ?>
            </ul>
          <?php else: ?>
            <div class="text-sm text-gray-600">No common trackers detected.</div>
          <?php endif; ?>
        </section>

        <!-- Third Parties -->
        <section class="bg-white rounded-2xl shadow p-5">
          <h2 class="text-xl font-semibold mb-3">Third-Party Requests</h2>
          <div class="grid grid-cols-2 gap-2 text-sm mb-3">
            <div class="border rounded-lg p-2">Scripts: <span class="font-medium"><?= (int)$r['third_parties']['counts']['scripts'] ?></span></div>
            <div class="border rounded-lg p-2">Links: <span class="font-medium"><?= (int)$r['third_parties']['counts']['links'] ?></span></div>
            <div class="border rounded-lg p-2">Iframes: <span class="font-medium"><?= (int)$r['third_parties']['counts']['iframes'] ?></span></div>
            <div class="border rounded-lg p-2">Images: <span class="font-medium"><?= (int)$r['third_parties']['counts']['images'] ?></span></div>
          </div>
          <?php if ($r['third_parties']['third_party_hosts']): ?>
            <ul class="text-sm mono space-y-1 max-h-48 overflow-auto border rounded-lg p-2">
              <?php foreach ($r['third_parties']['third_party_hosts'] as $h): ?>
                <li><?= htmlspecialchars($h, ENT_QUOTES) ?></li>
              <?php endforeach; ?>
            </ul>
          <?php else: ?>
            <div class="text-sm text-gray-600">No third-party hosts detected.</div>
          <?php endif; ?>
        </section>

        <!-- Endpoints -->
        <section class="bg-white rounded-2xl shadow p-5">
          <h2 class="text-xl font-semibold mb-3">Endpoints</h2>
          <div class="space-y-2 text-sm">
            <?php foreach ($r['endpoints'] as $k=>$v): ?>
              <div class="flex items-center justify-between border rounded-lg p-2">
                <div>
                  <div class="font-medium"><?= htmlspecialchars(ucwords(str_replace('_',' ', $k)), ENT_QUOTES) ?></div>
                  <div class="text-xs text-gray-500"><?= htmlspecialchars($v['url'], ENT_QUOTES) ?></div>
                </div>
                <div><?= $v['reachable'] ? '✅' : '❌' ?> <span class="text-xs text-gray-500">(<?= (int)$v['status'] ?>)</span></div>
              </div>
            <?php endforeach; ?>
          </div>
        </section>

        <!-- Forms -->
        <section class="bg-white rounded-2xl shadow p-5">
          <h2 class="text-xl font-semibold mb-3">Forms (PII Signals)</h2>
          <?php if ($r['forms']['pii_forms']): ?>
            <div class="space-y-2 text-sm">
              <?php foreach ($r['forms']['pii_forms'] as $f): ?>
                <div class="border rounded-lg p-2">
                  <div class="font-medium"><?= htmlspecialchars($f['method'].' '.$f['action'], ENT_QUOTES) ?></div>
                  <div class="text-xs text-gray-500">Signals: <?= htmlspecialchars(implode(', ', $f['signals']), ENT_QUOTES) ?></div>
                </div>
              <?php endforeach; ?>
            </div>
          <?php else: ?>
            <div class="text-sm text-gray-600">No forms with clear PII signals detected.</div>
          <?php endif; ?>
        </section>

        <!-- UI Signals -->
        <section class="bg-white rounded-2xl shadow p-5">
          <h2 class="text-xl font-semibold mb-3">UI Signals</h2>
          <div class="text-sm">
            <div class="mb-2">Cookie banner keywords:</div>
            <div class="border rounded-lg p-2 min-h-[48px]">
              <?= $r['ui_signals']['cookie_banner_hits'] ? htmlspecialchars(implode(', ', $r['ui_signals']['cookie_banner_hits']), ENT_QUOTES) : '<span class="text-gray-500">none</span>' ?>
            </div>
          </div>
        </section>
      </div>

      <!-- Recommendations -->
      <section class="bg-white rounded-2xl shadow p-5 mt-6">
        <h2 class="text-xl font-semibold mb-3">Recommendations</h2>
        <ul class="list-disc pl-5 text-sm">
          <?php foreach ($r['recommendations'] as $rec): ?>
            <li><?= htmlspecialchars($rec, ENT_QUOTES) ?></li>
          <?php endforeach; ?>
        </ul>
      </section>

      <!-- Raw JSON -->
      <section class="bg-white rounded-2xl shadow p-5 mt-6">
        <h2 class="text-xl font-semibold mb-3">Raw Report (JSON)</h2>
        <textarea class="w-full h-52 mono text-xs bg-gray-50 rounded-lg p-3" readonly><?= htmlspecialchars(safe_json_encode($r), ENT_QUOTES) ?></textarea>
      </section>
    <?php endif; ?>

    <footer class="text-xs text-gray-500 mt-10">
      <p>Heuristics only. Results may vary depending on dynamic content and geolocation. Always validate with your legal and security teams.</p>
      <p class="mt-1">© <?= date('Y') ?> PrivacyReport</p>
    </footer>
  </div>
</body>
</html>