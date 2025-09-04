<?php

declare(strict_types=1);

use App\Config\AppConfig;
use App\Security\Crypto;
use App\Database\Connection;
use App\Database\DocumentRepository;

require_once __DIR__ . '/../vendor/autoload.php';

session_start();

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

$secretKeyPath = AppConfig::secretKeyPath();
$encPath = AppConfig::mssqlConfigPath();

if ($method === 'POST' && isset($_POST['first_setup'])) {
    $key = bin2hex(random_bytes(32));
    if (!is_dir(dirname($secretKeyPath))) {
        mkdir(dirname($secretKeyPath), 0770, true);
    }
    file_put_contents($secretKeyPath, $key);

    $host = trim($_POST['host'] ?? '');
    $user = trim($_POST['user'] ?? '');
    $pass = (string)($_POST['pass'] ?? '');
    $db = trim($_POST['db'] ?? '');

    $hostEnc = Crypto::encrypt($host, $key);
    $userEnc = Crypto::encrypt($user, $key);
    $passEnc = Crypto::encrypt($pass, $key);
    $dbEnc = Crypto::encrypt($db, $key);

    $payload = [
        'data' => $hostEnc['data'], 'iv' => $hostEnc['iv'], 'tag' => $hostEnc['tag'],
        'user' => $userEnc, 'pass' => $passEnc, 'db' => $dbEnc,
    ];
    file_put_contents($encPath, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
    header('Location: /przyPOMINANIE/');
    exit;
}

$hasConfig = is_file($secretKeyPath) && is_file($encPath);

?><!doctype html>
<html lang="pl">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>przyPOMINANIE</title>
    <style>
        body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji"; margin: 2rem; }
        .card { max-width: 640px; padding: 1.25rem; border: 1px solid #ddd; border-radius: 12px; box-shadow: 0 1px 2px rgba(0,0,0,.05); }
        label { display:block; margin-top: .75rem; font-weight: 600; }
        input { width: 100%; padding: .5rem .6rem; border:1px solid #ccc; border-radius: 8px; }
        button { margin-top: 1rem; padding: .6rem 1rem; border-radius: 8px; border: 1px solid #0b5; background:#0c6; color:#fff; cursor:pointer; }
        button:hover { background:#0b5; }
        .muted { color:#666; font-size:.9rem; }
    </style>
    <base href="/przyPOMINANIE/" />
</head>
<body>
<div class="card">
<?php if (!$hasConfig): ?>
    <h2>Pierwsze logowanie – konfiguracja MSSQL</h2>
    <p class="muted">Serwer i baza wstępnie uzupełnione: 192.168.0.3 / BUDUJ</p>
    <form method="post">
        <input type="hidden" name="first_setup" value="1" />
        <label>Serwer</label>
        <input name="host" value="192.168.0.3" required />
        <label>Baza danych</label>
        <input name="db" value="BUDUJ" required />
        <label>Login</label>
        <input name="user" placeholder="login do MSSQL" required />
        <label>Hasło</label>
        <input name="pass" type="password" placeholder="hasło do MSSQL" required />
        <button type="submit">Zapisz konfigurację</button>
    </form>
<?php else: ?>
    <h2>przyPOMINANIE</h2>
    <?php
        $error = null;
        $rows = [];
        try {
            $pdo = Connection::get();
            $repo = new DocumentRepository($pdo);
            $rows = $repo->fetchUnsettledDocuments();
        } catch (Throwable $e) {
            $error = $e->getMessage();
        }
    ?>
    <?php if ($error): ?>
        <p class="muted">Błąd połączenia/zapytania: <?= htmlspecialchars($error, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></p>
    <?php else: ?>
        <?php
            // Grupowanie wyników po ID_KONTRAHENTA
            $grouped = [];
            foreach ($rows as $row) {
                $kontrahentId = $row['ID_KONTRAHENTA'] ?? 'NULL';
                $grouped[$kontrahentId][] = $row;
            }
        ?>
        
        <?php if (!$rows): ?>
            <p class="muted" style="margin-top:1rem">Brak wyników.</p>
        <?php else: ?>
            <?php 
                // Funkcja formatowania waluty PLN
                function formatPLN($amount) {
                    $num = (float)($amount ?? 0);
                    return number_format($num, 2, ',', ' ') . ' zł';
                }
            ?>
            <?php foreach ($grouped as $kontrahentId => $kontrahentRows): ?>
                <?php 
                    $firstRow = $kontrahentRows[0];
                    // Oblicz sumę POZOSTALO dla grupy
                    $sumaPozostalo = 0;
                    foreach ($kontrahentRows as $row) {
                        $sumaPozostalo += (float)($row['POZOSTALO'] ?? 0);
                    }
                ?>
                <div style="margin-top: 2rem;">
                    <h3 style="background:#f8f9fa; padding:.75rem; border-radius:8px; margin:0 0 .5rem 0; border-left:4px solid #007bff;">
                        <?= htmlspecialchars((string)($firstRow['KONTRAHENT_NAZWA'] ?? 'Brak nazwy'), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>
                        <span style="font-weight:normal; color:#666; font-size:.9em">(<?= count($kontrahentRows) ?> dok.)</span>
                    </h3>
                    
                    <table style="width:100%; border-collapse: collapse;">
                        <thead>
                            <tr>
                                <th style="text-align:left; border-bottom:1px solid #ddd; padding:.5rem; background:#fafafa;">NUMER</th>
                                <th style="text-align:left; border-bottom:1px solid #ddd; padding:.5rem; background:#fafafa;">FORMA_PLATNOSCI</th>
                                <th style="text-align:left; border-bottom:1px solid #ddd; padding:.5rem; background:#fafafa;">TERMIN_PLAT</th>
                                <th style="text-align:center; border-bottom:1px solid #ddd; padding:.5rem; background:#fafafa;">DNI PO TERMINIE</th>
                                <th style="text-align:right; border-bottom:1px solid #ddd; padding:.5rem; background:#fafafa;">POZOSTALO</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($kontrahentRows as $r): ?>
                                <?php 
                                    $dniPoTerminie = (int)($r['DNI_PO_TERMINIE'] ?? 0);
                                    $kolorDni = $dniPoTerminie > 0 ? 'color:#d73527; font-weight:bold;' : 'color:#28a745;';
                                ?>
                                <tr>
                                    <td style="border-bottom:1px solid #f0f0f0; padding:.5rem"><?= htmlspecialchars((string)($r['NUMER'] ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></td>
                                    <td style="border-bottom:1px solid #f0f0f0; padding:.5rem"><?= htmlspecialchars((string)($r['FORMA_PLATNOSCI'] ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></td>
                                    <td style="border-bottom:1px solid #f0f0f0; padding:.5rem"><?= htmlspecialchars((string)($r['TERMIN_PLAT'] ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?></td>
                                    <td style="border-bottom:1px solid #f0f0f0; padding:.5rem; text-align:center; font-family:monospace; <?= $kolorDni ?>"><?= $dniPoTerminie ?></td>
                                    <td style="border-bottom:1px solid #f0f0f0; padding:.5rem; text-align:right; font-family:monospace"><?= formatPLN($r['POZOSTALO']) ?></td>
                                </tr>
                            <?php endforeach; ?>
                            <tr>
                                <td colspan="4" style="border-top:2px solid #007bff; padding:.75rem; font-weight:bold; background:#f8f9fa;">RAZEM:</td>
                                <td style="border-top:2px solid #007bff; padding:.75rem; text-align:right; font-weight:bold; background:#f8f9fa; font-family:monospace; color:#007bff;"><?= formatPLN($sumaPozostalo) ?></td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            <?php endforeach; ?>
        <?php endif; ?>
    <?php endif; ?>
<?php endif; ?>
</div>
</body>
</html>


