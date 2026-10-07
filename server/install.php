<?php
// Instalación de un solo uso: crea las tablas, carga los Pokémon y, si existe import.json,
// importa los jugadores y las puntuaciones exportados de Supabase.
// Se abre con install.php?key=<install_key de config.php>. BÓRRALO DEL SERVIDOR AL TERMINAR.
declare(strict_types=1);
header('Content-Type: text/plain; charset=utf-8');

$c = require __DIR__ . '/config.php';
if (empty($c['install_key']) || !hash_equals($c['install_key'], (string)($_GET['key'] ?? ''))) { http_response_code(403); exit("No autorizado\n"); }

$db = new PDO("mysql:host={$c['db_host']};dbname={$c['db_name']};charset=utf8mb4", $c['db_user'], $c['db_pass'],
  [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$db->exec("SET time_zone = '+00:00'");

foreach (array_filter(array_map('trim', explode(';', preg_replace('/^--.*$/m', '', file_get_contents(__DIR__ . '/schema.sql'))))) as $sql) $db->exec($sql);
echo "Tablas creadas\n";

$st = $db->prepare('INSERT INTO pokemon (id, name, gen, types) VALUES (?, ?, ?, ?)
  ON DUPLICATE KEY UPDATE name = VALUES(name), gen = VALUES(gen), types = VALUES(types)');
$pokemon = json_decode(file_get_contents(__DIR__ . '/pokemon.json'), true);
foreach ($pokemon as [$id, $name, $gen, $types]) $st->execute([$id, $name, $gen, json_encode($types)]);
echo 'Pokémon: ' . count($pokemon) . "\n";

// import.json = resultado de la consulta de exportación de Supabase (ver README)
if (is_file(__DIR__ . '/import.json')) {
  $data = json_decode(file_get_contents(__DIR__ . '/import.json'), true, 512, JSON_THROW_ON_ERROR);
  if (isset($data[0]['export'])) $data = $data[0]['export'];   // por si se pega tal cual la fila del SQL Editor
  $date = fn($s) => $s === null ? null : (new DateTime($s))->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s.u');
  $db->beginTransaction();
  // la importación sustituye todo: se borran antes los jugadores de prueba y sus partidas
  foreach (['games', 'scores', 'sessions', 'players'] as $t) $db->exec("DELETE FROM $t");
  $p = $db->prepare('INSERT INTO players (id, username, pass_hash, created_at) VALUES (?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE pass_hash = VALUES(pass_hash)');
  foreach ($data['players'] ?? [] as $r) $p->execute([$r['id'], $r['username'], $r['pass_hash'], $date($r['created_at'])]);
  $s = $db->prepare('INSERT IGNORE INTO sessions (token, player_id, expires_at) VALUES (?, ?, ?)');
  foreach ($data['sessions'] ?? [] as $r) $s->execute([$r['token'], $r['player_id'], $date($r['expires_at'])]);
  $sc = $db->prepare('INSERT IGNORE INTO scores (id, player_id, mode, score, level, hits, avg_time, gens, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
  foreach ($data['scores'] ?? [] as $r) $sc->execute([$r['id'], $r['player_id'], $r['mode'], $r['score'], $r['level'], $r['hits'],
    $r['avg_time'], json_encode($r['gens'] ?? []), $date($r['created_at'])]);
  $db->commit();
  echo 'Importado: ' . count($data['players'] ?? []) . ' jugadores, ' . count($data['sessions'] ?? []) . ' sesiones, ' . count($data['scores'] ?? []) . " partidas\n";
}
foreach (['players', 'sessions', 'scores', 'pokemon', 'games'] as $t) echo "$t: " . $db->query("SELECT COUNT(*) FROM $t")->fetchColumn() . " filas\n";
echo "Listo. Borra install.php e import.json del servidor.\n";
