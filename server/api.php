<?php
// API de "¿Quién es ese Pokémon?". La web llama a api.php?fn=<función> con un JSON de parámetros.
//
// Anti-trampas: el servidor arbitra la partida. Elige el Pokémon y las opciones, mide el tiempo
// con su propio reloj, corrige cada respuesta, calcula los puntos y guarda la puntuación al
// terminar. La web nunca conoce la respuesta antes de contestar ni envía puntos.
declare(strict_types=1);

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

const HITS_PER_LEVEL = 5;
const LATE_MARGIN = 1.5;   // segundos de margen para lo que tarda la conexión
const MODES = ['silueta'];
const IMG = 'https://raw.githubusercontent.com/PokeAPI/sprites/master/sprites/pokemon/other/official-artwork/%d.png';

// Error que se enseña al jugador tal cual
class Fail extends Exception {}
function fail(string $msg): never { throw new Fail($msg); }

/* ---------- Utilidades ---------- */

function db(): PDO {
  static $db = null;
  if ($db) return $db;
  $c = require __DIR__ . '/config.php';
  $db = new PDO("mysql:host={$c['db_host']};dbname={$c['db_name']};charset=utf8mb4", $c['db_user'], $c['db_pass'], [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
  ]);
  $db->exec("SET time_zone = '+00:00'");
  return $db;
}

function q(string $sql, array $args = []): PDOStatement {
  $st = db()->prepare($sql);
  $st->execute($args);
  return $st;
}

function uuid(): string {
  $b = random_bytes(16);
  $b[6] = chr(ord($b[6]) & 0x0f | 0x40);
  $b[8] = chr(ord($b[8]) & 0x3f | 0x80);
  return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
}

function is_uuid($v): bool {
  return is_string($v) && preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $v) === 1;
}

// fecha en formato ISO (UTC) para la web
const ISO = "DATE_FORMAT(%s, '%%Y-%%m-%%dT%%H:%%i:%%sZ')";

function player_from_token($token): ?int {
  if (!is_uuid($token)) return null;
  $id = q('SELECT player_id FROM sessions WHERE token = ? AND expires_at > NOW()', [$token])->fetchColumn();
  return $id === false ? null : (int)$id;
}

function new_session(int $player, string $username): array {
  $token = uuid();
  q('INSERT INTO sessions (token, player_id, expires_at) VALUES (?, ?, NOW() + INTERVAL 30 DAY)', [$token, $player]);
  return ['token' => $token, 'username' => $username];
}

function check_mode($mode): string {
  if (!is_string($mode) || !in_array($mode, MODES, true)) fail('Modo de juego desconocido');
  return $mode;
}

function limit($v, int $def, int $max): int {
  return max(1, min($max, is_int($v) ? $v : $def));
}

// Dificultad por nivel (igual que en la web): tiempo y número de opciones
function round_time(int $level): float { return max(2.0, 10 * 0.82 ** ($level - 1)); }
function option_count(int $level): int { return $level >= 6 ? 8 : ($level >= 3 ? 6 : 4); }

function lock_game($id): array {
  $g = is_uuid($id) ? q('SELECT * FROM games WHERE id = ? FOR UPDATE', [$id])->fetch() : false;
  if (!$g || $g['finished']) fail('Esta partida ya ha terminado.');
  return $g;
}

/* ---------- Árbitro del modo "silueta" ---------- */

// Elige el Pokémon y las opciones de la siguiente ronda (sin empezar a contar el tiempo)
function prepare_round(string $game): void {
  $g = q('SELECT * FROM games WHERE id = ?', [$game])->fetch();
  $gens = json_decode($g['gens'], true);
  $recent = json_decode($g['recent'], true);
  $level = (int)$g['level'];
  $n = option_count($level);

  $pool = [];   // id => tipos
  $in = implode(',', array_fill(0, count($gens), '?'));
  foreach (q("SELECT id, types FROM pokemon WHERE gen IN ($in)", $gens) as $p) $pool[(int)$p['id']] = json_decode($p['types'], true);
  $ids = array_keys($pool);

  // respuesta al azar, evitando las que han salido hace poco
  $fresh = array_values(array_diff($ids, $recent));
  $choices = $fresh ?: $ids;
  $answer = $choices[random_int(0, count($choices) - 1)];

  // a partir del nivel 4, las opciones falsas comparten tipo con la respuesta (si hay suficientes)
  $others = [];
  if ($level >= 4) {
    $same = array_keys(array_filter($pool, fn($t, $id) => $id !== $answer && array_intersect($t, $pool[$answer]), ARRAY_FILTER_USE_BOTH));
    if (count($same) >= $n - 1) $others = $same;
  }
  if (!$others) $others = array_values(array_diff($ids, [$answer]));
  shuffle($others);
  $options = array_merge(array_slice($others, 0, $n - 1), [$answer]);
  shuffle($options);

  $recent[] = $answer;
  $recent = array_slice($recent, -40);
  q('UPDATE games SET answer_id = ?, options = ?, time_limit = ?, round_started = NULL, recent = ? WHERE id = ?',
    [$answer, json_encode($options), round_time($level), json_encode($recent), $game]);
}

// Cierra la partida y, si es de un jugador con cuenta, guarda su puntuación.
// Devuelve la mejor puntuación del jugador y su puesto en el ranking de ese modo (o null).
function finish_game(string $game): ?array {
  if (q('UPDATE games SET finished = 1, round_started = NULL WHERE id = ? AND finished = 0', [$game])->rowCount() === 0) return null;
  $g = q('SELECT * FROM games WHERE id = ?', [$game])->fetch();
  if ($g['player_id'] === null) return null;

  q('INSERT INTO scores (player_id, mode, score, level, hits, avg_time, gens) VALUES (?, ?, ?, ?, ?, ?, ?)', [
    $g['player_id'], $g['mode'], $g['score'], $g['level'], $g['hits'],
    $g['rounds'] > 0 ? $g['total_time'] / $g['rounds'] : null, $g['gens'],
  ]);
  $best = (int)q('SELECT MAX(score) FROM scores WHERE player_id = ? AND mode = ?', [$g['player_id'], $g['mode']])->fetchColumn();
  $rank = 1 + (int)q('SELECT COUNT(*) FROM (SELECT MAX(score) AS best FROM scores WHERE mode = ? GROUP BY player_id) b WHERE b.best > ?',
                     [$g['mode'], $best])->fetchColumn();
  return ['best' => $best, 'rank' => $rank];
}

// cada función recibe los parámetros que manda la web (mismos nombres que tenía Supabase)
$API = [

  'register' => function (array $in) {
    $user = strtolower(trim((string)($in['p_username'] ?? '')));
    $pass = (string)($in['p_password'] ?? '');
    if (!preg_match('/^[a-z0-9_]{3,16}$/', $user)) fail('El usuario debe tener de 3 a 16 caracteres: letras, números o _');
    if (strlen($pass) < 4) fail('La contraseña debe tener al menos 4 caracteres');
    if (q('SELECT 1 FROM players WHERE username = ?', [$user])->fetchColumn()) fail('Ese usuario ya existe');
    try {
      q('INSERT INTO players (username, pass_hash) VALUES (?, ?)', [$user, password_hash($pass, PASSWORD_BCRYPT)]);
    } catch (PDOException $e) {
      if ($e->errorInfo[1] === 1062) fail('Ese usuario ya existe');
      throw $e;
    }
    return new_session((int)db()->lastInsertId(), $user);
  },

  'login' => function (array $in) {
    $user = strtolower(trim((string)($in['p_username'] ?? '')));
    $p = q('SELECT id, pass_hash FROM players WHERE username = ?', [$user])->fetch();
    if (!$p || !password_verify((string)($in['p_password'] ?? ''), $p['pass_hash'])) fail('Usuario o contraseña incorrectos');
    q('DELETE FROM sessions WHERE expires_at < NOW()');
    return new_session((int)$p['id'], $user);
  },

  'whoami' => function (array $in) {
    $id = player_from_token($in['p_token'] ?? null);
    return $id === null ? null : q('SELECT username FROM players WHERE id = ?', [$id])->fetchColumn();
  },

  'logout' => function (array $in) {
    if (is_uuid($in['p_token'] ?? null)) q('DELETE FROM sessions WHERE token = ?', [$in['p_token']]);
    return null;
  },

  // Ranking de un modo: la mejor partida de cada jugador
  'leaderboard' => function (array $in) {
    $mode = check_mode($in['p_mode'] ?? null);
    $rows = q('SELECT p.username, b.score AS best_score, b.level, b.hits, b.avg_time, b.games, ' . sprintf(ISO, 'b.created_at') . ' AS achieved_at
      FROM (SELECT s.*, ROW_NUMBER() OVER (PARTITION BY s.player_id ORDER BY s.score DESC, s.created_at) AS rn,
                   COUNT(*) OVER (PARTITION BY s.player_id) AS games
            FROM scores s WHERE s.mode = ?) b
      JOIN players p ON p.id = b.player_id
      WHERE b.rn = 1
      ORDER BY b.score DESC, b.created_at
      LIMIT ' . limit($in['p_limit'] ?? null, 10, 100), [$mode])->fetchAll();
    return $rows;
  },

  // Últimas partidas del jugador con sesión (de un modo, o de todos si p_mode es null)
  'my_scores' => function (array $in) {
    $id = player_from_token($in['p_token'] ?? null);
    if ($id === null) return [];
    $mode = isset($in['p_mode']) ? check_mode($in['p_mode']) : null;
    $rows = q('SELECT mode, score, level, hits, avg_time, gens, ' . sprintf(ISO, 'created_at') . ' AS created_at
      FROM scores WHERE player_id = ? AND (? IS NULL OR mode = ?)
      ORDER BY created_at DESC LIMIT ' . limit($in['p_limit'] ?? null, 50, 200), [$id, $mode, $mode])->fetchAll();
    foreach ($rows as &$r) $r['gens'] = json_decode($r['gens'], true);
    return $rows;
  },

  // Empieza una partida. p_token null = jugar sin cuenta (no se guarda).
  // Devuelve el id de la partida y la imagen de la primera ronda para precargarla.
  'start_game' => function (array $in) {
    $mode = check_mode($in['p_mode'] ?? null);
    $gens = array_values(array_unique(array_filter((array)($in['p_gens'] ?? []), fn($x) => is_int($x) && $x >= 1 && $x <= 9)));
    sort($gens);
    if (!$gens) fail('Elige al menos una generación.');

    $player = null;
    if (($in['p_token'] ?? null) !== null) {
      $player = player_from_token($in['p_token']);
      if ($player === null) fail('Tu sesión ha caducado. Vuelve a entrar.');
      // partidas que se quedaron a medias (pestaña cerrada, etc.): se cierran y se guardan
      foreach (q('SELECT id FROM games WHERE player_id = ? AND finished = 0', [$player])->fetchAll(PDO::FETCH_COLUMN) as $old) finish_game($old);
    }
    q('DELETE FROM games WHERE created_at < NOW() - INTERVAL 1 DAY AND (finished = 1 OR player_id IS NULL)');

    $game = uuid();
    q("INSERT INTO games (id, player_id, mode, gens, recent) VALUES (?, ?, ?, ?, '[]')", [$game, $player, $mode, json_encode($gens)]);
    prepare_round($game);
    $answer = (int)q('SELECT answer_id FROM games WHERE id = ?', [$game])->fetchColumn();
    return ['game' => $game, 'img' => sprintf(IMG, $answer)];
  },

  // Muestra la ronda preparada: devuelve las opciones y empieza a contar el tiempo.
  // Solo se puede llamar una vez por ronda, así que no se puede reiniciar el reloj.
  'start_round' => function (array $in) {
    $g = lock_game($in['p_game'] ?? null);
    if ($g['round_started'] !== null) fail('Esta ronda ya ha empezado.');
    q('UPDATE games SET round_started = ? WHERE id = ?', [microtime(true), $g['id']]);
    $opts = json_decode($g['options'], true);
    $names = q('SELECT id, name FROM pokemon WHERE id IN (' . implode(',', array_map('intval', $opts)) . ')')->fetchAll(PDO::FETCH_KEY_PAIR);
    return [
      'round' => $g['rounds'] + 1,
      'level' => $g['level'],
      'time' => $g['time_limit'],
      'img' => sprintf(IMG, $g['answer_id']),
      'options' => array_map(fn($id) => $names[$id], $opts),
    ];
  },

  // Corrige la respuesta (p_choice = posición de la opción, desde 0; null = se acabó el tiempo).
  // Si acierta, prepara la siguiente ronda; si falla, termina la partida y guarda la puntuación.
  'answer_round' => function (array $in) {
    $g = lock_game($in['p_game'] ?? null);
    if ($g['round_started'] === null) fail('Esta ronda no ha empezado.');
    $choice = $in['p_choice'] ?? null;

    $limit   = (float)$g['time_limit'];
    $elapsed = microtime(true) - (float)$g['round_started'];
    $correct = array_search((int)$g['answer_id'], json_decode($g['options'], true), true);
    $late    = $elapsed > $limit + LATE_MARGIN;
    $ok      = !$late && is_int($choice) && $choice === $correct;
    $ans     = q('SELECT id, name, types FROM pokemon WHERE id = ?', [$g['answer_id']])->fetch();

    $rounds = $g['rounds'] + 1;
    $total  = $g['total_time'] + min($elapsed, $limit);
    $streak = $g['streak']; $score = $g['score']; $hits = $g['hits']; $level = $g['level'];
    $gained = 0; $levelUp = false;
    if ($ok) {
      $streak++;
      $gained = (int)round((100 + max(0, 1 - $elapsed / $limit) * 150) * min(1 + ($streak - 1) * 0.5, 4) * $level);
      $score += $gained;
      $hits++;
      if (1 + intdiv($hits, HITS_PER_LEVEL) > $level) { $level = 1 + intdiv($hits, HITS_PER_LEVEL); $levelUp = true; }
    } else {
      $streak = 0;
    }
    q('UPDATE games SET rounds = ?, total_time = ?, streak = ?, score = ?, hits = ?, level = ?, round_started = NULL WHERE id = ?',
      [$rounds, $total, $streak, $score, $hits, $level, $g['id']]);

    $next = null; $saved = null;
    if ($ok) {
      prepare_round($g['id']);
      $next = sprintf(IMG, (int)q('SELECT answer_id FROM games WHERE id = ?', [$g['id']])->fetchColumn());
    } else {
      $saved = finish_game($g['id']);
    }
    return [
      'ok' => $ok,
      'late' => $late || $choice === null,
      'correct' => $correct,
      'answer' => ['id' => (int)$ans['id'], 'name' => $ans['name'], 'types' => json_decode($ans['types'], true)],
      'gained' => $gained,
      'score' => $score,
      'level' => $level,
      'hits' => $hits,
      'streak' => $streak,
      'avg_time' => $total / $rounds,
      'level_up' => $levelUp,
      'next_time' => round_time($level),
      'next_img' => $next,
      'over' => !$ok,
      'saved' => $saved,
    ];
  },

  // Abandonar la partida (botón MENÚ): se cierra y se guarda tal como está
  'end_game' => function (array $in) {
    return is_uuid($in['p_game'] ?? null) ? finish_game($in['p_game']) : null;
  },
];

try {
  if ($_SERVER['REQUEST_METHOD'] !== 'POST') fail('Usa POST');
  $fn = $_GET['fn'] ?? '';
  if (!isset($API[$fn])) fail('Función desconocida');
  $in = json_decode(file_get_contents('php://input') ?: '{}', true);
  if (!is_array($in)) fail('Petición no válida');
  db()->beginTransaction();
  $out = $API[$fn]($in);
  db()->commit();
  echo json_encode($out, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION);
} catch (Throwable $e) {
  try { if (db()->inTransaction()) db()->rollBack(); } catch (Throwable) {}
  if ($e instanceof Fail) {
    http_response_code(400);
    echo json_encode(['message' => $e->getMessage()], JSON_UNESCAPED_UNICODE);
  } else {
    error_log((string)$e);
    http_response_code(500);
    echo json_encode(['message' => 'Error del servidor']);
  }
}
