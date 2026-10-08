<?php
// Prepara el entorno local (lo llama dev.bat cada vez; si ya está todo listo, no hace nada):
//   1. crea server/config.local.php si no existe
//   2. crea la base de datos local y carga las tablas y los Pokémon la primera vez
declare(strict_types=1);
$server = dirname(__DIR__) . '/server';
$cfgFile = "$server/config.local.php";

if (!is_file($cfgFile)) {
  file_put_contents($cfgFile, <<<'PHP'
<?php
// Configuración SOLO para probar en tu PC (MySQL de XAMPP). No se sube a GitHub ni al servidor.
return [
  'db_host' => '127.0.0.1',
  'db_name' => 'pokemon_local',
  'db_user' => 'root',
  'db_pass' => '',
  'install_key' => 'local',
];

PHP);
  echo "Creado server/config.local.php\n";
}
$c = require $cfgFile;

// MySQL puede tardar unos segundos en arrancar
for ($i = 0; ; $i++) {
  try {
    $db = new PDO("mysql:host={$c['db_host']};charset=utf8mb4", $c['db_user'], $c['db_pass'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    break;
  } catch (PDOException $e) {
    if ($i >= 15) { fwrite(STDERR, "No se pudo conectar con MySQL: {$e->getMessage()}\n¿Está instalado XAMPP en C:\xampp?\n"); exit(1); }
    sleep(1);
  }
}
$db->exec("CREATE DATABASE IF NOT EXISTS `{$c['db_name']}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
$db->exec("USE `{$c['db_name']}`");

$ready = $db->query("SHOW TABLES LIKE 'pokemon'")->fetch() && (int)$db->query('SELECT COUNT(*) FROM pokemon')->fetchColumn() > 0;
if (!$ready) {
  $_GET['key'] = $c['install_key'];
  require "$server/install.php";
}
