<?php
// Router para probar el juego en local con el servidor integrado de PHP (lo usa dev.bat).
// Imita la estructura del servidor real: index.html, config.js, api.php e install.php en la misma carpeta.
$root = dirname(__DIR__);
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if ($path === '/api.php' || $path === '/install.php') {
  require $root . '/server' . $path;
  return true;
}
if ($path === '/') $path = '/index.html';
if (in_array($path, ['/index.html', '/config.js'], true)) return false;  // archivo estático

http_response_code(404);
echo 'No encontrado';
