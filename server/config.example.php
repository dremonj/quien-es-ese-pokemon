<?php
// Copia este archivo como config.php en el servidor y rellena los datos de MySQL.
// config.php NO se sube a GitHub (está en .gitignore): contiene la contraseña de la base de datos.
return [
  'db_host' => 'localhost',
  'db_name' => 'nombre_de_la_base',
  'db_user' => 'usuario_de_la_base',
  'db_pass' => 'contraseña',
  'install_key' => '',   // clave larga al azar para abrir install.php una vez; déjala vacía después
];
