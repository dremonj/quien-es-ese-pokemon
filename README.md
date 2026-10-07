# ¿Quién es ese Pokémon?

Juego web para adivinar Pokémon por su silueta. Los datos se obtienen de la [PokéAPI](https://pokeapi.co/).

**Jugar:** http://netanyahu.mataxetos.es/

## Cómo se juega

- Entra con un usuario y una contraseña (o crea una cuenta). También se puede jugar sin cuenta, pero entonces no se guarda nada.
- Aparece la silueta de un Pokémon y eliges su nombre entre varias opciones (teclas 1–8 o clic).
- Un fallo y se acaba la partida. Cada 5 aciertos subes de nivel: menos tiempo, más opciones, opciones del mismo tipo, siluetas en espejo y recortadas.
- Puedes elegir las generaciones (1 a 9).
- Al terminar ves tu tiempo medio por respuesta.
- Tras entrar eliges el modo de juego. Cada modo tiene su propio ranking.
- Todas las partidas se guardan en la base de datos. Al lado del juego se ve el mejor jugador y el top 10 del modo elegido.

## Servidor

La web y el servidor están en un hosting con PHP y MySQL (MariaDB).

| Archivo | Qué es | ¿Se sube al hosting? |
|---|---|---|
| `index.html`, `config.js` | La página del juego | Sí |
| `server/api.php` | El servidor: cuentas, partidas y ranking | Sí, junto a `index.html` |
| `server/config.php` | Datos de conexión a MySQL. **No está en GitHub**: créalo copiando `server/config.example.php` | Sí |
| `server/install.php`, `server/schema.sql`, `server/pokemon.json` | Instalación: crea las tablas y carga los 1025 Pokémon | Solo para instalar; bórralos después |

Para instalar en un hosting nuevo: sube todo a la carpeta de la web, pon una `install_key` larga al azar en `config.php`, abre `install.php?key=<esa clave>` y después borra los archivos de instalación.

### Seguridad

- La web no toca la base de datos: solo llama a `api.php`. Las contraseñas se guardan cifradas con bcrypt.
- La partida la arbitra el servidor, para que no se pueda hacer trampa desde la consola del navegador. Él elige el Pokémon y las opciones, mide el tiempo, corrige cada respuesta, calcula los puntos y guarda la puntuación al terminar (`start_game`, `start_round`, `answer_round`, `end_game`). La página no conoce la respuesta hasta que contestas y no puede enviar puntuaciones.

Hasta octubre de 2026 el juego estuvo en GitHub Pages con [Supabase](https://supabase.com/) como base de datos; el script de entonces (`supabase.sql`) está en el historial del repositorio.
