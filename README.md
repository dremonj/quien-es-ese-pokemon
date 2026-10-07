# ¿Quién es ese Pokémon?

Juego web para adivinar Pokémon por su silueta. Los datos se obtienen de la [PokéAPI](https://pokeapi.co/).

**Jugar:** https://dremonj.github.io/quien-es-ese-pokemon/

## Cómo se juega

- Entra con un usuario y una contraseña (o crea una cuenta). También se puede jugar sin cuenta, pero entonces no se guarda nada.
- Aparece la silueta de un Pokémon y eliges su nombre entre varias opciones (teclas 1–8 o clic).
- Un fallo y se acaba la partida. Cada 5 aciertos subes de nivel: menos tiempo, más opciones, opciones del mismo tipo, siluetas en espejo y recortadas.
- Puedes elegir las generaciones (1 a 9).
- Al terminar ves tu tiempo medio por respuesta.
- Tras entrar eliges el modo de juego. Cada modo tiene su propio ranking.
- Todas las partidas se guardan en la base de datos. Al lado del juego se ve el mejor jugador y el top 10 del modo elegido.

## Base de datos

Los usuarios y las puntuaciones se guardan en [Supabase](https://supabase.com/).

- `supabase.sql` crea las tablas y las funciones. Ejecútalo en el SQL Editor de Supabase.
- `config.js` contiene la URL del proyecto y la clave pública (publishable). Nunca pongas ahí la clave secret o service_role.
- Las tablas no se pueden leer desde la web; solo se accede mediante las funciones `register`, `login`, `start_game`, `leaderboard`, etc. Las contraseñas se guardan cifradas con bcrypt.
- La partida la arbitra la base de datos, para que no se pueda hacer trampa desde la consola del navegador. Ella elige el Pokémon y las opciones, mide el tiempo, corrige cada respuesta, calcula los puntos y guarda la puntuación al terminar (`start_game`, `start_round`, `answer_round`, `end_game`). La página no conoce la respuesta hasta que contestas y no puede enviar puntuaciones.
- La tabla `pokemon` (nombre en español, generación y tipos) se rellena al final de `supabase.sql` con datos de la PokéAPI.
