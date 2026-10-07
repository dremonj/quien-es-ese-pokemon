-- Base de datos de "¿Quién es ese Pokémon?" para Supabase.
-- Cómo usarlo: en tu proyecto de Supabase abre SQL Editor > New query, pega todo este archivo y pulsa Run.
-- Se puede ejecutar varias veces sin romper nada.
--
-- Diseño: las tablas no se pueden leer ni escribir directamente desde la web.
-- La página solo llama a las funciones de abajo (register, login, start_game, leaderboard...),
-- que comprueban la sesión y nunca devuelven contraseñas.
--
-- Anti-trampas: la partida la arbitra la base de datos. Ella elige el Pokémon y las opciones,
-- mide el tiempo con su propio reloj, corrige cada respuesta, calcula los puntos y guarda la
-- puntuación al terminar. La página nunca conoce la respuesta antes de contestar ni envía puntos.

create extension if not exists pgcrypto with schema extensions;

-- Jugadores: usuario + contraseña cifrada con bcrypt
create table if not exists public.players (
  id         bigint generated always as identity primary key,
  username   text not null unique check (username ~ '^[a-z0-9_]{3,16}$'),
  pass_hash  text not null,
  created_at timestamptz not null default now()
);

-- Sesiones: la web guarda solo el token, no la contraseña
create table if not exists public.sessions (
  token      uuid primary key default gen_random_uuid(),
  player_id  bigint not null references public.players(id) on delete cascade,
  expires_at timestamptz not null default now() + interval '30 days'
);

-- Resultados de cada partida (cada modo de juego tiene su propio ranking)
create table if not exists public.scores (
  id         bigint generated always as identity primary key,
  player_id  bigint not null references public.players(id) on delete cascade,
  mode       text not null default 'silueta',
  score      integer not null check (score >= 0),
  level      integer not null check (level >= 1),
  hits       integer not null check (hits >= 0),
  avg_time   real check (avg_time is null or avg_time >= 0),
  gens       smallint[] not null default '{}',
  created_at timestamptz not null default now()
);
-- para bases de datos creadas antes de que existieran los modos
alter table public.scores add column if not exists mode text not null default 'silueta';

-- Reglas de cada modo (se recrean para que el script se pueda ejecutar varias veces)
alter table public.scores drop constraint if exists scores_mode_format;
alter table public.scores drop constraint if exists scores_level_matches_hits;
alter table public.scores drop constraint if exists scores_score_possible;
alter table public.scores add constraint scores_mode_format check (mode ~ '^[a-z0-9_]{1,32}$');
-- modo "silueta": 5 aciertos por nivel, máximo 1000 puntos por acierto y nivel
alter table public.scores add constraint scores_level_matches_hits check (mode <> 'silueta' or level = 1 + hits / 5);
alter table public.scores add constraint scores_score_possible check (mode <> 'silueta' or score <= 1000 * hits * level);

create index if not exists scores_player_score_idx on public.scores (player_id, score desc);
create index if not exists scores_mode_score_idx on public.scores (mode, score desc);
drop index if exists public.scores_score_idx;

-- Pokémon (datos de la PokéAPI, se rellenan al final del archivo)
create table if not exists public.pokemon (
  id    integer primary key,
  name  text not null,       -- nombre en español
  gen   smallint not null,   -- generación 1-9
  types text[] not null      -- tipos en inglés, como en la PokéAPI
);

-- Partidas en curso. La respuesta de la ronda actual solo la conoce la base de datos.
create table if not exists public.games (
  id            uuid primary key default gen_random_uuid(),
  player_id     bigint references public.players(id) on delete cascade,  -- null = jugando sin cuenta
  mode          text not null,
  gens          smallint[] not null,
  score         integer not null default 0,
  level         integer not null default 1,
  hits          integer not null default 0,
  streak        integer not null default 0,
  rounds        integer not null default 0,     -- rondas respondidas
  total_time    real not null default 0,        -- suma de tiempos de respuesta (para la media)
  recent        integer[] not null default '{}', -- últimos Pokémon salidos, para no repetir
  answer_id     integer,                        -- respuesta de la ronda actual
  options       integer[],                      -- opciones de la ronda actual, en orden de pantalla
  time_limit    real,                           -- segundos de la ronda actual
  round_started timestamptz,                    -- null = ronda preparada pero aún no mostrada
  finished      boolean not null default false,
  created_at    timestamptz not null default now()
);
create index if not exists games_open_idx on public.games (player_id) where not finished;

alter table public.players  enable row level security;
alter table public.sessions enable row level security;
alter table public.scores   enable row level security;
alter table public.pokemon  enable row level security;
alter table public.games    enable row level security;
-- Sin políticas RLS a propósito: acceso solo a través de las funciones.
revoke all on public.players, public.sessions, public.scores, public.pokemon, public.games from anon, authenticated;


-- Devuelve el jugador de un token válido (uso interno)
create or replace function public._player_from_token(p_token uuid)
returns bigint
language sql stable security definer set search_path = public
as $$
  select player_id from sessions where token = p_token and expires_at > now()
$$;
revoke all on function public._player_from_token(uuid) from public, anon, authenticated;


create or replace function public.register(p_username text, p_password text)
returns json
language plpgsql security definer set search_path = public, extensions
as $$
declare
  v_user  text := lower(trim(p_username));
  v_id    bigint;
  v_token uuid;
begin
  if v_user !~ '^[a-z0-9_]{3,16}$' then
    raise exception 'El usuario debe tener de 3 a 16 caracteres: letras, números o _';
  end if;
  if coalesce(length(p_password), 0) < 4 then
    raise exception 'La contraseña debe tener al menos 4 caracteres';
  end if;
  if exists (select 1 from players where username = v_user) then
    raise exception 'Ese usuario ya existe';
  end if;
  insert into players (username, pass_hash)
  values (v_user, crypt(p_password, gen_salt('bf')))
  returning id into v_id;
  insert into sessions (player_id) values (v_id) returning token into v_token;
  return json_build_object('token', v_token, 'username', v_user);
end
$$;


create or replace function public.login(p_username text, p_password text)
returns json
language plpgsql security definer set search_path = public, extensions
as $$
declare
  v_user  text := lower(trim(p_username));
  v_id    bigint;
  v_hash  text;
  v_token uuid;
begin
  select id, pass_hash into v_id, v_hash from players where username = v_user;
  if v_id is null or v_hash <> crypt(coalesce(p_password, ''), v_hash) then
    raise exception 'Usuario o contraseña incorrectos';
  end if;
  delete from sessions where expires_at < now();
  insert into sessions (player_id) values (v_id) returning token into v_token;
  return json_build_object('token', v_token, 'username', v_user);
end
$$;


create or replace function public.whoami(p_token uuid)
returns text
language sql stable security definer set search_path = public
as $$
  select p.username from players p where p.id = _player_from_token(p_token)
$$;


create or replace function public.logout(p_token uuid)
returns void
language sql security definer set search_path = public
as $$
  delete from sessions where token = p_token
$$;


-- Versiones antiguas (sin modos de juego)
drop function if exists public.submit_score(uuid, integer, integer, integer, real, smallint[]);
drop function if exists public.leaderboard(integer);
drop function if exists public.my_scores(uuid, integer);


-- La web ya no puede enviar puntuaciones: las guarda la propia base de datos al terminar la partida
drop function if exists public.submit_score(uuid, text, integer, integer, integer, real, smallint[]);


/* ---------- Árbitro del modo "silueta" ---------- */

-- Dificultad por nivel (igual que en la web): tiempo y número de opciones
create or replace function public._round_time(p_level integer)
returns real language sql immutable
as $$ select greatest(2, 10 * power(0.82, p_level - 1))::real $$;

create or replace function public._option_count(p_level integer)
returns integer language sql immutable
as $$ select case when p_level >= 6 then 8 when p_level >= 3 then 6 else 4 end $$;

create or replace function public._img(p_id integer)
returns text language sql immutable
as $$ select 'https://raw.githubusercontent.com/PokeAPI/sprites/master/sprites/pokemon/other/official-artwork/' || p_id || '.png' $$;


-- Elige el Pokémon y las opciones de la siguiente ronda (sin empezar a contar el tiempo)
create or replace function public._prepare_round(p_game uuid)
returns void
language plpgsql security definer set search_path = public
as $$
declare
  g        games%rowtype;
  n        integer;
  v_answer integer;
  v_types  text[];
  v_others integer[];
  v_opts   integer[];
begin
  select * into g from games where id = p_game;
  n := _option_count(g.level);

  -- respuesta al azar, evitando las que han salido hace poco
  select id into v_answer from pokemon
  where gen = any(g.gens) and not (id = any(g.recent))
  order by random() limit 1;
  if v_answer is null then
    select id into v_answer from pokemon where gen = any(g.gens) order by random() limit 1;
  end if;

  -- a partir del nivel 4, las opciones falsas comparten tipo con la respuesta (si hay suficientes)
  if g.level >= 4 then
    select types into v_types from pokemon where id = v_answer;
    select array_agg(id) into v_others from (
      select id from pokemon
      where gen = any(g.gens) and id <> v_answer and types && v_types
      order by random() limit n - 1
    ) s;
  end if;
  if coalesce(cardinality(v_others), 0) < n - 1 then
    select array_agg(id) into v_others from (
      select id from pokemon where gen = any(g.gens) and id <> v_answer order by random() limit n - 1
    ) s;
  end if;

  select array_agg(x order by random()) into v_opts from unnest(v_others || v_answer) x;
  g.recent := array_append(g.recent, v_answer);
  g.recent := g.recent[greatest(1, cardinality(g.recent) - 39):];

  update games
  set answer_id = v_answer, options = v_opts, time_limit = _round_time(g.level),
      round_started = null, recent = g.recent
  where id = p_game;
end
$$;


-- Cierra la partida y, si es de un jugador con cuenta, guarda su puntuación.
-- Devuelve la mejor puntuación del jugador y su puesto en el ranking de ese modo (o null).
create or replace function public._finish_game(p_game uuid)
returns json
language plpgsql security definer set search_path = public
as $$
declare
  g      games%rowtype;
  v_best integer;
  v_rank integer;
begin
  update games set finished = true, round_started = null
  where id = p_game and not finished
  returning * into g;
  if not found or g.player_id is null then
    return null;
  end if;

  insert into scores (player_id, mode, score, level, hits, avg_time, gens)
  values (g.player_id, g.mode, g.score, g.level, g.hits,
          case when g.rounds > 0 then g.total_time / g.rounds end, g.gens);

  select max(score) into v_best from scores where player_id = g.player_id and mode = g.mode;
  select 1 + count(*) into v_rank
  from (select player_id, max(score) as best from scores where mode = g.mode group by player_id) b
  where b.best > v_best;
  return json_build_object('best', v_best, 'rank', v_rank);
end
$$;


-- Empieza una partida. p_token null = jugar sin cuenta (no se guarda).
-- Devuelve el id de la partida y la imagen de la primera ronda para precargarla.
create or replace function public.start_game(p_token uuid, p_mode text, p_gens smallint[])
returns json
language plpgsql security definer set search_path = public, extensions
as $$
declare
  v_player bigint;
  v_gens   smallint[];
  v_game   uuid;
begin
  if p_mode is distinct from 'silueta' then
    raise exception 'Modo de juego desconocido';
  end if;
  select array_agg(distinct x order by x) into v_gens from unnest(p_gens) x where x between 1 and 9;
  if v_gens is null then
    raise exception 'Elige al menos una generación.';
  end if;

  if p_token is not null then
    v_player := _player_from_token(p_token);
    if v_player is null then
      raise exception 'Tu sesión ha caducado. Vuelve a entrar.';
    end if;
    -- partidas que se quedaron a medias (pestaña cerrada, etc.): se cierran y se guardan
    perform _finish_game(id) from games where player_id = v_player and not finished;
  end if;
  delete from games where created_at < now() - interval '1 day' and (finished or player_id is null);

  insert into games (player_id, mode, gens) values (v_player, p_mode, v_gens) returning id into v_game;
  perform _prepare_round(v_game);
  return json_build_object('game', v_game, 'img', (select _img(answer_id) from games where id = v_game));
end
$$;


-- Muestra la ronda preparada: devuelve las opciones y empieza a contar el tiempo.
-- Solo se puede llamar una vez por ronda, así que no se puede reiniciar el reloj.
create or replace function public.start_round(p_game uuid)
returns json
language plpgsql security definer set search_path = public
as $$
declare
  g games%rowtype;
begin
  select * into g from games where id = p_game for update;
  if not found or g.finished then
    raise exception 'Esta partida ya ha terminado.';
  end if;
  if g.round_started is not null then
    raise exception 'Esta ronda ya ha empezado.';
  end if;
  update games set round_started = now() where id = p_game;
  return json_build_object(
    'round', g.rounds + 1,
    'level', g.level,
    'time', g.time_limit,
    'img', _img(g.answer_id),
    'options', (select json_agg(p.name order by o.ord)
                from unnest(g.options) with ordinality o(id, ord) join pokemon p on p.id = o.id)
  );
end
$$;


-- Corrige la respuesta (p_choice = posición de la opción, desde 0; null = se acabó el tiempo).
-- Si acierta, prepara la siguiente ronda; si falla, termina la partida y guarda la puntuación.
create or replace function public.answer_round(p_game uuid, p_choice integer)
returns json
language plpgsql security definer set search_path = public
as $$
declare
  g         games%rowtype;
  v_ans     pokemon%rowtype;
  v_elapsed real;
  v_correct integer;
  v_late    boolean;
  v_ok      boolean;
  v_gained  integer := 0;
  v_lvlup   boolean := false;
  v_saved   json;
  v_next    text;
begin
  select * into g from games where id = p_game for update;
  if not found or g.finished then
    raise exception 'Esta partida ya ha terminado.';
  end if;
  if g.round_started is null then
    raise exception 'Esta ronda no ha empezado.';
  end if;

  v_elapsed := extract(epoch from now() - g.round_started);
  v_correct := array_position(g.options, g.answer_id) - 1;
  v_late    := v_elapsed > g.time_limit + 1.5;   -- margen para lo que tarda la conexión
  v_ok      := not v_late and p_choice is not null and p_choice = v_correct;
  select * into v_ans from pokemon where id = g.answer_id;

  g.rounds     := g.rounds + 1;
  g.total_time := g.total_time + least(v_elapsed, g.time_limit);
  if v_ok then
    g.streak := g.streak + 1;
    v_gained := round((100 + greatest(0, 1 - v_elapsed / g.time_limit)::float8 * 150)
                      * least(1 + (g.streak - 1) * 0.5, 4)::float8 * g.level);
    g.score := g.score + v_gained;
    g.hits  := g.hits + 1;
    if 1 + g.hits / 5 > g.level then
      g.level := 1 + g.hits / 5;
      v_lvlup := true;
    end if;
  else
    g.streak := 0;
  end if;

  update games
  set rounds = g.rounds, total_time = g.total_time, streak = g.streak,
      score = g.score, hits = g.hits, level = g.level, round_started = null
  where id = p_game;

  if v_ok then
    perform _prepare_round(p_game);
    select _img(answer_id) into v_next from games where id = p_game;
  else
    v_saved := _finish_game(p_game);
  end if;

  return json_build_object(
    'ok', v_ok,
    'late', v_late or p_choice is null,
    'correct', v_correct,
    'answer', json_build_object('id', v_ans.id, 'name', v_ans.name, 'types', v_ans.types),
    'gained', v_gained,
    'score', g.score,
    'level', g.level,
    'hits', g.hits,
    'streak', g.streak,
    'avg_time', g.total_time / g.rounds,
    'level_up', v_lvlup,
    'next_time', _round_time(g.level),
    'next_img', v_next,
    'over', not v_ok,
    'saved', v_saved
  );
end
$$;


-- Abandonar la partida (botón MENÚ): se cierra y se guarda tal como está
create or replace function public.end_game(p_game uuid)
returns json
language sql security definer set search_path = public
as $$ select _finish_game(p_game) $$;


revoke all on function
  public._round_time(integer),
  public._option_count(integer),
  public._img(integer),
  public._prepare_round(uuid),
  public._finish_game(uuid)
from public, anon, authenticated;


-- Ranking de un modo: la mejor partida de cada jugador
create or replace function public.leaderboard(p_mode text, p_limit integer default 10)
returns table (username text, best_score integer, level integer, hits integer, avg_time real, games bigint, achieved_at timestamptz)
language sql stable security definer set search_path = public
as $$
  with best as (
    select distinct on (s.player_id) s.player_id, s.score, s.level, s.hits, s.avg_time, s.created_at
    from scores s
    where s.mode = p_mode
    order by s.player_id, s.score desc, s.created_at asc
  ), games as (
    select player_id, count(*) as n from scores where mode = p_mode group by player_id
  )
  select p.username, b.score, b.level, b.hits, b.avg_time, g.n, b.created_at
  from best b
  join players p on p.id = b.player_id
  join games g on g.player_id = b.player_id
  order by b.score desc, b.created_at asc
  limit least(greatest(coalesce(p_limit, 10), 1), 100)
$$;


-- Últimas partidas del jugador con sesión (de un modo, o de todos si p_mode es null)
create or replace function public.my_scores(p_token uuid, p_mode text default null, p_limit integer default 50)
returns table (mode text, score integer, level integer, hits integer, avg_time real, gens smallint[], created_at timestamptz)
language sql stable security definer set search_path = public
as $$
  select s.mode, s.score, s.level, s.hits, s.avg_time, s.gens, s.created_at
  from scores s
  where s.player_id = _player_from_token(p_token)
    and (p_mode is null or s.mode = p_mode)
  order by s.created_at desc
  limit least(greatest(coalesce(p_limit, 50), 1), 200)
$$;


grant execute on function
  public.register(text, text),
  public.login(text, text),
  public.whoami(uuid),
  public.logout(uuid),
  public.start_game(uuid, text, smallint[]),
  public.start_round(uuid),
  public.answer_round(uuid, integer),
  public.end_game(uuid),
  public.leaderboard(text, integer),
  public.my_scores(uuid, text, integer)
to anon, authenticated;


-- Datos de los Pokémon (PokéAPI): id, nombre en español, generación y tipos
insert into public.pokemon (id, name, gen, types) values
(1,'Bulbasaur',1,'{grass,poison}'),
(2,'Ivysaur',1,'{grass,poison}'),
(3,'Venusaur',1,'{grass,poison}'),
(4,'Charmander',1,'{fire}'),
(5,'Charmeleon',1,'{fire}'),
(6,'Charizard',1,'{fire,flying}'),
(7,'Squirtle',1,'{water}'),
(8,'Wartortle',1,'{water}'),
(9,'Blastoise',1,'{water}'),
(10,'Caterpie',1,'{bug}'),
(11,'Metapod',1,'{bug}'),
(12,'Butterfree',1,'{bug,flying}'),
(13,'Weedle',1,'{bug,poison}'),
(14,'Kakuna',1,'{bug,poison}'),
(15,'Beedrill',1,'{bug,poison}'),
(16,'Pidgey',1,'{normal,flying}'),
(17,'Pidgeotto',1,'{normal,flying}'),
(18,'Pidgeot',1,'{normal,flying}'),
(19,'Rattata',1,'{normal}'),
(20,'Raticate',1,'{normal}'),
(21,'Spearow',1,'{normal,flying}'),
(22,'Fearow',1,'{normal,flying}'),
(23,'Ekans',1,'{poison}'),
(24,'Arbok',1,'{poison}'),
(25,'Pikachu',1,'{electric}'),
(26,'Raichu',1,'{electric}'),
(27,'Sandshrew',1,'{ground}'),
(28,'Sandslash',1,'{ground}'),
(29,'Nidoran♀',1,'{poison}'),
(30,'Nidorina',1,'{poison}'),
(31,'Nidoqueen',1,'{poison,ground}'),
(32,'Nidoran♂',1,'{poison}'),
(33,'Nidorino',1,'{poison}'),
(34,'Nidoking',1,'{poison,ground}'),
(35,'Clefairy',1,'{fairy}'),
(36,'Clefable',1,'{fairy}'),
(37,'Vulpix',1,'{fire}'),
(38,'Ninetales',1,'{fire}'),
(39,'Jigglypuff',1,'{normal,fairy}'),
(40,'Wigglytuff',1,'{normal,fairy}'),
(41,'Zubat',1,'{poison,flying}'),
(42,'Golbat',1,'{poison,flying}'),
(43,'Oddish',1,'{grass,poison}'),
(44,'Gloom',1,'{grass,poison}'),
(45,'Vileplume',1,'{grass,poison}'),
(46,'Paras',1,'{bug,grass}'),
(47,'Parasect',1,'{bug,grass}'),
(48,'Venonat',1,'{bug,poison}'),
(49,'Venomoth',1,'{bug,poison}'),
(50,'Diglett',1,'{ground}'),
(51,'Dugtrio',1,'{ground}'),
(52,'Meowth',1,'{normal}'),
(53,'Persian',1,'{normal}'),
(54,'Psyduck',1,'{water}'),
(55,'Golduck',1,'{water}'),
(56,'Mankey',1,'{fighting}'),
(57,'Primeape',1,'{fighting}'),
(58,'Growlithe',1,'{fire}'),
(59,'Arcanine',1,'{fire}'),
(60,'Poliwag',1,'{water}'),
(61,'Poliwhirl',1,'{water}'),
(62,'Poliwrath',1,'{water,fighting}'),
(63,'Abra',1,'{psychic}'),
(64,'Kadabra',1,'{psychic}'),
(65,'Alakazam',1,'{psychic}'),
(66,'Machop',1,'{fighting}'),
(67,'Machoke',1,'{fighting}'),
(68,'Machamp',1,'{fighting}'),
(69,'Bellsprout',1,'{grass,poison}'),
(70,'Weepinbell',1,'{grass,poison}'),
(71,'Victreebel',1,'{grass,poison}'),
(72,'Tentacool',1,'{water,poison}'),
(73,'Tentacruel',1,'{water,poison}'),
(74,'Geodude',1,'{rock,ground}'),
(75,'Graveler',1,'{rock,ground}'),
(76,'Golem',1,'{rock,ground}'),
(77,'Ponyta',1,'{fire}'),
(78,'Rapidash',1,'{fire}'),
(79,'Slowpoke',1,'{water,psychic}'),
(80,'Slowbro',1,'{water,psychic}'),
(81,'Magnemite',1,'{electric,steel}'),
(82,'Magneton',1,'{electric,steel}'),
(83,'Farfetch’d',1,'{normal,flying}'),
(84,'Doduo',1,'{normal,flying}'),
(85,'Dodrio',1,'{normal,flying}'),
(86,'Seel',1,'{water}'),
(87,'Dewgong',1,'{water,ice}'),
(88,'Grimer',1,'{poison}'),
(89,'Muk',1,'{poison}'),
(90,'Shellder',1,'{water}'),
(91,'Cloyster',1,'{water,ice}'),
(92,'Gastly',1,'{ghost,poison}'),
(93,'Haunter',1,'{ghost,poison}'),
(94,'Gengar',1,'{ghost,poison}'),
(95,'Onix',1,'{rock,ground}'),
(96,'Drowzee',1,'{psychic}'),
(97,'Hypno',1,'{psychic}'),
(98,'Krabby',1,'{water}'),
(99,'Kingler',1,'{water}'),
(100,'Voltorb',1,'{electric}'),
(101,'Electrode',1,'{electric}'),
(102,'Exeggcute',1,'{grass,psychic}'),
(103,'Exeggutor',1,'{grass,psychic}'),
(104,'Cubone',1,'{ground}'),
(105,'Marowak',1,'{ground}'),
(106,'Hitmonlee',1,'{fighting}'),
(107,'Hitmonchan',1,'{fighting}'),
(108,'Lickitung',1,'{normal}'),
(109,'Koffing',1,'{poison}'),
(110,'Weezing',1,'{poison}'),
(111,'Rhyhorn',1,'{ground,rock}'),
(112,'Rhydon',1,'{ground,rock}'),
(113,'Chansey',1,'{normal}'),
(114,'Tangela',1,'{grass}'),
(115,'Kangaskhan',1,'{normal}'),
(116,'Horsea',1,'{water}'),
(117,'Seadra',1,'{water}'),
(118,'Goldeen',1,'{water}'),
(119,'Seaking',1,'{water}'),
(120,'Staryu',1,'{water}'),
(121,'Starmie',1,'{water,psychic}'),
(122,'Mr. Mime',1,'{psychic,fairy}'),
(123,'Scyther',1,'{bug,flying}'),
(124,'Jynx',1,'{ice,psychic}'),
(125,'Electabuzz',1,'{electric}'),
(126,'Magmar',1,'{fire}'),
(127,'Pinsir',1,'{bug}'),
(128,'Tauros',1,'{normal}'),
(129,'Magikarp',1,'{water}'),
(130,'Gyarados',1,'{water,flying}'),
(131,'Lapras',1,'{water,ice}'),
(132,'Ditto',1,'{normal}'),
(133,'Eevee',1,'{normal}'),
(134,'Vaporeon',1,'{water}'),
(135,'Jolteon',1,'{electric}'),
(136,'Flareon',1,'{fire}'),
(137,'Porygon',1,'{normal}'),
(138,'Omanyte',1,'{rock,water}'),
(139,'Omastar',1,'{rock,water}'),
(140,'Kabuto',1,'{rock,water}'),
(141,'Kabutops',1,'{rock,water}'),
(142,'Aerodactyl',1,'{rock,flying}'),
(143,'Snorlax',1,'{normal}'),
(144,'Articuno',1,'{ice,flying}'),
(145,'Zapdos',1,'{electric,flying}'),
(146,'Moltres',1,'{fire,flying}'),
(147,'Dratini',1,'{dragon}'),
(148,'Dragonair',1,'{dragon}'),
(149,'Dragonite',1,'{dragon,flying}'),
(150,'Mewtwo',1,'{psychic}'),
(151,'Mew',1,'{psychic}'),
(152,'Chikorita',2,'{grass}'),
(153,'Bayleef',2,'{grass}'),
(154,'Meganium',2,'{grass}'),
(155,'Cyndaquil',2,'{fire}'),
(156,'Quilava',2,'{fire}'),
(157,'Typhlosion',2,'{fire}'),
(158,'Totodile',2,'{water}'),
(159,'Croconaw',2,'{water}'),
(160,'Feraligatr',2,'{water}'),
(161,'Sentret',2,'{normal}'),
(162,'Furret',2,'{normal}'),
(163,'Hoothoot',2,'{normal,flying}'),
(164,'Noctowl',2,'{normal,flying}'),
(165,'Ledyba',2,'{bug,flying}'),
(166,'Ledian',2,'{bug,flying}'),
(167,'Spinarak',2,'{bug,poison}'),
(168,'Ariados',2,'{bug,poison}'),
(169,'Crobat',2,'{poison,flying}'),
(170,'Chinchou',2,'{water,electric}'),
(171,'Lanturn',2,'{water,electric}'),
(172,'Pichu',2,'{electric}'),
(173,'Cleffa',2,'{fairy}'),
(174,'Igglybuff',2,'{normal,fairy}'),
(175,'Togepi',2,'{fairy}'),
(176,'Togetic',2,'{fairy,flying}'),
(177,'Natu',2,'{psychic,flying}'),
(178,'Xatu',2,'{psychic,flying}'),
(179,'Mareep',2,'{electric}'),
(180,'Flaaffy',2,'{electric}'),
(181,'Ampharos',2,'{electric}'),
(182,'Bellossom',2,'{grass}'),
(183,'Marill',2,'{water,fairy}'),
(184,'Azumarill',2,'{water,fairy}'),
(185,'Sudowoodo',2,'{rock}'),
(186,'Politoed',2,'{water}'),
(187,'Hoppip',2,'{grass,flying}'),
(188,'Skiploom',2,'{grass,flying}'),
(189,'Jumpluff',2,'{grass,flying}'),
(190,'Aipom',2,'{normal}'),
(191,'Sunkern',2,'{grass}'),
(192,'Sunflora',2,'{grass}'),
(193,'Yanma',2,'{bug,flying}'),
(194,'Wooper',2,'{water,ground}'),
(195,'Quagsire',2,'{water,ground}'),
(196,'Espeon',2,'{psychic}'),
(197,'Umbreon',2,'{dark}'),
(198,'Murkrow',2,'{dark,flying}'),
(199,'Slowking',2,'{water,psychic}'),
(200,'Misdreavus',2,'{ghost}'),
(201,'Unown',2,'{psychic}'),
(202,'Wobbuffet',2,'{psychic}'),
(203,'Girafarig',2,'{normal,psychic}'),
(204,'Pineco',2,'{bug}'),
(205,'Forretress',2,'{bug,steel}'),
(206,'Dunsparce',2,'{normal}'),
(207,'Gligar',2,'{ground,flying}'),
(208,'Steelix',2,'{steel,ground}'),
(209,'Snubbull',2,'{fairy}'),
(210,'Granbull',2,'{fairy}'),
(211,'Qwilfish',2,'{water,poison}'),
(212,'Scizor',2,'{bug,steel}'),
(213,'Shuckle',2,'{bug,rock}'),
(214,'Heracross',2,'{bug,fighting}'),
(215,'Sneasel',2,'{dark,ice}'),
(216,'Teddiursa',2,'{normal}'),
(217,'Ursaring',2,'{normal}'),
(218,'Slugma',2,'{fire}'),
(219,'Magcargo',2,'{fire,rock}'),
(220,'Swinub',2,'{ice,ground}'),
(221,'Piloswine',2,'{ice,ground}'),
(222,'Corsola',2,'{water,rock}'),
(223,'Remoraid',2,'{water}'),
(224,'Octillery',2,'{water}'),
(225,'Delibird',2,'{ice,flying}'),
(226,'Mantine',2,'{water,flying}'),
(227,'Skarmory',2,'{steel,flying}'),
(228,'Houndour',2,'{dark,fire}'),
(229,'Houndoom',2,'{dark,fire}'),
(230,'Kingdra',2,'{water,dragon}'),
(231,'Phanpy',2,'{ground}'),
(232,'Donphan',2,'{ground}'),
(233,'Porygon2',2,'{normal}'),
(234,'Stantler',2,'{normal}'),
(235,'Smeargle',2,'{normal}'),
(236,'Tyrogue',2,'{fighting}'),
(237,'Hitmontop',2,'{fighting}'),
(238,'Smoochum',2,'{ice,psychic}'),
(239,'Elekid',2,'{electric}'),
(240,'Magby',2,'{fire}'),
(241,'Miltank',2,'{normal}'),
(242,'Blissey',2,'{normal}'),
(243,'Raikou',2,'{electric}'),
(244,'Entei',2,'{fire}'),
(245,'Suicune',2,'{water}'),
(246,'Larvitar',2,'{rock,ground}'),
(247,'Pupitar',2,'{rock,ground}'),
(248,'Tyranitar',2,'{rock,dark}'),
(249,'Lugia',2,'{psychic,flying}'),
(250,'Ho-Oh',2,'{fire,flying}'),
(251,'Celebi',2,'{psychic,grass}'),
(252,'Treecko',3,'{grass}'),
(253,'Grovyle',3,'{grass}'),
(254,'Sceptile',3,'{grass}'),
(255,'Torchic',3,'{fire}'),
(256,'Combusken',3,'{fire,fighting}'),
(257,'Blaziken',3,'{fire,fighting}'),
(258,'Mudkip',3,'{water}'),
(259,'Marshtomp',3,'{water,ground}'),
(260,'Swampert',3,'{water,ground}'),
(261,'Poochyena',3,'{dark}'),
(262,'Mightyena',3,'{dark}'),
(263,'Zigzagoon',3,'{normal}'),
(264,'Linoone',3,'{normal}'),
(265,'Wurmple',3,'{bug}'),
(266,'Silcoon',3,'{bug}'),
(267,'Beautifly',3,'{bug,flying}'),
(268,'Cascoon',3,'{bug}'),
(269,'Dustox',3,'{bug,poison}'),
(270,'Lotad',3,'{water,grass}'),
(271,'Lombre',3,'{water,grass}'),
(272,'Ludicolo',3,'{water,grass}'),
(273,'Seedot',3,'{grass}'),
(274,'Nuzleaf',3,'{grass,dark}'),
(275,'Shiftry',3,'{grass,dark}'),
(276,'Taillow',3,'{normal,flying}'),
(277,'Swellow',3,'{normal,flying}'),
(278,'Wingull',3,'{water,flying}'),
(279,'Pelipper',3,'{water,flying}'),
(280,'Ralts',3,'{psychic,fairy}'),
(281,'Kirlia',3,'{psychic,fairy}'),
(282,'Gardevoir',3,'{psychic,fairy}'),
(283,'Surskit',3,'{bug,water}'),
(284,'Masquerain',3,'{bug,flying}'),
(285,'Shroomish',3,'{grass}'),
(286,'Breloom',3,'{grass,fighting}'),
(287,'Slakoth',3,'{normal}'),
(288,'Vigoroth',3,'{normal}'),
(289,'Slaking',3,'{normal}'),
(290,'Nincada',3,'{bug,ground}'),
(291,'Ninjask',3,'{bug,flying}'),
(292,'Shedinja',3,'{bug,ghost}'),
(293,'Whismur',3,'{normal}'),
(294,'Loudred',3,'{normal}'),
(295,'Exploud',3,'{normal}'),
(296,'Makuhita',3,'{fighting}'),
(297,'Hariyama',3,'{fighting}'),
(298,'Azurill',3,'{normal,fairy}'),
(299,'Nosepass',3,'{rock}'),
(300,'Skitty',3,'{normal}'),
(301,'Delcatty',3,'{normal}'),
(302,'Sableye',3,'{dark,ghost}'),
(303,'Mawile',3,'{steel,fairy}'),
(304,'Aron',3,'{steel,rock}'),
(305,'Lairon',3,'{steel,rock}'),
(306,'Aggron',3,'{steel,rock}'),
(307,'Meditite',3,'{fighting,psychic}'),
(308,'Medicham',3,'{fighting,psychic}'),
(309,'Electrike',3,'{electric}'),
(310,'Manectric',3,'{electric}'),
(311,'Plusle',3,'{electric}'),
(312,'Minun',3,'{electric}'),
(313,'Volbeat',3,'{bug}'),
(314,'Illumise',3,'{bug}'),
(315,'Roselia',3,'{grass,poison}'),
(316,'Gulpin',3,'{poison}'),
(317,'Swalot',3,'{poison}'),
(318,'Carvanha',3,'{water,dark}'),
(319,'Sharpedo',3,'{water,dark}'),
(320,'Wailmer',3,'{water}'),
(321,'Wailord',3,'{water}'),
(322,'Numel',3,'{fire,ground}'),
(323,'Camerupt',3,'{fire,ground}'),
(324,'Torkoal',3,'{fire}'),
(325,'Spoink',3,'{psychic}'),
(326,'Grumpig',3,'{psychic}'),
(327,'Spinda',3,'{normal}'),
(328,'Trapinch',3,'{ground}'),
(329,'Vibrava',3,'{ground,dragon}'),
(330,'Flygon',3,'{ground,dragon}'),
(331,'Cacnea',3,'{grass}'),
(332,'Cacturne',3,'{grass,dark}'),
(333,'Swablu',3,'{normal,flying}'),
(334,'Altaria',3,'{dragon,flying}'),
(335,'Zangoose',3,'{normal}'),
(336,'Seviper',3,'{poison}'),
(337,'Lunatone',3,'{rock,psychic}'),
(338,'Solrock',3,'{rock,psychic}'),
(339,'Barboach',3,'{water,ground}'),
(340,'Whiscash',3,'{water,ground}'),
(341,'Corphish',3,'{water}'),
(342,'Crawdaunt',3,'{water,dark}'),
(343,'Baltoy',3,'{ground,psychic}'),
(344,'Claydol',3,'{ground,psychic}'),
(345,'Lileep',3,'{rock,grass}'),
(346,'Cradily',3,'{rock,grass}'),
(347,'Anorith',3,'{rock,bug}'),
(348,'Armaldo',3,'{rock,bug}'),
(349,'Feebas',3,'{water}'),
(350,'Milotic',3,'{water}'),
(351,'Castform',3,'{normal}'),
(352,'Kecleon',3,'{normal}'),
(353,'Shuppet',3,'{ghost}'),
(354,'Banette',3,'{ghost}'),
(355,'Duskull',3,'{ghost}'),
(356,'Dusclops',3,'{ghost}'),
(357,'Tropius',3,'{grass,flying}'),
(358,'Chimecho',3,'{psychic}'),
(359,'Absol',3,'{dark}'),
(360,'Wynaut',3,'{psychic}'),
(361,'Snorunt',3,'{ice}'),
(362,'Glalie',3,'{ice}'),
(363,'Spheal',3,'{ice,water}'),
(364,'Sealeo',3,'{ice,water}'),
(365,'Walrein',3,'{ice,water}'),
(366,'Clamperl',3,'{water}'),
(367,'Huntail',3,'{water}'),
(368,'Gorebyss',3,'{water}'),
(369,'Relicanth',3,'{water,rock}'),
(370,'Luvdisc',3,'{water}'),
(371,'Bagon',3,'{dragon}'),
(372,'Shelgon',3,'{dragon}'),
(373,'Salamence',3,'{dragon,flying}'),
(374,'Beldum',3,'{steel,psychic}'),
(375,'Metang',3,'{steel,psychic}'),
(376,'Metagross',3,'{steel,psychic}'),
(377,'Regirock',3,'{rock}'),
(378,'Regice',3,'{ice}'),
(379,'Registeel',3,'{steel}'),
(380,'Latias',3,'{dragon,psychic}'),
(381,'Latios',3,'{dragon,psychic}'),
(382,'Kyogre',3,'{water}'),
(383,'Groudon',3,'{ground}'),
(384,'Rayquaza',3,'{dragon,flying}'),
(385,'Jirachi',3,'{steel,psychic}'),
(386,'Deoxys',3,'{psychic}'),
(387,'Turtwig',4,'{grass}'),
(388,'Grotle',4,'{grass}'),
(389,'Torterra',4,'{grass,ground}'),
(390,'Chimchar',4,'{fire}'),
(391,'Monferno',4,'{fire,fighting}'),
(392,'Infernape',4,'{fire,fighting}'),
(393,'Piplup',4,'{water}'),
(394,'Prinplup',4,'{water}'),
(395,'Empoleon',4,'{water,steel}'),
(396,'Starly',4,'{normal,flying}'),
(397,'Staravia',4,'{normal,flying}'),
(398,'Staraptor',4,'{normal,flying}'),
(399,'Bidoof',4,'{normal}'),
(400,'Bibarel',4,'{normal,water}'),
(401,'Kricketot',4,'{bug}'),
(402,'Kricketune',4,'{bug}'),
(403,'Shinx',4,'{electric}'),
(404,'Luxio',4,'{electric}'),
(405,'Luxray',4,'{electric}'),
(406,'Budew',4,'{grass,poison}'),
(407,'Roserade',4,'{grass,poison}'),
(408,'Cranidos',4,'{rock}'),
(409,'Rampardos',4,'{rock}'),
(410,'Shieldon',4,'{rock,steel}'),
(411,'Bastiodon',4,'{rock,steel}'),
(412,'Burmy',4,'{bug}'),
(413,'Wormadam',4,'{bug,grass}'),
(414,'Mothim',4,'{bug,flying}'),
(415,'Combee',4,'{bug,flying}'),
(416,'Vespiquen',4,'{bug,flying}'),
(417,'Pachirisu',4,'{electric}'),
(418,'Buizel',4,'{water}'),
(419,'Floatzel',4,'{water}'),
(420,'Cherubi',4,'{grass}'),
(421,'Cherrim',4,'{grass}'),
(422,'Shellos',4,'{water}'),
(423,'Gastrodon',4,'{water,ground}'),
(424,'Ambipom',4,'{normal}'),
(425,'Drifloon',4,'{ghost,flying}'),
(426,'Drifblim',4,'{ghost,flying}'),
(427,'Buneary',4,'{normal}'),
(428,'Lopunny',4,'{normal}'),
(429,'Mismagius',4,'{ghost}'),
(430,'Honchkrow',4,'{dark,flying}'),
(431,'Glameow',4,'{normal}'),
(432,'Purugly',4,'{normal}'),
(433,'Chingling',4,'{psychic}'),
(434,'Stunky',4,'{poison,dark}'),
(435,'Skuntank',4,'{poison,dark}'),
(436,'Bronzor',4,'{steel,psychic}'),
(437,'Bronzong',4,'{steel,psychic}'),
(438,'Bonsly',4,'{rock}'),
(439,'Mime Jr.',4,'{psychic,fairy}'),
(440,'Happiny',4,'{normal}'),
(441,'Chatot',4,'{normal,flying}'),
(442,'Spiritomb',4,'{ghost,dark}'),
(443,'Gible',4,'{dragon,ground}'),
(444,'Gabite',4,'{dragon,ground}'),
(445,'Garchomp',4,'{dragon,ground}'),
(446,'Munchlax',4,'{normal}'),
(447,'Riolu',4,'{fighting}'),
(448,'Lucario',4,'{fighting,steel}'),
(449,'Hippopotas',4,'{ground}'),
(450,'Hippowdon',4,'{ground}'),
(451,'Skorupi',4,'{poison,bug}'),
(452,'Drapion',4,'{poison,dark}'),
(453,'Croagunk',4,'{poison,fighting}'),
(454,'Toxicroak',4,'{poison,fighting}'),
(455,'Carnivine',4,'{grass}'),
(456,'Finneon',4,'{water}'),
(457,'Lumineon',4,'{water}'),
(458,'Mantyke',4,'{water,flying}'),
(459,'Snover',4,'{grass,ice}'),
(460,'Abomasnow',4,'{grass,ice}'),
(461,'Weavile',4,'{dark,ice}'),
(462,'Magnezone',4,'{electric,steel}'),
(463,'Lickilicky',4,'{normal}'),
(464,'Rhyperior',4,'{ground,rock}'),
(465,'Tangrowth',4,'{grass}'),
(466,'Electivire',4,'{electric}'),
(467,'Magmortar',4,'{fire}'),
(468,'Togekiss',4,'{fairy,flying}'),
(469,'Yanmega',4,'{bug,flying}'),
(470,'Leafeon',4,'{grass}'),
(471,'Glaceon',4,'{ice}'),
(472,'Gliscor',4,'{ground,flying}'),
(473,'Mamoswine',4,'{ice,ground}'),
(474,'Porygon-Z',4,'{normal}'),
(475,'Gallade',4,'{psychic,fighting}'),
(476,'Probopass',4,'{rock,steel}'),
(477,'Dusknoir',4,'{ghost}'),
(478,'Froslass',4,'{ice,ghost}'),
(479,'Rotom',4,'{electric,ghost}'),
(480,'Uxie',4,'{psychic}'),
(481,'Mesprit',4,'{psychic}'),
(482,'Azelf',4,'{psychic}'),
(483,'Dialga',4,'{steel,dragon}'),
(484,'Palkia',4,'{water,dragon}'),
(485,'Heatran',4,'{fire,steel}'),
(486,'Regigigas',4,'{normal}'),
(487,'Giratina',4,'{ghost,dragon}'),
(488,'Cresselia',4,'{psychic}'),
(489,'Phione',4,'{water}'),
(490,'Manaphy',4,'{water}'),
(491,'Darkrai',4,'{dark}'),
(492,'Shaymin',4,'{grass}'),
(493,'Arceus',4,'{normal}'),
(494,'Victini',5,'{psychic,fire}'),
(495,'Snivy',5,'{grass}'),
(496,'Servine',5,'{grass}'),
(497,'Serperior',5,'{grass}'),
(498,'Tepig',5,'{fire}'),
(499,'Pignite',5,'{fire,fighting}'),
(500,'Emboar',5,'{fire,fighting}'),
(501,'Oshawott',5,'{water}'),
(502,'Dewott',5,'{water}'),
(503,'Samurott',5,'{water}'),
(504,'Patrat',5,'{normal}'),
(505,'Watchog',5,'{normal}'),
(506,'Lillipup',5,'{normal}'),
(507,'Herdier',5,'{normal}'),
(508,'Stoutland',5,'{normal}'),
(509,'Purrloin',5,'{dark}'),
(510,'Liepard',5,'{dark}'),
(511,'Pansage',5,'{grass}'),
(512,'Simisage',5,'{grass}'),
(513,'Pansear',5,'{fire}'),
(514,'Simisear',5,'{fire}'),
(515,'Panpour',5,'{water}'),
(516,'Simipour',5,'{water}'),
(517,'Munna',5,'{psychic}'),
(518,'Musharna',5,'{psychic}'),
(519,'Pidove',5,'{normal,flying}'),
(520,'Tranquill',5,'{normal,flying}'),
(521,'Unfezant',5,'{normal,flying}'),
(522,'Blitzle',5,'{electric}'),
(523,'Zebstrika',5,'{electric}'),
(524,'Roggenrola',5,'{rock}'),
(525,'Boldore',5,'{rock}'),
(526,'Gigalith',5,'{rock}'),
(527,'Woobat',5,'{psychic,flying}'),
(528,'Swoobat',5,'{psychic,flying}'),
(529,'Drilbur',5,'{ground}'),
(530,'Excadrill',5,'{ground,steel}'),
(531,'Audino',5,'{normal}'),
(532,'Timburr',5,'{fighting}'),
(533,'Gurdurr',5,'{fighting}'),
(534,'Conkeldurr',5,'{fighting}'),
(535,'Tympole',5,'{water}'),
(536,'Palpitoad',5,'{water,ground}'),
(537,'Seismitoad',5,'{water,ground}'),
(538,'Throh',5,'{fighting}'),
(539,'Sawk',5,'{fighting}'),
(540,'Sewaddle',5,'{bug,grass}'),
(541,'Swadloon',5,'{bug,grass}'),
(542,'Leavanny',5,'{bug,grass}'),
(543,'Venipede',5,'{bug,poison}'),
(544,'Whirlipede',5,'{bug,poison}'),
(545,'Scolipede',5,'{bug,poison}'),
(546,'Cottonee',5,'{grass,fairy}'),
(547,'Whimsicott',5,'{grass,fairy}'),
(548,'Petilil',5,'{grass}'),
(549,'Lilligant',5,'{grass}'),
(550,'Basculin',5,'{water}'),
(551,'Sandile',5,'{ground,dark}'),
(552,'Krokorok',5,'{ground,dark}'),
(553,'Krookodile',5,'{ground,dark}'),
(554,'Darumaka',5,'{fire}'),
(555,'Darmanitan',5,'{fire}'),
(556,'Maractus',5,'{grass}'),
(557,'Dwebble',5,'{bug,rock}'),
(558,'Crustle',5,'{bug,rock}'),
(559,'Scraggy',5,'{dark,fighting}'),
(560,'Scrafty',5,'{dark,fighting}'),
(561,'Sigilyph',5,'{psychic,flying}'),
(562,'Yamask',5,'{ghost}'),
(563,'Cofagrigus',5,'{ghost}'),
(564,'Tirtouga',5,'{water,rock}'),
(565,'Carracosta',5,'{water,rock}'),
(566,'Archen',5,'{rock,flying}'),
(567,'Archeops',5,'{rock,flying}'),
(568,'Trubbish',5,'{poison}'),
(569,'Garbodor',5,'{poison}'),
(570,'Zorua',5,'{dark}'),
(571,'Zoroark',5,'{dark}'),
(572,'Minccino',5,'{normal}'),
(573,'Cinccino',5,'{normal}'),
(574,'Gothita',5,'{psychic}'),
(575,'Gothorita',5,'{psychic}'),
(576,'Gothitelle',5,'{psychic}'),
(577,'Solosis',5,'{psychic}'),
(578,'Duosion',5,'{psychic}'),
(579,'Reuniclus',5,'{psychic}'),
(580,'Ducklett',5,'{water,flying}'),
(581,'Swanna',5,'{water,flying}'),
(582,'Vanillite',5,'{ice}'),
(583,'Vanillish',5,'{ice}'),
(584,'Vanilluxe',5,'{ice}'),
(585,'Deerling',5,'{normal,grass}'),
(586,'Sawsbuck',5,'{normal,grass}'),
(587,'Emolga',5,'{electric,flying}'),
(588,'Karrablast',5,'{bug}'),
(589,'Escavalier',5,'{bug,steel}'),
(590,'Foongus',5,'{grass,poison}'),
(591,'Amoonguss',5,'{grass,poison}'),
(592,'Frillish',5,'{water,ghost}'),
(593,'Jellicent',5,'{water,ghost}'),
(594,'Alomomola',5,'{water}'),
(595,'Joltik',5,'{bug,electric}'),
(596,'Galvantula',5,'{bug,electric}'),
(597,'Ferroseed',5,'{grass,steel}'),
(598,'Ferrothorn',5,'{grass,steel}'),
(599,'Klink',5,'{steel}'),
(600,'Klang',5,'{steel}'),
(601,'Klinklang',5,'{steel}'),
(602,'Tynamo',5,'{electric}'),
(603,'Eelektrik',5,'{electric}'),
(604,'Eelektross',5,'{electric}'),
(605,'Elgyem',5,'{psychic}'),
(606,'Beheeyem',5,'{psychic}'),
(607,'Litwick',5,'{ghost,fire}'),
(608,'Lampent',5,'{ghost,fire}'),
(609,'Chandelure',5,'{ghost,fire}'),
(610,'Axew',5,'{dragon}'),
(611,'Fraxure',5,'{dragon}'),
(612,'Haxorus',5,'{dragon}'),
(613,'Cubchoo',5,'{ice}'),
(614,'Beartic',5,'{ice}'),
(615,'Cryogonal',5,'{ice}'),
(616,'Shelmet',5,'{bug}'),
(617,'Accelgor',5,'{bug}'),
(618,'Stunfisk',5,'{ground,electric}'),
(619,'Mienfoo',5,'{fighting}'),
(620,'Mienshao',5,'{fighting}'),
(621,'Druddigon',5,'{dragon}'),
(622,'Golett',5,'{ground,ghost}'),
(623,'Golurk',5,'{ground,ghost}'),
(624,'Pawniard',5,'{dark,steel}'),
(625,'Bisharp',5,'{dark,steel}'),
(626,'Bouffalant',5,'{normal}'),
(627,'Rufflet',5,'{normal,flying}'),
(628,'Braviary',5,'{normal,flying}'),
(629,'Vullaby',5,'{dark,flying}'),
(630,'Mandibuzz',5,'{dark,flying}'),
(631,'Heatmor',5,'{fire}'),
(632,'Durant',5,'{bug,steel}'),
(633,'Deino',5,'{dark,dragon}'),
(634,'Zweilous',5,'{dark,dragon}'),
(635,'Hydreigon',5,'{dark,dragon}'),
(636,'Larvesta',5,'{bug,fire}'),
(637,'Volcarona',5,'{bug,fire}'),
(638,'Cobalion',5,'{steel,fighting}'),
(639,'Terrakion',5,'{rock,fighting}'),
(640,'Virizion',5,'{grass,fighting}'),
(641,'Tornadus',5,'{flying}'),
(642,'Thundurus',5,'{electric,flying}'),
(643,'Reshiram',5,'{dragon,fire}'),
(644,'Zekrom',5,'{dragon,electric}'),
(645,'Landorus',5,'{ground,flying}'),
(646,'Kyurem',5,'{dragon,ice}'),
(647,'Keldeo',5,'{water,fighting}'),
(648,'Meloetta',5,'{normal,psychic}'),
(649,'Genesect',5,'{bug,steel}'),
(650,'Chespin',6,'{grass}'),
(651,'Quilladin',6,'{grass}'),
(652,'Chesnaught',6,'{grass,fighting}'),
(653,'Fennekin',6,'{fire}'),
(654,'Braixen',6,'{fire}'),
(655,'Delphox',6,'{fire,psychic}'),
(656,'Froakie',6,'{water}'),
(657,'Frogadier',6,'{water}'),
(658,'Greninja',6,'{water,dark}'),
(659,'Bunnelby',6,'{normal}'),
(660,'Diggersby',6,'{normal,ground}'),
(661,'Fletchling',6,'{normal,flying}'),
(662,'Fletchinder',6,'{fire,flying}'),
(663,'Talonflame',6,'{fire,flying}'),
(664,'Scatterbug',6,'{bug}'),
(665,'Spewpa',6,'{bug}'),
(666,'Vivillon',6,'{bug,flying}'),
(667,'Litleo',6,'{fire,normal}'),
(668,'Pyroar',6,'{fire,normal}'),
(669,'Flabébé',6,'{fairy}'),
(670,'Floette',6,'{fairy}'),
(671,'Florges',6,'{fairy}'),
(672,'Skiddo',6,'{grass}'),
(673,'Gogoat',6,'{grass}'),
(674,'Pancham',6,'{fighting}'),
(675,'Pangoro',6,'{fighting,dark}'),
(676,'Furfrou',6,'{normal}'),
(677,'Espurr',6,'{psychic}'),
(678,'Meowstic',6,'{psychic}'),
(679,'Honedge',6,'{steel,ghost}'),
(680,'Doublade',6,'{steel,ghost}'),
(681,'Aegislash',6,'{steel,ghost}'),
(682,'Spritzee',6,'{fairy}'),
(683,'Aromatisse',6,'{fairy}'),
(684,'Swirlix',6,'{fairy}'),
(685,'Slurpuff',6,'{fairy}'),
(686,'Inkay',6,'{dark,psychic}'),
(687,'Malamar',6,'{dark,psychic}'),
(688,'Binacle',6,'{rock,water}'),
(689,'Barbaracle',6,'{rock,water}'),
(690,'Skrelp',6,'{poison,water}'),
(691,'Dragalge',6,'{poison,dragon}'),
(692,'Clauncher',6,'{water}'),
(693,'Clawitzer',6,'{water}'),
(694,'Helioptile',6,'{electric,normal}'),
(695,'Heliolisk',6,'{electric,normal}'),
(696,'Tyrunt',6,'{rock,dragon}'),
(697,'Tyrantrum',6,'{rock,dragon}'),
(698,'Amaura',6,'{rock,ice}'),
(699,'Aurorus',6,'{rock,ice}'),
(700,'Sylveon',6,'{fairy}'),
(701,'Hawlucha',6,'{fighting,flying}'),
(702,'Dedenne',6,'{electric,fairy}'),
(703,'Carbink',6,'{rock,fairy}'),
(704,'Goomy',6,'{dragon}'),
(705,'Sliggoo',6,'{dragon}'),
(706,'Goodra',6,'{dragon}'),
(707,'Klefki',6,'{steel,fairy}'),
(708,'Phantump',6,'{ghost,grass}'),
(709,'Trevenant',6,'{ghost,grass}'),
(710,'Pumpkaboo',6,'{ghost,grass}'),
(711,'Gourgeist',6,'{ghost,grass}'),
(712,'Bergmite',6,'{ice}'),
(713,'Avalugg',6,'{ice}'),
(714,'Noibat',6,'{flying,dragon}'),
(715,'Noivern',6,'{flying,dragon}'),
(716,'Xerneas',6,'{fairy}'),
(717,'Yveltal',6,'{dark,flying}'),
(718,'Zygarde',6,'{dragon,ground}'),
(719,'Diancie',6,'{rock,fairy}'),
(720,'Hoopa',6,'{psychic,ghost}'),
(721,'Volcanion',6,'{fire,water}'),
(722,'Rowlet',7,'{grass,flying}'),
(723,'Dartrix',7,'{grass,flying}'),
(724,'Decidueye',7,'{grass,ghost}'),
(725,'Litten',7,'{fire}'),
(726,'Torracat',7,'{fire}'),
(727,'Incineroar',7,'{fire,dark}'),
(728,'Popplio',7,'{water}'),
(729,'Brionne',7,'{water}'),
(730,'Primarina',7,'{water,fairy}'),
(731,'Pikipek',7,'{normal,flying}'),
(732,'Trumbeak',7,'{normal,flying}'),
(733,'Toucannon',7,'{normal,flying}'),
(734,'Yungoos',7,'{normal}'),
(735,'Gumshoos',7,'{normal}'),
(736,'Grubbin',7,'{bug}'),
(737,'Charjabug',7,'{bug,electric}'),
(738,'Vikavolt',7,'{bug,electric}'),
(739,'Crabrawler',7,'{fighting}'),
(740,'Crabominable',7,'{fighting,ice}'),
(741,'Oricorio',7,'{fire,flying}'),
(742,'Cutiefly',7,'{bug,fairy}'),
(743,'Ribombee',7,'{bug,fairy}'),
(744,'Rockruff',7,'{rock}'),
(745,'Lycanroc',7,'{rock}'),
(746,'Wishiwashi',7,'{water}'),
(747,'Mareanie',7,'{poison,water}'),
(748,'Toxapex',7,'{poison,water}'),
(749,'Mudbray',7,'{ground}'),
(750,'Mudsdale',7,'{ground}'),
(751,'Dewpider',7,'{water,bug}'),
(752,'Araquanid',7,'{water,bug}'),
(753,'Fomantis',7,'{grass}'),
(754,'Lurantis',7,'{grass}'),
(755,'Morelull',7,'{grass,fairy}'),
(756,'Shiinotic',7,'{grass,fairy}'),
(757,'Salandit',7,'{poison,fire}'),
(758,'Salazzle',7,'{poison,fire}'),
(759,'Stufful',7,'{normal,fighting}'),
(760,'Bewear',7,'{normal,fighting}'),
(761,'Bounsweet',7,'{grass}'),
(762,'Steenee',7,'{grass}'),
(763,'Tsareena',7,'{grass}'),
(764,'Comfey',7,'{fairy}'),
(765,'Oranguru',7,'{normal,psychic}'),
(766,'Passimian',7,'{fighting}'),
(767,'Wimpod',7,'{bug,water}'),
(768,'Golisopod',7,'{bug,water}'),
(769,'Sandygast',7,'{ghost,ground}'),
(770,'Palossand',7,'{ghost,ground}'),
(771,'Pyukumuku',7,'{water}'),
(772,'Código Cero',7,'{normal}'),
(773,'Silvally',7,'{normal}'),
(774,'Minior',7,'{rock,flying}'),
(775,'Komala',7,'{normal}'),
(776,'Turtonator',7,'{fire,dragon}'),
(777,'Togedemaru',7,'{electric,steel}'),
(778,'Mimikyu',7,'{ghost,fairy}'),
(779,'Bruxish',7,'{water,psychic}'),
(780,'Drampa',7,'{normal,dragon}'),
(781,'Dhelmise',7,'{ghost,grass}'),
(782,'Jangmo-o',7,'{dragon}'),
(783,'Hakamo-o',7,'{dragon,fighting}'),
(784,'Kommo-o',7,'{dragon,fighting}'),
(785,'Tapu Koko',7,'{electric,fairy}'),
(786,'Tapu Lele',7,'{psychic,fairy}'),
(787,'Tapu Bulu',7,'{grass,fairy}'),
(788,'Tapu Fini',7,'{water,fairy}'),
(789,'Cosmog',7,'{psychic}'),
(790,'Cosmoem',7,'{psychic}'),
(791,'Solgaleo',7,'{psychic,steel}'),
(792,'Lunala',7,'{psychic,ghost}'),
(793,'Nihilego',7,'{rock,poison}'),
(794,'Buzzwole',7,'{bug,fighting}'),
(795,'Pheromosa',7,'{bug,fighting}'),
(796,'Xurkitree',7,'{electric}'),
(797,'Celesteela',7,'{steel,flying}'),
(798,'Kartana',7,'{grass,steel}'),
(799,'Guzzlord',7,'{dark,dragon}'),
(800,'Necrozma',7,'{psychic}'),
(801,'Magearna',7,'{steel,fairy}'),
(802,'Marshadow',7,'{fighting,ghost}'),
(803,'Poipole',7,'{poison}'),
(804,'Naganadel',7,'{poison,dragon}'),
(805,'Stakataka',7,'{rock,steel}'),
(806,'Blacephalon',7,'{fire,ghost}'),
(807,'Zeraora',7,'{electric}'),
(808,'Meltan',7,'{steel}'),
(809,'Melmetal',7,'{steel}'),
(810,'Grookey',8,'{grass}'),
(811,'Thwackey',8,'{grass}'),
(812,'Rillaboom',8,'{grass}'),
(813,'Scorbunny',8,'{fire}'),
(814,'Raboot',8,'{fire}'),
(815,'Cinderace',8,'{fire}'),
(816,'Sobble',8,'{water}'),
(817,'Drizzile',8,'{water}'),
(818,'Inteleon',8,'{water}'),
(819,'Skwovet',8,'{normal}'),
(820,'Greedent',8,'{normal}'),
(821,'Rookidee',8,'{flying}'),
(822,'Corvisquire',8,'{flying}'),
(823,'Corviknight',8,'{flying,steel}'),
(824,'Blipbug',8,'{bug}'),
(825,'Dottler',8,'{bug,psychic}'),
(826,'Orbeetle',8,'{bug,psychic}'),
(827,'Nickit',8,'{dark}'),
(828,'Thievul',8,'{dark}'),
(829,'Gossifleur',8,'{grass}'),
(830,'Eldegoss',8,'{grass}'),
(831,'Wooloo',8,'{normal}'),
(832,'Dubwool',8,'{normal}'),
(833,'Chewtle',8,'{water}'),
(834,'Drednaw',8,'{water,rock}'),
(835,'Yamper',8,'{electric}'),
(836,'Boltund',8,'{electric}'),
(837,'Rolycoly',8,'{rock}'),
(838,'Carkol',8,'{rock,fire}'),
(839,'Coalossal',8,'{rock,fire}'),
(840,'Applin',8,'{grass,dragon}'),
(841,'Flapple',8,'{grass,dragon}'),
(842,'Appletun',8,'{grass,dragon}'),
(843,'Silicobra',8,'{ground}'),
(844,'Sandaconda',8,'{ground}'),
(845,'Cramorant',8,'{flying,water}'),
(846,'Arrokuda',8,'{water}'),
(847,'Barraskewda',8,'{water}'),
(848,'Toxel',8,'{electric,poison}'),
(849,'Toxtricity',8,'{electric,poison}'),
(850,'Sizzlipede',8,'{fire,bug}'),
(851,'Centiskorch',8,'{fire,bug}'),
(852,'Clobbopus',8,'{fighting}'),
(853,'Grapploct',8,'{fighting}'),
(854,'Sinistea',8,'{ghost}'),
(855,'Polteageist',8,'{ghost}'),
(856,'Hatenna',8,'{psychic}'),
(857,'Hattrem',8,'{psychic}'),
(858,'Hatterene',8,'{psychic,fairy}'),
(859,'Impidimp',8,'{dark,fairy}'),
(860,'Morgrem',8,'{dark,fairy}'),
(861,'Grimmsnarl',8,'{dark,fairy}'),
(862,'Obstagoon',8,'{dark,normal}'),
(863,'Perrserker',8,'{steel}'),
(864,'Cursola',8,'{ghost}'),
(865,'Sirfetch’d',8,'{fighting}'),
(866,'Mr. Rime',8,'{ice,psychic}'),
(867,'Runerigus',8,'{ground,ghost}'),
(868,'Milcery',8,'{fairy}'),
(869,'Alcremie',8,'{fairy}'),
(870,'Falinks',8,'{fighting}'),
(871,'Pincurchin',8,'{electric}'),
(872,'Snom',8,'{ice,bug}'),
(873,'Frosmoth',8,'{ice,bug}'),
(874,'Stonjourner',8,'{rock}'),
(875,'Eiscue',8,'{ice}'),
(876,'Indeedee',8,'{psychic,normal}'),
(877,'Morpeko',8,'{electric,dark}'),
(878,'Cufant',8,'{steel}'),
(879,'Copperajah',8,'{steel}'),
(880,'Dracozolt',8,'{electric,dragon}'),
(881,'Arctozolt',8,'{electric,ice}'),
(882,'Dracovish',8,'{water,dragon}'),
(883,'Arctovish',8,'{water,ice}'),
(884,'Duraludon',8,'{steel,dragon}'),
(885,'Dreepy',8,'{dragon,ghost}'),
(886,'Drakloak',8,'{dragon,ghost}'),
(887,'Dragapult',8,'{dragon,ghost}'),
(888,'Zacian',8,'{fairy}'),
(889,'Zamazenta',8,'{fighting}'),
(890,'Eternatus',8,'{poison,dragon}'),
(891,'Kubfu',8,'{fighting}'),
(892,'Urshifu',8,'{fighting,dark}'),
(893,'Zarude',8,'{dark,grass}'),
(894,'Regieleki',8,'{electric}'),
(895,'Regidrago',8,'{dragon}'),
(896,'Glastrier',8,'{ice}'),
(897,'Spectrier',8,'{ghost}'),
(898,'Calyrex',8,'{psychic,grass}'),
(899,'Wyrdeer',8,'{normal,psychic}'),
(900,'Kleavor',8,'{bug,rock}'),
(901,'Ursaluna',8,'{ground,normal}'),
(902,'Basculegion',8,'{water,ghost}'),
(903,'Sneasler',8,'{fighting,poison}'),
(904,'Overqwil',8,'{dark,poison}'),
(905,'Enamorus',8,'{fairy,flying}'),
(906,'Sprigatito',9,'{grass}'),
(907,'Floragato',9,'{grass}'),
(908,'Meowscarada',9,'{grass,dark}'),
(909,'Fuecoco',9,'{fire}'),
(910,'Crocalor',9,'{fire}'),
(911,'Skeledirge',9,'{fire,ghost}'),
(912,'Quaxly',9,'{water}'),
(913,'Quaxwell',9,'{water}'),
(914,'Quaquaval',9,'{water,fighting}'),
(915,'Lechonk',9,'{normal}'),
(916,'Oinkologne',9,'{normal}'),
(917,'Tarountula',9,'{bug}'),
(918,'Spidops',9,'{bug}'),
(919,'Nymble',9,'{bug}'),
(920,'Lokix',9,'{bug,dark}'),
(921,'Pawmi',9,'{electric}'),
(922,'Pawmo',9,'{electric,fighting}'),
(923,'Pawmot',9,'{electric,fighting}'),
(924,'Tandemaus',9,'{normal}'),
(925,'Maushold',9,'{normal}'),
(926,'Fidough',9,'{fairy}'),
(927,'Dachsbun',9,'{fairy}'),
(928,'Smoliv',9,'{grass,normal}'),
(929,'Dolliv',9,'{grass,normal}'),
(930,'Arboliva',9,'{grass,normal}'),
(931,'Squawkabilly',9,'{normal,flying}'),
(932,'Nacli',9,'{rock}'),
(933,'Naclstack',9,'{rock}'),
(934,'Garganacl',9,'{rock}'),
(935,'Charcadet',9,'{fire}'),
(936,'Armarouge',9,'{fire,psychic}'),
(937,'Ceruledge',9,'{fire,ghost}'),
(938,'Tadbulb',9,'{electric}'),
(939,'Bellibolt',9,'{electric}'),
(940,'Wattrel',9,'{electric,flying}'),
(941,'Kilowattrel',9,'{electric,flying}'),
(942,'Maschiff',9,'{dark}'),
(943,'Mabosstiff',9,'{dark}'),
(944,'Shroodle',9,'{poison,normal}'),
(945,'Grafaiai',9,'{poison,normal}'),
(946,'Bramblin',9,'{grass,ghost}'),
(947,'Brambleghast',9,'{grass,ghost}'),
(948,'Toedscool',9,'{ground,grass}'),
(949,'Toedscruel',9,'{ground,grass}'),
(950,'Klawf',9,'{rock}'),
(951,'Capsakid',9,'{grass}'),
(952,'Scovillain',9,'{grass,fire}'),
(953,'Rellor',9,'{bug}'),
(954,'Rabsca',9,'{bug,psychic}'),
(955,'Flittle',9,'{psychic}'),
(956,'Espathra',9,'{psychic}'),
(957,'Tinkatink',9,'{fairy,steel}'),
(958,'Tinkatuff',9,'{fairy,steel}'),
(959,'Tinkaton',9,'{fairy,steel}'),
(960,'Wiglett',9,'{water}'),
(961,'Wugtrio',9,'{water}'),
(962,'Bombirdier',9,'{flying,dark}'),
(963,'Finizen',9,'{water}'),
(964,'Palafin',9,'{water}'),
(965,'Varoom',9,'{steel,poison}'),
(966,'Revavroom',9,'{steel,poison}'),
(967,'Cyclizar',9,'{dragon,normal}'),
(968,'Orthworm',9,'{steel}'),
(969,'Glimmet',9,'{rock,poison}'),
(970,'Glimmora',9,'{rock,poison}'),
(971,'Greavard',9,'{ghost}'),
(972,'Houndstone',9,'{ghost}'),
(973,'Flamigo',9,'{flying,fighting}'),
(974,'Cetoddle',9,'{ice}'),
(975,'Cetitan',9,'{ice}'),
(976,'Veluza',9,'{water,psychic}'),
(977,'Dondozo',9,'{water}'),
(978,'Tatsugiri',9,'{dragon,water}'),
(979,'Annihilape',9,'{fighting,ghost}'),
(980,'Clodsire',9,'{poison,ground}'),
(981,'Farigiraf',9,'{normal,psychic}'),
(982,'Dudunsparce',9,'{normal}'),
(983,'Kingambit',9,'{dark,steel}'),
(984,'Colmilargo',9,'{ground,fighting}'),
(985,'Colagrito',9,'{fairy,psychic}'),
(986,'Furioseta',9,'{grass,dark}'),
(987,'Melenaleteo',9,'{ghost,fairy}'),
(988,'Reptalada',9,'{bug,fighting}'),
(989,'Pelarena',9,'{electric,ground}'),
(990,'Ferrodada',9,'{ground,steel}'),
(991,'Ferrosaco',9,'{ice,water}'),
(992,'Ferropalmas',9,'{fighting,electric}'),
(993,'Ferrocuello',9,'{dark,flying}'),
(994,'Ferropolilla',9,'{fire,poison}'),
(995,'Ferropúas',9,'{rock,electric}'),
(996,'Frigibax',9,'{dragon,ice}'),
(997,'Arctibax',9,'{dragon,ice}'),
(998,'Baxcalibur',9,'{dragon,ice}'),
(999,'Gimmighoul',9,'{ghost}'),
(1000,'Gholdengo',9,'{steel,ghost}'),
(1001,'Wo-Chien',9,'{dark,grass}'),
(1002,'Chien-Pao',9,'{dark,ice}'),
(1003,'Ting-Lu',9,'{dark,ground}'),
(1004,'Chi-Yu',9,'{dark,fire}'),
(1005,'Bramaluna',9,'{dragon,dark}'),
(1006,'Ferropaladín',9,'{fairy,fighting}'),
(1007,'Koraidon',9,'{fighting,dragon}'),
(1008,'Miraidon',9,'{electric,dragon}'),
(1009,'Ondulagua',9,'{water,dragon}'),
(1010,'Ferroverdor',9,'{grass,psychic}'),
(1011,'Dipplin',9,'{grass,dragon}'),
(1012,'Poltchageist',9,'{grass,ghost}'),
(1013,'Sinistcha',9,'{grass,ghost}'),
(1014,'Okidogi',9,'{poison,fighting}'),
(1015,'Munkidori',9,'{poison,psychic}'),
(1016,'Fezandipiti',9,'{poison,fairy}'),
(1017,'Ogerpon',9,'{grass}'),
(1018,'Archaludon',9,'{steel,dragon}'),
(1019,'Hydrapple',9,'{grass,dragon}'),
(1020,'Flamariete',9,'{fire,dragon}'),
(1021,'Electrofuria',9,'{electric,dragon}'),
(1022,'Ferromole',9,'{rock,psychic}'),
(1023,'Ferrotesta',9,'{steel,psychic}'),
(1024,'Terapagos',9,'{normal}'),
(1025,'Pecharunt',9,'{poison,ghost}')
on conflict (id) do update set name = excluded.name, gen = excluded.gen, types = excluded.types;
