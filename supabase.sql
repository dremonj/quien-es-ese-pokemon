-- Base de datos de "¿Quién es ese Pokémon?" para Supabase.
-- Cómo usarlo: en tu proyecto de Supabase abre SQL Editor > New query, pega todo este archivo y pulsa Run.
-- Se puede ejecutar varias veces sin romper nada.
--
-- Diseño: las tablas no se pueden leer ni escribir directamente desde la web.
-- La página solo llama a las funciones de abajo (register, login, submit_score, leaderboard...),
-- que comprueban la sesión y nunca devuelven contraseñas.

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

-- Resultados de cada partida
create table if not exists public.scores (
  id         bigint generated always as identity primary key,
  player_id  bigint not null references public.players(id) on delete cascade,
  score      integer not null check (score >= 0),
  level      integer not null check (level >= 1),
  hits       integer not null check (hits >= 0),
  avg_time   real check (avg_time is null or avg_time >= 0),
  gens       smallint[] not null default '{}',
  created_at timestamptz not null default now(),
  -- coherencia con las reglas del juego (5 aciertos por nivel, máximo 1000 puntos por acierto y nivel)
  constraint scores_level_matches_hits check (level = 1 + hits / 5),
  constraint scores_score_possible check (score <= 1000 * hits * level)
);
create index if not exists scores_player_score_idx on public.scores (player_id, score desc);
create index if not exists scores_score_idx on public.scores (score desc);

alter table public.players  enable row level security;
alter table public.sessions enable row level security;
alter table public.scores   enable row level security;
-- Sin políticas RLS a propósito: acceso solo a través de las funciones.
revoke all on public.players, public.sessions, public.scores from anon, authenticated;


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


-- Guarda una partida y devuelve la mejor puntuación del jugador y su puesto en el ranking
create or replace function public.submit_score(
  p_token uuid, p_score integer, p_level integer, p_hits integer, p_avg_time real, p_gens smallint[]
)
returns json
language plpgsql security definer set search_path = public
as $$
declare
  v_id   bigint := _player_from_token(p_token);
  v_best integer;
  v_rank integer;
begin
  if v_id is null then
    raise exception 'Tu sesión ha caducado. Vuelve a entrar.';
  end if;
  insert into scores (player_id, score, level, hits, avg_time, gens)
  values (v_id, p_score, p_level, p_hits, p_avg_time, coalesce(p_gens, '{}'));

  select max(score) into v_best from scores where player_id = v_id;
  select 1 + count(*) into v_rank
  from (select player_id, max(score) as best from scores group by player_id) b
  where b.best > v_best;
  return json_build_object('best', v_best, 'rank', v_rank);
end
$$;


-- Ranking: la mejor partida de cada jugador
create or replace function public.leaderboard(p_limit integer default 10)
returns table (username text, best_score integer, level integer, hits integer, avg_time real, games bigint, achieved_at timestamptz)
language sql stable security definer set search_path = public
as $$
  with best as (
    select distinct on (s.player_id) s.player_id, s.score, s.level, s.hits, s.avg_time, s.created_at
    from scores s
    order by s.player_id, s.score desc, s.created_at asc
  ), games as (
    select player_id, count(*) as n from scores group by player_id
  )
  select p.username, b.score, b.level, b.hits, b.avg_time, g.n, b.created_at
  from best b
  join players p on p.id = b.player_id
  join games g on g.player_id = b.player_id
  order by b.score desc, b.created_at asc
  limit least(greatest(coalesce(p_limit, 10), 1), 100)
$$;


-- Últimas partidas del jugador con sesión
create or replace function public.my_scores(p_token uuid, p_limit integer default 50)
returns table (score integer, level integer, hits integer, avg_time real, gens smallint[], created_at timestamptz)
language sql stable security definer set search_path = public
as $$
  select s.score, s.level, s.hits, s.avg_time, s.gens, s.created_at
  from scores s
  where s.player_id = _player_from_token(p_token)
  order by s.created_at desc
  limit least(greatest(coalesce(p_limit, 50), 1), 200)
$$;


grant execute on function
  public.register(text, text),
  public.login(text, text),
  public.whoami(uuid),
  public.logout(uuid),
  public.submit_score(uuid, integer, integer, integer, real, smallint[]),
  public.leaderboard(integer),
  public.my_scores(uuid, integer)
to anon, authenticated;
