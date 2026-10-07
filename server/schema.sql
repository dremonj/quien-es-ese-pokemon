-- Base de datos MySQL/MariaDB de "¿Quién es ese Pokémon?" (la crea install.php).
-- La web nunca toca estas tablas: solo llama a api.php, que hace de árbitro.

CREATE TABLE IF NOT EXISTS players (
  id         BIGINT AUTO_INCREMENT PRIMARY KEY,
  username   VARCHAR(16) NOT NULL UNIQUE,
  pass_hash  VARCHAR(255) NOT NULL,            -- bcrypt
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT players_username_format CHECK (username REGEXP '^[a-z0-9_]{3,16}$')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

-- Sesiones: la web guarda solo el token, no la contraseña
CREATE TABLE IF NOT EXISTS sessions (
  token      CHAR(36) PRIMARY KEY,
  player_id  BIGINT NOT NULL,
  expires_at DATETIME NOT NULL,
  FOREIGN KEY (player_id) REFERENCES players(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Resultados de cada partida (cada modo de juego tiene su propio ranking)
CREATE TABLE IF NOT EXISTS scores (
  id         BIGINT AUTO_INCREMENT PRIMARY KEY,
  player_id  BIGINT NOT NULL,
  mode       VARCHAR(32) NOT NULL,
  score      INT NOT NULL,
  level      INT NOT NULL,
  hits       INT NOT NULL,
  avg_time   DOUBLE NULL,
  gens       VARCHAR(64) NOT NULL DEFAULT '[]',  -- JSON, p. ej. [1,2]
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  FOREIGN KEY (player_id) REFERENCES players(id) ON DELETE CASCADE,
  INDEX scores_mode_score_idx (mode, score DESC),
  INDEX scores_player_idx (player_id, mode),
  CONSTRAINT scores_values CHECK (score >= 0 AND level >= 1 AND hits >= 0 AND (avg_time IS NULL OR avg_time >= 0)),
  -- modo "silueta": 5 aciertos por nivel, máximo 1000 puntos por acierto y nivel
  CONSTRAINT scores_level_matches_hits CHECK (mode <> 'silueta' OR level = 1 + hits DIV 5),
  CONSTRAINT scores_score_possible CHECK (mode <> 'silueta' OR score <= 1000 * hits * level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Pokémon (datos de la PokéAPI, los carga install.php desde pokemon.json)
CREATE TABLE IF NOT EXISTS pokemon (
  id    INT PRIMARY KEY,
  name  VARCHAR(64) NOT NULL,   -- nombre en español
  gen   TINYINT NOT NULL,       -- generación 1-9
  types VARCHAR(64) NOT NULL,   -- JSON con los tipos en inglés, p. ej. ["grass","poison"]
  INDEX pokemon_gen_idx (gen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Partidas en curso. La respuesta de la ronda actual solo la conoce el servidor.
CREATE TABLE IF NOT EXISTS games (
  id            CHAR(36) PRIMARY KEY,
  player_id     BIGINT NULL,                  -- NULL = jugando sin cuenta
  mode          VARCHAR(32) NOT NULL,
  gens          VARCHAR(64) NOT NULL,         -- JSON
  score         INT NOT NULL DEFAULT 0,
  level         INT NOT NULL DEFAULT 1,
  hits          INT NOT NULL DEFAULT 0,
  streak        INT NOT NULL DEFAULT 0,
  rounds        INT NOT NULL DEFAULT 0,       -- rondas respondidas
  total_time    DOUBLE NOT NULL DEFAULT 0,    -- suma de tiempos de respuesta (para la media)
  recent        TEXT NOT NULL,                -- JSON: últimos Pokémon salidos, para no repetir
  answer_id     INT NULL,                     -- respuesta de la ronda actual
  options       VARCHAR(255) NULL,            -- JSON: opciones de la ronda, en orden de pantalla
  time_limit    DOUBLE NULL,                  -- segundos de la ronda actual
  round_started DOUBLE NULL,                  -- hora unix con decimales (NULL = ronda aún no mostrada)
  finished      TINYINT(1) NOT NULL DEFAULT 0,
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (player_id) REFERENCES players(id) ON DELETE CASCADE,
  INDEX games_open_idx (player_id, finished)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
