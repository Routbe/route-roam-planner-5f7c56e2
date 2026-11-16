-- 0285 (EXPAND, additive): workspace group encryption and the anonymous question page.
--
-- Owner directive 2026-11-16 (FASE 2, "STAP 2 — WORKSPACE RVE1 GROUP ENCRYPTION"):
--   * workspace_rve1_pk  -> public.workspace_keys: the workspace's own RVE1 public key,
--     per key epoch. Visitors use it client-side to encrypt questions on /w/<slug>/ask.
--   * workspace_member_envelopes -> public.workspace_member_keys: the workspace secret key
--     (its 32-byte RVE1 seed) sealed to each authorized member's personal RVE1 public key.
--   * RBAC: envelopes exist only for role owner or admin. editor, developer and viewer are
--     refused by rout_ws_group_member_store, which re-reads the role from workspace_members.
--   * Key rotation: publishing a new epoch retires the previous one. Remaining managers
--     issue member keys for the new epoch; a former manager holds no envelope for it and so
--     cannot open questions filed after the rotation.
--
-- Questions (public.workspace_questions) arrive as one RVE1 envelope of kind wq sealed to
-- the workspace's active epoch key, plus the visitor's reply public key and the SHA-256 of
-- their private #token= secret. The server verifies the BLAKE3 Hashcash proof before calling
-- rout_ws_question_create; this function re-checks the envelope shape, the epoch and the
-- proof bucket on the database clock, and refuses a second row with the same payload hash.
--
-- Answers: a private reply is an RVE1 envelope of kind wa sealed to the visitor's reply key
-- (public.workspace_question_replies), opened only by the browser holding #token=. A public
-- reply is a deliberate release: the manager who read the question publishes the question
-- text and the answer text as an anonymous FAQ item (public.workspace_faq_items).
--
-- Envelope kinds (pqc-envelope.ts, new codes 10/11/12): wsk = workspace secret key sealed to
-- a member device, wq = question sealed to the workspace key (opened on a member device),
-- wa = answer sealed to the visitor's own reply key. Base64url header prefixes:
-- wsk 'UlZFMQEK', wq 'UlZFMQEL', wa 'UlZFMQEM'. Padded buckets are the three booking sizes.
--
-- rout_app holds no table privilege on any of these tables; RLS is enabled with no policy,
-- so every read and write goes through the SECURITY DEFINER functions below, which take the
-- caller from the transaction context (rout.current_user_id), never from a parameter.
-- Rollback: db-pending/0285_workspace_group_encryption_rollback.sql.

-- --------------------------------------------------------------------------- tables

create table if not exists public.workspace_keys (
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  epoch        integer not null check (epoch >= 1),
  -- RVE1 recipient public key: ML-KEM-1024 (1568) || X25519 (32) = 1600 bytes, base64url.
  public_key   text not null check (public_key ~ '^[A-Za-z0-9_-]+$' and length(public_key) = 2134),
  kid          text not null check (kid ~ '^[A-Za-z0-9_-]{22}$'),
  status       text not null default 'active' check (status in ('active', 'retired')),
  created_by   uuid references public.users(id) on delete set null,
  created_at   timestamptz not null default now(),
  retired_at   timestamptz,
  primary key (workspace_id, epoch)
);
-- Exactly one live key per workspace: a visitor must never have to guess which epoch to seal for.
create unique index workspace_keys_one_active_idx on public.workspace_keys (workspace_id)
  where status = 'active';

create table if not exists public.workspace_member_keys (
  workspace_id   uuid not null,
  epoch          integer not null,
  member_user_id uuid not null references public.users(id) on delete cascade,
  -- Reference of the member's own personal key (never a vault token), so an envelope that
  -- was sealed to somebody else's key is refused before it is stored.
  member_ref     uuid not null,
  kid            text not null check (kid ~ '^[A-Za-z0-9_-]{22}$'),
  -- RVE1 kind wsk: the workspace secret key (its 32-byte seed, padded) sealed to this member.
  envelope       text not null check (
    envelope ~ '^[A-Za-z0-9_-]+$' and length(envelope) in (3583, 7679, 24063)
    and left(envelope, 8) = 'UlZFMQEK'),
  created_at     timestamptz not null default now(),
  primary key (workspace_id, epoch, member_user_id),
  foreign key (workspace_id, epoch) references public.workspace_keys(workspace_id, epoch) on delete cascade
);
create index workspace_member_keys_member_idx on public.workspace_member_keys (member_user_id, epoch);

create table if not exists public.workspace_ask_settings (
  workspace_id uuid primary key references public.workspaces(id) on delete cascade,
  enabled      boolean not null default false,
  updated_by   uuid references public.users(id) on delete set null,
  updated_at   timestamptz not null default now()
);

create table if not exists public.workspace_questions (
  id               uuid primary key default gen_random_uuid(),
  workspace_id     uuid not null references public.workspaces(id) on delete cascade,
  epoch            integer not null,
  payload_id       uuid not null unique,
  -- RVE1 kind wq: the question, sealed to the workspace key of this epoch.
  envelope         text not null check (
    envelope ~ '^[A-Za-z0-9_-]+$' and length(envelope) in (3583, 7679, 24063)
    and left(envelope, 8) = 'UlZFMQEL'),
  blake3_payload_hash bytea not null unique check (octet_length(blake3_payload_hash) = 32),
  pow_nonce        text not null check (pow_nonce ~ '^[0-9a-f]{16}$'),
  epoch_bucket     integer not null check (epoch_bucket > 0),
  -- Public half of the visitor's reply key; the private half lives only in their #token=.
  guest_public_key text not null check (
    guest_public_key ~ '^[A-Za-z0-9_-]+$' and length(guest_public_key) = 2134),
  -- SHA-256 of the visitor's 32-byte token. The token itself never reaches the server.
  token_hash       bytea not null check (octet_length(token_hash) = 32),
  status           text not null default 'open' check (status in ('open', 'answered', 'published', 'declined')),
  created_at       timestamptz not null default now(),
  answered_at      timestamptz
);
create index workspace_questions_ws_idx on public.workspace_questions (workspace_id, created_at desc);
-- One question per token per workspace: a token is issued for exactly one submission.
create unique index workspace_questions_token_idx on public.workspace_questions (workspace_id, token_hash);

create table if not exists public.workspace_question_replies (
  question_id uuid primary key references public.workspace_questions(id) on delete cascade,
  -- RVE1 kind wa: the answer, sealed to the visitor's reply key.
  envelope    text not null check (
    envelope ~ '^[A-Za-z0-9_-]+$' and length(envelope) in (3583, 7679, 24063)
    and left(envelope, 8) = 'UlZFMQEM'),
  blake3_payload_hash bytea not null unique check (octet_length(blake3_payload_hash) = 32),
  replied_by  uuid references public.users(id) on delete set null,
  created_at  timestamptz not null default now()
);

-- Deliberate public release: the manager who opened the question publishes both texts.
-- Nothing here is written by the visitor's browser, so a published item is always a choice.
create table if not exists public.workspace_faq_items (
  id            uuid primary key default gen_random_uuid(),
  workspace_id  uuid not null references public.workspaces(id) on delete cascade,
  question_id   uuid not null unique references public.workspace_questions(id) on delete cascade,
  question_text text not null check (char_length(question_text) between 1 and 2000),
  answer_text   text not null check (char_length(answer_text) between 1 and 4000),
  published_by  uuid references public.users(id) on delete set null,
  published_at  timestamptz not null default now()
);
create index workspace_faq_ws_idx on public.workspace_faq_items (workspace_id, published_at desc);

-- --------------------------------------------------------------------------- rights

-- rout_app gets no table privilege at all: every path runs through a definer below.
revoke all on public.workspace_keys, public.workspace_member_keys, public.workspace_ask_settings,
  public.workspace_questions, public.workspace_question_replies, public.workspace_faq_items
  from public, rout_app;

alter table public.workspace_keys enable row level security;
alter table public.workspace_member_keys enable row level security;
alter table public.workspace_ask_settings enable row level security;
alter table public.workspace_questions enable row level security;
alter table public.workspace_question_replies enable row level security;
alter table public.workspace_faq_items enable row level security;

-- --------------------------------------------------------------------------- internal helpers

-- The caller is owner or admin of the workspace. developer, editor and viewer are not managers.
create or replace function public.rout_ws_group_manager(p_ws uuid)
 returns boolean language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select exists (select 1 from public.workspace_members m
    where m.workspace_id = p_ws and m.user_id = public.rout_current_user_id()
      and m.role::text in ('owner', 'admin'))
$function$;

-- Shape of one RVE1 envelope of the requested kind, in base64url, in one of the three
-- padded buckets. The eight leading characters are magic "RVE1", suite 1 and the kind byte.
create or replace function public.rout_ws_group_envelope_ok(p_envelope text, p_kind text)
 returns boolean language sql immutable security definer set search_path = pg_catalog, pg_temp
as $function$
  select p_envelope is not null and p_kind in ('wsk', 'wq', 'wa')
     and p_envelope ~ '^[A-Za-z0-9_-]+$'
     and pg_catalog.length(p_envelope) in (3583, 7679, 24063)
     and pg_catalog.left(p_envelope, 8) = case p_kind
           when 'wsk' then 'UlZFMQEK' when 'wq' then 'UlZFMQEL' else 'UlZFMQEM' end
$function$;

-- The Hashcash bucket must sit within one 10-minute bucket of the database clock.
create or replace function public.rout_ws_group_epoch_ok(p_bucket integer)
 returns boolean language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select p_bucket is not null
     and pg_catalog.abs(p_bucket - pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.now()) / 600)::integer) <= 1
$function$;

-- The workspace's live key, or null when it has none.
create or replace function public.rout_ws_group_active(p_ws uuid)
 returns table(epoch integer, public_key text, kid text)
 language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select k.epoch, k.public_key, k.kid from public.workspace_keys k
   where k.workspace_id = p_ws and k.status = 'active'
   limit 1
$function$;

-- --------------------------------------------------------------------------- managers: key epochs

-- Publish (or replace) the workspace's live key for a new epoch. Managers only. The epoch
-- number must be the next one, so a retired epoch can never be brought back to life.
-- Publishing is the rotation: the previous live key is retired in the same transaction.
create or replace function public.rout_ws_group_publish(p_ws uuid, p_epoch integer,
  p_public_key text, p_kid text)
 returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
declare v_max integer;
begin
  if not public.rout_ws_group_manager(p_ws) then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'forbidden'); end if;
  if p_epoch is null or p_epoch < 1
     or p_public_key is null or p_public_key !~ '^[A-Za-z0-9_-]+$' or pg_catalog.length(p_public_key) <> 2134
     or p_kid is null or p_kid !~ '^[A-Za-z0-9_-]{22}$' then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'invalid');
  end if;
  select pg_catalog.coalesce(pg_catalog.max(epoch), 0) into v_max from public.workspace_keys where workspace_id = p_ws;
  if p_epoch <> v_max + 1 then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'epoch'); end if;
  update public.workspace_keys set status = 'retired', retired_at = pg_catalog.now()
   where workspace_id = p_ws and status = 'active';
  insert into public.workspace_keys (workspace_id, epoch, public_key, kid, status, created_by)
  values (p_ws, p_epoch, p_public_key, p_kid, 'active', public.rout_current_user_id());
  return pg_catalog.jsonb_build_object('ok', true, 'epoch', p_epoch);
end $function$;

-- Store the workspace secret key for one member. Managers only, and the target must be
-- owner or admin at this very moment: editor, developer and viewer never get an envelope.
create or replace function public.rout_ws_group_member_store(p_ws uuid, p_epoch integer,
  p_member uuid, p_member_ref uuid, p_kid text, p_envelope text)
 returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
begin
  if not public.rout_ws_group_manager(p_ws) then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'forbidden'); end if;
  if p_member is null or p_member_ref is null
     or p_kid is null or p_kid !~ '^[A-Za-z0-9_-]{22}$'
     or not public.rout_ws_group_envelope_ok(p_envelope, 'wsk') then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'invalid');
  end if;
  if not exists (select 1 from public.workspace_keys k
                  where k.workspace_id = p_ws and k.epoch = p_epoch and k.status = 'active') then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'epoch');
  end if;
  if not exists (select 1 from public.workspace_members m
                  where m.workspace_id = p_ws and m.user_id = p_member
                    and m.role::text in ('owner', 'admin')) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'forbidden');
  end if;
  insert into public.workspace_member_keys (workspace_id, epoch, member_user_id, member_ref, kid, envelope)
  values (p_ws, p_epoch, p_member, p_member_ref, p_kid, p_envelope)
  on conflict (workspace_id, epoch, member_user_id) do update
    set member_ref = excluded.member_ref, kid = excluded.kid, envelope = excluded.envelope;
  return pg_catalog.jsonb_build_object('ok', true);
end $function$;

-- The caller's own sealed workspace key for one epoch. A member who is no longer owner or
-- admin gets nothing, even while an older envelope for that member is still on the table.
create or replace function public.rout_ws_group_member_key(p_ws uuid, p_epoch integer)
 returns jsonb language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select pg_catalog.coalesce(
    (select pg_catalog.jsonb_build_object('ok', true, 'envelope', m.envelope, 'kid', m.kid, 'memberRef', m.member_ref)
       from public.workspace_member_keys m
      where m.workspace_id = p_ws and m.epoch = p_epoch
        and m.member_user_id = public.rout_current_user_id()
        and exists (select 1 from public.workspace_members x
                     where x.workspace_id = p_ws and x.user_id = m.member_user_id
                       and x.role::text in ('owner', 'admin'))
      limit 1),
    pg_catalog.jsonb_build_object('ok', false, 'reason', 'none'))
$function$;

-- Managers: the key history and, per epoch, which managers still have no envelope.
-- No key material and no ciphertext is ever returned here.
create or replace function public.rout_ws_group_state(p_ws uuid)
 returns jsonb language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select case when public.rout_ws_group_manager(p_ws) then pg_catalog.jsonb_build_object(
    'epochs', coalesce((select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'epoch', k.epoch, 'status', k.status, 'kid', k.kid, 'publicKey', k.public_key,
        'createdAt', k.created_at, 'retiredAt', k.retired_at,
        'heldBy', (select pg_catalog.count(*) from public.workspace_member_keys m where m.workspace_id = k.workspace_id and m.epoch = k.epoch),
        'missing', coalesce((select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('userId', x.user_id, 'role', x.role::text) order by x.user_id)
                              from public.workspace_members x
                             where x.workspace_id = p_ws and x.role::text in ('owner', 'admin')
                               and not exists (select 1 from public.workspace_member_keys m
                                                where m.workspace_id = k.workspace_id and m.epoch = k.epoch
                                                  and m.member_user_id = x.user_id)), '[]'::jsonb)
        ) order by k.epoch desc)
       from public.workspace_keys k where k.workspace_id = p_ws), '[]'::jsonb))
    else pg_catalog.jsonb_build_object('epochs', '[]'::jsonb) end
$function$;

-- --------------------------------------------------------------------------- managers: ask switch

create or replace function public.rout_ws_ask_save(p_ws uuid, p_enabled boolean)
 returns text language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
begin
  if not public.rout_ws_group_manager(p_ws) then return 'forbidden'; end if;
  if p_enabled is null then return 'invalid'; end if;
  insert into public.workspace_ask_settings (workspace_id, enabled, updated_by, updated_at)
  values (p_ws, p_enabled, public.rout_current_user_id(), pg_catalog.now())
  on conflict (workspace_id) do update set enabled = excluded.enabled,
    updated_by = excluded.updated_by, updated_at = excluded.updated_at;
  return 'ok';
end $function$;

-- --------------------------------------------------------------------------- public: ask page

-- What the anonymous /w/<slug>/ask page needs: the live key of an enabled workspace.
-- A workspace without a live key or without the switch answers nothing.
create or replace function public.rout_public_ws_ask_key(p_slug text)
 returns jsonb language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select pg_catalog.jsonb_build_object('workspaceId', w.id, 'name', w.name, 'slug', w.slug,
           'epoch', k.epoch, 'kid', k.kid, 'publicKey', k.public_key)
    from public.workspaces w
    join public.workspace_ask_settings s on s.workspace_id = w.id and s.enabled
    join public.workspace_keys k on k.workspace_id = w.id and k.status = 'active'
   where w.slug = pg_catalog.lower(p_slug)
   limit 1
$function$;

-- Anonymous submission. The server has already verified the Hashcash proof over these exact
-- bytes and the envelope header against the live key; this function re-checks the shape,
-- the epoch and the bucket on the database clock and refuses a replayed payload hash.
create or replace function public.rout_ws_question_create(p_slug text, p_payload_id uuid, p_epoch integer,
  p_envelope text, p_hash bytea, p_pow_nonce text, p_epoch_bucket integer,
  p_guest_public_key text, p_token_hash bytea)
 returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
declare v_ws uuid; v_kid text; v_id uuid;
begin
  if p_slug is null or p_payload_id is null or p_epoch is null
     or not public.rout_ws_group_envelope_ok(p_envelope, 'wq')
     or p_hash is null or pg_catalog.octet_length(p_hash) <> 32
     or p_pow_nonce is null or p_pow_nonce !~ '^[0-9a-f]{16}$'
     or p_guest_public_key is null or p_guest_public_key !~ '^[A-Za-z0-9_-]+$'
     or pg_catalog.length(p_guest_public_key) <> 2134
     or p_token_hash is null or pg_catalog.octet_length(p_token_hash) <> 32 then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'invalid');
  end if;
  if not public.rout_ws_group_epoch_ok(p_epoch_bucket) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'pow_stale');
  end if;
  select k.workspace_id, k.kid into v_ws, v_kid
    from public.workspaces w
    join public.workspace_ask_settings s on s.workspace_id = w.id and s.enabled
    join public.workspace_keys k on k.workspace_id = w.id and k.status = 'active'
   where w.slug = pg_catalog.lower(p_slug)
   limit 1;
  if v_ws is null then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'unavailable'); end if;
  -- The envelope must carry the epoch the visitor was actually shown. Which key that epoch
  -- holds is checked by the server on the envelope header before this call, as in db/0278.
  if not exists (select 1 from public.workspace_keys k
                  where k.workspace_id = v_ws and k.epoch = p_epoch) then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'epoch');
  end if;
  -- Flood ceiling on top of the proof-of-work.
  if (select pg_catalog.count(*) from public.workspace_questions q
       where q.workspace_id = v_ws and q.created_at > pg_catalog.now() - interval '1 hour') >= 30 then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'rate_limited');
  end if;
  begin
    insert into public.workspace_questions (workspace_id, epoch, payload_id, envelope,
      blake3_payload_hash, pow_nonce, epoch_bucket, guest_public_key, token_hash)
    values (v_ws, p_epoch, p_payload_id, p_envelope,
      p_hash, p_pow_nonce, p_epoch_bucket, p_guest_public_key, p_token_hash)
    returning id into v_id;
  exception when unique_violation then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'duplicate');
  end;
  return pg_catalog.jsonb_build_object('ok', true, 'id', v_id);
end $function$;

-- --------------------------------------------------------------------------- managers: inbox

-- Managers: the questions of their own workspace, ciphertext only. The guest reply key is
-- handed back because sealing a private answer needs it; no plaintext is ever returned.
create or replace function public.rout_ws_question_list(p_ws uuid)
 returns table(id uuid, epoch integer, payload_id uuid, status text, created_at timestamptz,
   answered_at timestamptz, envelope text, kid text, guest_public_key text, has_reply boolean)
 language plpgsql stable security definer set search_path = pg_catalog, pg_temp
as $function$
begin
  if not public.rout_ws_group_manager(p_ws) then return; end if;
  return query
  select q.id, q.epoch, q.payload_id, q.status, q.created_at, q.answered_at, q.envelope,
         k.kid, q.guest_public_key, (r.question_id is not null)
    from public.workspace_questions q
    join public.workspace_keys k on k.workspace_id = q.workspace_id and k.epoch = q.epoch
    left join public.workspace_question_replies r on r.question_id = q.id
   where q.workspace_id = p_ws
   order by q.created_at desc;
end $function$;

-- Private answer: sealed to the visitor's reply key. Managers only; one answer per question.
create or replace function public.rout_ws_question_reply(p_question_id uuid, p_envelope text, p_hash bytea)
 returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
declare v_ws uuid; v_status text;
begin
  if p_question_id is null or not public.rout_ws_group_envelope_ok(p_envelope, 'wa')
     or p_hash is null or pg_catalog.octet_length(p_hash) <> 32 then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'invalid');
  end if;
  select q.workspace_id, q.status into v_ws, v_status from public.workspace_questions q where q.id = p_question_id;
  if v_ws is null then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'invalid'); end if;
  if not public.rout_ws_group_manager(v_ws) then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'forbidden'); end if;
  if v_status = 'declined' then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'declined'); end if;
  begin
    insert into public.workspace_question_replies (question_id, envelope, blake3_payload_hash, replied_by)
    values (p_question_id, p_envelope, p_hash, public.rout_current_user_id())
    on conflict (question_id) do update set envelope = excluded.envelope,
      blake3_payload_hash = excluded.blake3_payload_hash, replied_by = excluded.replied_by,
      created_at = pg_catalog.now();
  exception when unique_violation then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'duplicate');
  end;
  update public.workspace_questions set status = 'answered', answered_at = pg_catalog.now() where id = p_question_id;
  return pg_catalog.jsonb_build_object('ok', true);
end $function$;

-- Public answer: the deliberate release of question and answer as an anonymous FAQ item.
-- The texts come from the manager's own enclave, so publishing is always an explicit choice.
create or replace function public.rout_ws_question_publish(p_question_id uuid, p_question_text text, p_answer_text text)
 returns jsonb language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
declare v_ws uuid;
begin
  if p_question_id is null
     or p_question_text is null or pg_catalog.char_length(p_question_text) not between 1 and 2000
     or p_answer_text is null or pg_catalog.char_length(p_answer_text) not between 1 and 4000 then
    return pg_catalog.jsonb_build_object('ok', false, 'reason', 'invalid');
  end if;
  select q.workspace_id into v_ws from public.workspace_questions q where q.id = p_question_id;
  if v_ws is null then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'invalid'); end if;
  if not public.rout_ws_group_manager(v_ws) then return pg_catalog.jsonb_build_object('ok', false, 'reason', 'forbidden'); end if;
  insert into public.workspace_faq_items (workspace_id, question_id, question_text, answer_text, published_by)
  values (v_ws, p_question_id, p_question_text, p_answer_text, public.rout_current_user_id())
  on conflict (question_id) do update set question_text = excluded.question_text,
    answer_text = excluded.answer_text, published_by = excluded.published_by, published_at = pg_catalog.now();
  update public.workspace_questions set status = 'published' where id = p_question_id;
  return pg_catalog.jsonb_build_object('ok', true);
end $function$;

-- Managers: close a question without answering it.
create or replace function public.rout_ws_question_decline(p_question_id uuid)
 returns text language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
declare v_ws uuid;
begin
  select q.workspace_id into v_ws from public.workspace_questions q where q.id = p_question_id;
  if v_ws is null then return 'invalid'; end if;
  if not public.rout_ws_group_manager(v_ws) then return 'forbidden'; end if;
  update public.workspace_questions set status = 'declined', answered_at = pg_catalog.now()
   where id = p_question_id and status <> 'published';
  return 'ok';
end $function$;

-- --------------------------------------------------------------------------- public: FAQ and answer

-- The published FAQ of a workspace. Only items a manager deliberately released appear here.
create or replace function public.rout_public_ws_faq(p_slug text)
 returns table(id uuid, question_text text, answer_text text, published_at timestamptz)
 language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select f.id, f.question_text, f.answer_text, f.published_at
    from public.workspace_faq_items f
    join public.workspaces w on w.id = f.workspace_id
   where w.slug = pg_catalog.lower(p_slug)
   order by f.published_at desc
   limit 100
$function$;

-- The visitor's private answer, found by the hash of their own token. The browser still needs
-- the token itself to open the envelope, so this row is useless to anyone else. Always one
-- answer object back, so a caller cannot tell "no such token" from "no answer yet" by row count.
create or replace function public.rout_ws_answer_fetch(p_token_hash bytea)
 returns jsonb language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select pg_catalog.coalesce(
    (select pg_catalog.jsonb_build_object('ok', true, 'status', q.status,
             'envelope', (select r.envelope from public.workspace_question_replies r where r.question_id = q.id),
             'workspaceName', w.name, 'slug', w.slug)
       from public.workspace_questions q
       join public.workspaces w on w.id = q.workspace_id
      where q.token_hash = p_token_hash
      limit 1),
    pg_catalog.jsonb_build_object('ok', false, 'reason', 'not_found'))
$function$;

-- --------------------------------------------------------------------------- function rights

-- Internal helpers: neither rout_app nor PUBLIC may call them.
revoke all on function public.rout_ws_group_manager(uuid) from public, rout_app;
revoke all on function public.rout_ws_group_envelope_ok(text, text) from public, rout_app;
revoke all on function public.rout_ws_group_epoch_ok(integer) from public, rout_app;
revoke all on function public.rout_ws_group_active(uuid) from public, rout_app;

-- Entry points: PUBLIC gets nothing, rout_app executes exactly these.
revoke all on function public.rout_ws_group_publish(uuid, integer, text, text) from public;
revoke all on function public.rout_ws_group_member_store(uuid, integer, uuid, uuid, text, text) from public;
revoke all on function public.rout_ws_group_member_key(uuid, integer) from public;
revoke all on function public.rout_ws_group_state(uuid) from public;
revoke all on function public.rout_ws_ask_save(uuid, boolean) from public;
revoke all on function public.rout_public_ws_ask_key(text) from public;
revoke all on function public.rout_ws_question_create(text, uuid, integer, text, bytea, text, integer, text, bytea) from public;
revoke all on function public.rout_ws_question_list(uuid) from public;
revoke all on function public.rout_ws_question_reply(uuid, text, bytea) from public;
revoke all on function public.rout_ws_question_publish(uuid, text, text) from public;
revoke all on function public.rout_ws_question_decline(uuid) from public;
revoke all on function public.rout_public_ws_faq(text) from public;
revoke all on function public.rout_ws_answer_fetch(bytea) from public;

grant execute on function public.rout_ws_group_publish(uuid, integer, text, text) to rout_app;
grant execute on function public.rout_ws_group_member_store(uuid, integer, uuid, uuid, text, text) to rout_app;
grant execute on function public.rout_ws_group_member_key(uuid, integer) to rout_app;
grant execute on function public.rout_ws_group_state(uuid) to rout_app;
grant execute on function public.rout_ws_ask_save(uuid, boolean) to rout_app;
grant execute on function public.rout_public_ws_ask_key(text) to rout_app;
grant execute on function public.rout_ws_question_create(text, uuid, integer, text, bytea, text, integer, text, bytea) to rout_app;
grant execute on function public.rout_ws_question_list(uuid) to rout_app;
grant execute on function public.rout_ws_question_reply(uuid, text, bytea) to rout_app;
grant execute on function public.rout_ws_question_publish(uuid, text, text) to rout_app;
grant execute on function public.rout_ws_question_decline(uuid) to rout_app;
grant execute on function public.rout_public_ws_faq(text) to rout_app;
grant execute on function public.rout_ws_answer_fetch(bytea) to rout_app;
