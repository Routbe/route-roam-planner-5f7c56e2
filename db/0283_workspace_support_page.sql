-- 0283: workspace support page /w/<slug>/support (EXPAND, additive).
--
-- Owner decision 2026-11-15: support for a workspace goes to the workspace's own payout
-- configuration, never to the founder's personal tip page or keys. ROUT moves no money:
-- the page shows an EPC/SEPA QR + IBAN, and optionally pays out through the workspace's
-- own Stripe/Mollie keys (AES-GCM sealed by the server with PSP_ENCRYPTION_KEY, as db/58).
--
-- Who manages it: workspace owner and admins only, taken from rout.current_user_id.
-- Eligibility: the workspace owner holds a completed Didit attestation (db/0282 rule) OR the
-- workspace has a verified DNS business domain. The IBAN holder must match the owner's
-- Didit legal name or, with a verified domain, the workspace name / billing name; the
-- comparison runs here, so no admin ever receives the owner's legal name.
-- rout_app gets no table rights; everything goes through the definers below.

create table if not exists public.workspace_tip_settings (
  workspace_id  uuid primary key references public.workspaces(id) on delete cascade,
  enabled       boolean not null default false,
  iban          text check (iban is null or iban ~ '^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$'),
  account_name  text check (account_name is null or char_length(account_name) between 1 and 70),
  presets_cents integer[] not null default '{500,1000,2500}',
  allow_custom  boolean not null default true,
  min_cents     integer not null default 100 check (min_cents between 100 and 500000),
  message       text check (message is null or char_length(message) <= 400),
  psp_enabled   boolean not null default false,
  updated_by    uuid references public.users(id) on delete set null,
  updated_at    timestamptz not null default now(),
  check (pg_catalog.cardinality(presets_cents) <= 6)
);

create table if not exists public.workspace_psp_credentials (
  workspace_id    uuid not null references public.workspaces(id) on delete cascade,
  provider        text not null check (provider in ('stripe', 'mollie')),
  ciphertext      text not null,
  iv              text not null,
  last4           text not null check (char_length(last4) <= 4),
  mode            text not null check (mode in ('live', 'test')),
  publishable_key text,
  saved_by        uuid references public.users(id) on delete set null,
  verified_at     timestamptz not null default now(),
  primary key (workspace_id, provider)
);

revoke all on public.workspace_tip_settings, public.workspace_psp_credentials from public, rout_app;
alter table public.workspace_tip_settings enable row level security;
alter table public.workspace_psp_credentials enable row level security;

-- Internal: the caller is owner or admin of the workspace.
create or replace function public.rout_ws_support_manager(p_ws uuid)
 returns boolean language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select exists (select 1 from public.workspace_members m
    where m.workspace_id = p_ws and m.user_id = public.rout_current_user_id()
      and m.role::text in ('owner', 'admin'))
$function$;

-- Internal: account-holder names the workspace may use; empty when it is not eligible.
create or replace function public.rout_ws_support_names(p_ws uuid)
 returns setof text language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select n from (
    select coalesce(vi.legal_name, case when iv.verification_provider::text = 'didit' then iv.verified_real_name end) as n
      from public.workspace_members m
      left join public.identity_verifications iv on iv.user_id = m.user_id and coalesce(iv.is_verified, false)
      left join public.verified_identities vi on vi.user_id = m.user_id
           and coalesce(vi.tier_2_legal_identity, false) and vi.national_id_nullifier is not null
     where m.workspace_id = p_ws and m.role::text = 'owner'
       and ((coalesce(iv.is_verified, false) and iv.verification_provider::text = 'didit') or vi.user_id is not null)
    union all
    select w.name from public.workspaces w where w.id = p_ws and w.domain_verified_at is not null
    union all
    select w.billing_name from public.workspaces w where w.id = p_ws and w.domain_verified_at is not null
  ) x where n is not null and pg_catalog.btrim(n) <> ''
$function$;

create or replace function public.rout_ws_support_norm(p text)
 returns text language sql immutable security definer set search_path = pg_catalog, pg_temp
as $function$
  select pg_catalog.regexp_replace(pg_catalog.lower(pg_catalog.normalize(coalesce(p, ''), 'NFKD')), '[^a-z0-9]', '', 'g')
$function$;

-- Managers: current settings, eligibility and linked providers (no key material).
create or replace function public.rout_ws_support_get(p_ws uuid)
 returns table(enabled boolean, iban text, account_name text, presets_cents integer[], allow_custom boolean,
   min_cents integer, message text, psp_enabled boolean, owner_didit boolean, domain_verified boolean,
   providers jsonb)
 language plpgsql stable security definer set search_path = pg_catalog, pg_temp
as $function$
begin
  if not public.rout_ws_support_manager(p_ws) then return; end if;
  return query
  select coalesce(s.enabled, false), s.iban, s.account_name, coalesce(s.presets_cents, '{500,1000,2500}'::integer[]),
         coalesce(s.allow_custom, true), coalesce(s.min_cents, 100), s.message, coalesce(s.psp_enabled, false),
         exists (select 1 from public.workspace_members m
                   left join public.identity_verifications iv on iv.user_id = m.user_id
                   left join public.verified_identities vi on vi.user_id = m.user_id
                  where m.workspace_id = p_ws and m.role::text = 'owner'
                    and ((coalesce(iv.is_verified, false) and iv.verification_provider::text = 'didit')
                      or (coalesce(vi.tier_2_legal_identity, false) and vi.national_id_nullifier is not null))),
         w.domain_verified_at is not null,
         coalesce((select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('provider', c.provider, 'last4', c.last4,
                     'mode', c.mode, 'verifiedAt', c.verified_at) order by c.provider)
                     from public.workspace_psp_credentials c where c.workspace_id = p_ws), '[]'::jsonb)
    from public.workspaces w
    left join public.workspace_tip_settings s on s.workspace_id = w.id
   where w.id = p_ws;
end $function$;

-- Managers: save settings. Answers ok | forbidden | not_eligible | name_mismatch | invalid.
create or replace function public.rout_ws_support_save(p_ws uuid, p_enabled boolean, p_iban text, p_account_name text,
  p_presets integer[], p_allow_custom boolean, p_min integer, p_message text, p_psp_enabled boolean)
 returns text language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
declare
  v_iban text := nullif(pg_catalog.upper(pg_catalog.regexp_replace(coalesce(p_iban, ''), '\s+', '', 'g')), '');
  v_name text := nullif(pg_catalog.btrim(coalesce(p_account_name, '')), '');
begin
  if not public.rout_ws_support_manager(p_ws) then return 'forbidden'; end if;
  if v_iban is not null and v_iban !~ '^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$' then return 'invalid'; end if;
  if p_min is null or p_min not between 100 and 500000 or pg_catalog.cardinality(coalesce(p_presets, '{}')) > 6
     or exists (select 1 from pg_catalog.unnest(coalesce(p_presets, '{}')) c where c < p_min or c > 500000)
     or (p_message is not null and pg_catalog.char_length(p_message) > 400)
     or (v_name is not null and pg_catalog.char_length(v_name) > 70) then
    return 'invalid';
  end if;
  if p_enabled or v_iban is not null then
    if v_iban is null or v_name is null then return 'invalid'; end if;
    if not exists (select 1 from public.rout_ws_support_names(p_ws)) then return 'not_eligible'; end if;
    if not exists (select 1 from public.rout_ws_support_names(p_ws) n
                    where public.rout_ws_support_norm(n) = public.rout_ws_support_norm(v_name)) then
      return 'name_mismatch';
    end if;
  end if;
  insert into public.workspace_tip_settings as s (workspace_id, enabled, iban, account_name, presets_cents, allow_custom,
      min_cents, message, psp_enabled, updated_by, updated_at)
  values (p_ws, p_enabled, v_iban, v_name, coalesce(p_presets, '{}'), p_allow_custom, p_min,
      nullif(pg_catalog.btrim(coalesce(p_message, '')), ''), p_psp_enabled, public.rout_current_user_id(), pg_catalog.now())
  on conflict (workspace_id) do update set enabled = excluded.enabled, iban = excluded.iban,
      account_name = excluded.account_name, presets_cents = excluded.presets_cents, allow_custom = excluded.allow_custom,
      min_cents = excluded.min_cents, message = excluded.message, psp_enabled = excluded.psp_enabled,
      updated_by = excluded.updated_by, updated_at = pg_catalog.now();
  return 'ok';
end $function$;

-- Managers: store a sealed provider key (the plaintext never reaches the database).
create or replace function public.rout_ws_psp_save(p_ws uuid, p_provider text, p_ciphertext text, p_iv text,
  p_last4 text, p_mode text, p_publishable_key text)
 returns text language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
begin
  if not public.rout_ws_support_manager(p_ws) then return 'forbidden'; end if;
  if not exists (select 1 from public.rout_ws_support_names(p_ws)) then return 'not_eligible'; end if;
  if p_provider not in ('stripe', 'mollie') or p_mode not in ('live', 'test') then return 'invalid'; end if;
  insert into public.workspace_psp_credentials (workspace_id, provider, ciphertext, iv, last4, mode, publishable_key, saved_by, verified_at)
  values (p_ws, p_provider, p_ciphertext, p_iv, pg_catalog.right(coalesce(p_last4, ''), 4), p_mode, p_publishable_key,
          public.rout_current_user_id(), pg_catalog.now())
  on conflict (workspace_id, provider) do update set ciphertext = excluded.ciphertext, iv = excluded.iv,
    last4 = excluded.last4, mode = excluded.mode, publishable_key = excluded.publishable_key,
    saved_by = excluded.saved_by, verified_at = pg_catalog.now();
  return 'ok';
end $function$;

create or replace function public.rout_ws_psp_delete(p_ws uuid, p_provider text)
 returns text language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
begin
  if not public.rout_ws_support_manager(p_ws) then return 'forbidden'; end if;
  delete from public.workspace_psp_credentials where workspace_id = p_ws and provider = p_provider;
  return 'ok';
end $function$;

-- Public: an active, still eligible support page, or nothing. Eligibility and the holder
-- name are re-checked at every read, so a lost Didit result or domain closes the page.
create or replace function public.rout_public_ws_support(p_slug text)
 returns table(workspace_id uuid, name text, slug text, avatar_url text, account_name text, iban text,
   presets_cents integer[], allow_custom boolean, min_cents integer, message text, providers text[])
 language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select w.id, w.name, w.slug, w.avatar_url, s.account_name, s.iban, s.presets_cents, s.allow_custom, s.min_cents, s.message,
         case when s.psp_enabled then coalesce((select pg_catalog.array_agg(c.provider order by c.provider)
           from public.workspace_psp_credentials c where c.workspace_id = w.id), '{}'::text[]) else '{}'::text[] end
    from public.workspaces w
    join public.workspace_tip_settings s on s.workspace_id = w.id
   where w.slug = pg_catalog.lower(p_slug) and s.enabled and s.iban is not null and s.account_name is not null
     and exists (select 1 from public.rout_ws_support_names(w.id) n
                  where public.rout_ws_support_norm(n) = public.rout_ws_support_norm(s.account_name))
   limit 1
$function$;

-- Payment start only: the sealed key of a workspace with an active public support page.
-- Useless without PSP_ENCRYPTION_KEY, which lives only in the server environment.
create or replace function public.rout_ws_psp_tip_credential(p_slug text, p_provider text)
 returns table(workspace_id uuid, ciphertext text, iv text, publishable_key text)
 language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select c.workspace_id, c.ciphertext, c.iv, c.publishable_key
    from public.rout_public_ws_support(p_slug) p
    join public.workspace_psp_credentials c on c.workspace_id = p.workspace_id and c.provider = p_provider
   where p_provider = any (p.providers)
   limit 1
$function$;

revoke all on function public.rout_ws_support_manager(uuid) from public, rout_app;
revoke all on function public.rout_ws_support_names(uuid) from public, rout_app;
revoke all on function public.rout_ws_support_norm(text) from public, rout_app;
revoke all on function public.rout_ws_support_get(uuid) from public;
revoke all on function public.rout_ws_support_save(uuid, boolean, text, text, integer[], boolean, integer, text, boolean) from public;
revoke all on function public.rout_ws_psp_save(uuid, text, text, text, text, text, text) from public;
revoke all on function public.rout_ws_psp_delete(uuid, text) from public;
revoke all on function public.rout_public_ws_support(text) from public;
revoke all on function public.rout_ws_psp_tip_credential(text, text) from public;
grant execute on function public.rout_ws_support_get(uuid) to rout_app;
grant execute on function public.rout_ws_support_save(uuid, boolean, text, text, integer[], boolean, integer, text, boolean) to rout_app;
grant execute on function public.rout_ws_psp_save(uuid, text, text, text, text, text, text) to rout_app;
grant execute on function public.rout_ws_psp_delete(uuid, text) to rout_app;
grant execute on function public.rout_public_ws_support(text) to rout_app;
grant execute on function public.rout_ws_psp_tip_credential(text, text) to rout_app;
