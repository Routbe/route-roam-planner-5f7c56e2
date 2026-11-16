-- 0282: the blue identity mark comes only from a completed Didit attestation (EXPAND, additive).
--
-- Owner decision 2026-11-15: identity and payment are separate. 0281 still answered only for
-- profiles.verified = true, a flag that a payment, an admin grant or a business/influencer
-- approval also sets, and a member who passed Didit without paying got no answer at all.
-- These definers ignore profiles.verified and is_paid entirely:
--   didit_legal_identity: identity_verifications row from provider 'didit' that passed, or a
--     verified_identities legal tier with a national-id nullifier (written only by a Didit
--     upgrade; Didit is the sole legal provider in src/lib/identity/identity-tiers.ts);
--   real_human: any passed unique-human check (pseudonymous, for the privacy shield).
-- At most 200 ids per call, ids come from server readers only; provider,
-- names and nullifiers never leave the database. No table, policy or data is changed.

create or replace function public.rout_public_identity_badges(p_user_ids uuid[])
 returns table(user_id uuid, didit_legal_identity boolean, real_human boolean)
 language sql
 stable
 security definer
 set search_path = pg_catalog, pg_temp
as $function$
  with t as (
    select p.id,
      (coalesce(iv.is_verified, false) and iv.verification_provider::text = 'didit')
        or (coalesce(vi.tier_2_legal_identity, false) and vi.national_id_nullifier is not null) as legal,
      coalesce(vi.tier_1_real_human, false)
        or (coalesce(iv.is_verified, false) and iv.verification_provider::text in ('w_identity', 'didit', 'manual')) as human
    from public.profiles p
    left join public.identity_verifications iv on iv.user_id = p.id
    left join public.verified_identities vi on vi.user_id = p.id
    where p.id = any (coalesce(p_user_ids[1:200], '{}'::uuid[]))
  )
  select t.id, t.legal, t.legal or t.human from t
$function$;

-- Count for the public community figure: active members with a public handle and a Didit result.
create or replace function public.rout_public_didit_member_count()
 returns integer
 language sql
 stable
 security definer
 set search_path = pg_catalog, pg_temp
as $function$
  select pg_catalog.count(*)::integer
    from public.profiles p
    left join public.identity_verifications iv on iv.user_id = p.id
    left join public.verified_identities vi on vi.user_id = p.id
   where p.username is not null
     and coalesce(p.is_banned, false) = false
     and coalesce(p.is_suspended, false) = false
     and ((coalesce(iv.is_verified, false) and iv.verification_provider::text = 'didit')
       or (coalesce(vi.tier_2_legal_identity, false) and vi.national_id_nullifier is not null))
$function$;

revoke all on function public.rout_public_identity_badges(uuid[]) from public;
grant execute on function public.rout_public_identity_badges(uuid[]) to rout_app;
revoke all on function public.rout_public_didit_member_count() from public;
grant execute on function public.rout_public_didit_member_count() to rout_app;
