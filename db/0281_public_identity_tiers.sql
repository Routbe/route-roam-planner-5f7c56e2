-- 0281: public identity tiers for the verified badge (EXPAND, additive).
--
-- The blue mark on a public root profile needs tier 2 (legal identity, e.g. Didit).
-- readTrustMeta read identity_verifications / verified_identities as rout_app, but both
-- tables only allow a member's own row (rout_scope = rout_current_user_id()). A visitor
-- has no member context, so the Didit result was invisible and the mark depended on the
-- legacy is_paid flag alone. This definer returns two booleans for a verified profile and
-- nothing else: provider, names and nullifiers never leave the database.
-- Tier rules mirror src/lib/identity/identity-tiers.ts (legal: didit, itsme, eid; unique
-- human: w_identity, didit, itsme, eid, manual; a passkey alone is never a tier).
-- No table, policy or data is changed.

create or replace function public.rout_public_identity_tiers(p_user_id uuid)
 returns table(tier_1_real_human boolean, tier_2_legal_identity boolean)
 language sql
 stable
 security definer
 set search_path = pg_catalog, pg_temp
as $function$
  with t as (
    select
      coalesce(vi.tier_2_legal_identity, false)
        or (coalesce(iv.is_verified, false) and iv.verification_provider::text in ('didit', 'itsme', 'eid')) as legal,
      coalesce(vi.tier_1_real_human, false)
        or (coalesce(iv.is_verified, false) and iv.verification_provider::text in ('w_identity', 'didit', 'itsme', 'eid', 'manual')) as human
    from public.profiles p
    left join public.identity_verifications iv on iv.user_id = p.id
    left join public.verified_identities vi on vi.user_id = p.id
    where p.id = p_user_id
      and coalesce(p.verified, false) = true
  )
  select t.human or t.legal, t.legal from t
$function$;

revoke all on function public.rout_public_identity_tiers(uuid) from public;
grant execute on function public.rout_public_identity_tiers(uuid) to rout_app;
