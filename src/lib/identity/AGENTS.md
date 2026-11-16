# Rules
- KYC: `identity_verifications` (db/81) stores a peppered HMAC `unique_human_id` (UNIQUE), is immutable for `rout_app` once verified, and its real name overrides `display_name` server-side; Didit is capped monthly in `didit_monthly_usage`. Why: one account per person, no fake names, bounded cost.
- The blue identity mark and every public trust badge come only from `rout_public_identity_badges` (db/0282, Didit); `profiles.verified`/`is_paid` grant Pro and the separate supporter crown, never identity. Why: identity and payment stay strictly separate.
