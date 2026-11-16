-- Rollback of 0285_workspace_group_encryption.sql. Idempotent. Refuses once any workspace key
-- epoch, member envelope, question, private answer or published FAQ item exists: dropping them
-- would destroy ciphertext only the workspace's own members can open, and a public FAQ item
-- that visitors have already read.
do $rollback$
begin
  if (to_regclass('public.workspace_keys') is not null and exists (select 1 from public.workspace_keys))
     or (to_regclass('public.workspace_member_keys') is not null and exists (select 1 from public.workspace_member_keys))
     or (to_regclass('public.workspace_questions') is not null and exists (select 1 from public.workspace_questions))
     or (to_regclass('public.workspace_question_replies') is not null and exists (select 1 from public.workspace_question_replies))
     or (to_regclass('public.workspace_faq_items') is not null and exists (select 1 from public.workspace_faq_items)) then
    raise exception '0285 rollback refused: workspace key, question or FAQ rows exist' using errcode = 'P0001';
  end if;
end $rollback$;

drop function if exists public.rout_ws_answer_fetch(bytea);
drop function if exists public.rout_public_ws_faq(text);
drop function if exists public.rout_ws_question_decline(uuid);
drop function if exists public.rout_ws_question_publish(uuid, text, text);
drop function if exists public.rout_ws_question_reply(uuid, text, bytea);
drop function if exists public.rout_ws_question_list(uuid);
drop function if exists public.rout_ws_question_create(text, uuid, integer, text, bytea, text, integer, text, bytea);
drop function if exists public.rout_public_ws_ask_key(text);
drop function if exists public.rout_ws_ask_save(uuid, boolean);
drop function if exists public.rout_ws_group_state(uuid);
drop function if exists public.rout_ws_group_member_key(uuid, integer);
drop function if exists public.rout_ws_group_member_store(uuid, integer, uuid, uuid, text, text);
drop function if exists public.rout_ws_group_publish(uuid, integer, text, text);
drop function if exists public.rout_ws_group_active(uuid);
drop function if exists public.rout_ws_group_epoch_ok(integer);
drop function if exists public.rout_ws_group_envelope_ok(text, text);
drop function if exists public.rout_ws_group_manager(uuid);

drop table if exists public.workspace_faq_items;
drop table if exists public.workspace_question_replies;
drop table if exists public.workspace_questions;
drop table if exists public.workspace_ask_settings;
drop table if exists public.workspace_member_keys;
drop table if exists public.workspace_keys;
