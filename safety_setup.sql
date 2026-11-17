-- =====================================================================
-- ACESSO SAFETY (segurança do trabalho) — Bluewind Skill Station
-- Rode uma vez no SQL Editor do banco de dados.
-- O Safety vê só: nome e dados do Onboard (situação, nota e erros por módulo).
-- Notas da seleção e psicotécnico continuam só para RH e Diretoria.
-- =====================================================================

-- 1) Permite o papel 'seg' (Safety)
alter table public.staff drop constraint if exists staff_role_check;
alter table public.staff add constraint staff_role_check check (role in ('rh','dir','seg'));

-- 2) Leitura direta das tabelas: só RH e Diretoria
drop policy if exists "staff le candidatos" on public.candidates;
create policy "staff le candidatos" on public.candidates for select to authenticated using (public.staff_role() in ('rh','dir'));
drop policy if exists "staff le codigos" on public.codes;
create policy "staff le codigos" on public.codes for select to authenticated using (public.staff_role() in ('rh','dir'));

-- 3) Lista do Safety: SÓ nome + dados do Onboard (nada da seleção do RH)
create or replace function public.safety_list() returns table(id text, doc jsonb)
language plpgsql stable security definer set search_path = public as $$
begin
  if public.staff_role() is null then raise exception 'sem permissao'; end if;
  return query
  select c.id,
         jsonb_build_object('name', c.doc->'name')
         || coalesce((select jsonb_object_agg(k, v) from jsonb_each(c.doc) e(k, v) where k like 'onboard%'), '{}'::jsonb)
  from public.candidates c
  where coalesce(c.doc->>'demo','false') <> 'true'
    and (c.doc->>'status' = 'aprovado' or c.doc ? 'onboardCode' or c.doc ? 'onboardDone');
end $$;
revoke all on function public.safety_list() from public;
grant execute on function public.safety_list() to authenticated;

-- 4) Safety gera o código do Onboard (começa com 9, vale 7 dias) só para aprovados
create or replace function public.safety_onb_code(p_id text) returns text
language plpgsql security definer set search_path = public as $$
declare cd text; tries int := 0; ms bigint := (extract(epoch from now()) * 1000)::bigint;
begin
  if public.staff_role() not in ('seg','rh') then raise exception 'sem permissao'; end if;
  if not exists (select 1 from candidates where id = p_id and doc->>'status' = 'aprovado') then raise exception 'candidato nao aprovado'; end if;
  loop
    cd := '9' || lpad((100 + floor(random() * 900))::int::text, 3, '0');
    exit when not exists (select 1 from codes where code = cd);
    tries := tries + 1; if tries > 50 then raise exception 'sem codigo livre'; end if;
  end loop;
  insert into codes(code, cand_id, exp, used) values (cd, p_id, ms + 7*24*3600000, false);
  update candidates set doc = doc || jsonb_build_object('onboardCode', cd, 'onboardCodeAt', ms), updated_at = now() where id = p_id;
  return cd;
end $$;
revoke all on function public.safety_onb_code(text) from public;
grant execute on function public.safety_onb_code(text) to authenticated;
