-- =====================================================================
-- APRESENTAÇÃO DO SAFETY PROTEGIDA — Bluewind Skill Station (18/11/2026)
-- O conteúdo (slides + fotos) fica SÓ nesta tabela. Leitura apenas para
-- usuários logados com papel RH, Diretoria ou Safety. Ninguém grava pela API.
-- =====================================================================
create table if not exists public.safety_show (
  id int primary key,
  html text not null default '',
  updated_at timestamptz not null default now()
);
alter table public.safety_show enable row level security;
revoke all on public.safety_show from anon, authenticated, public;
grant select on public.safety_show to authenticated;
drop policy if exists "staff le apresentacao" on public.safety_show;
create policy "staff le apresentacao" on public.safety_show
  for select to authenticated using (public.staff_role() in ('seg','rh','dir'));
