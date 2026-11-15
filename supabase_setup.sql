-- =====================================================================
--  Bluewind Skill Station — configuração do banco de dados (Supabase)
--  Cole TUDO no SQL Editor do Supabase e clique em "Run".
-- =====================================================================

-- 1) Tabelas
create table if not exists public.candidates (
  id text primary key,
  doc jsonb not null default '{}'::jsonb,
  token text,
  updated_at timestamptz not null default now()
);
create table if not exists public.codes (
  code text primary key,
  cand_id text,
  exp bigint,
  used boolean not null default false,
  created_at timestamptz not null default now()
);
create table if not exists public.staff (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('rh','dir'))
);

-- 2) Segurança: ninguém acessa as tabelas sem permissão
alter table public.candidates enable row level security;
alter table public.codes enable row level security;
alter table public.staff enable row level security;

create or replace function public.staff_role() returns text
language sql stable security definer set search_path = public as $$
  select role from public.staff where user_id = auth.uid()
$$;

drop policy if exists "staff le propria" on public.staff;
create policy "staff le propria" on public.staff for select to authenticated using (user_id = auth.uid());

drop policy if exists "staff le candidatos" on public.candidates;
drop policy if exists "rh cria candidatos" on public.candidates;
drop policy if exists "rh altera candidatos" on public.candidates;
drop policy if exists "rh apaga candidatos" on public.candidates;
create policy "staff le candidatos"  on public.candidates for select to authenticated using (public.staff_role() is not null);
create policy "rh cria candidatos"   on public.candidates for insert to authenticated with check (public.staff_role() = 'rh');
create policy "rh altera candidatos" on public.candidates for update to authenticated using (public.staff_role() = 'rh') with check (public.staff_role() = 'rh');
create policy "rh apaga candidatos"  on public.candidates for delete to authenticated using (public.staff_role() = 'rh');

drop policy if exists "staff le codigos" on public.codes;
drop policy if exists "rh cria codigos" on public.codes;
drop policy if exists "rh altera codigos" on public.codes;
drop policy if exists "rh apaga codigos" on public.codes;
create policy "staff le codigos"  on public.codes for select to authenticated using (public.staff_role() is not null);
create policy "rh cria codigos"   on public.codes for insert to authenticated with check (public.staff_role() = 'rh');
create policy "rh altera codigos" on public.codes for update to authenticated using (public.staff_role() = 'rh') with check (public.staff_role() = 'rh');
create policy "rh apaga codigos"  on public.codes for delete to authenticated using (public.staff_role() = 'rh');

-- 3) Funções do terminal do candidato (sem login)
-- 3a) Usar o código: vale UMA vez, depois "queima"
create or replace function public.redeem_code(p_code text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare c record; d jsonb; tok text;
begin
  select * into c from codes where code = p_code for update;
  if not found then return jsonb_build_object('error','invalid'); end if;
  if c.used then return jsonb_build_object('error','used'); end if;
  if c.exp is not null and c.exp < (extract(epoch from now()) * 1000)::bigint then
    return jsonb_build_object('error','expired');
  end if;
  update codes set used = true where code = p_code;
  tok := replace(gen_random_uuid()::text, '-', '');
  update candidates set token = tok, updated_at = now() where id = c.cand_id returning doc into d;
  if d is null then return jsonb_build_object('error','invalid'); end if;
  return jsonb_build_object('id', c.cand_id, 'name', d->>'name', 'role', d->>'role', 'token', tok);
end $$;

-- 3b) Código de teste 0000
create or replace function public.demo_start(p_role text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare nid text := 'd' || replace(gen_random_uuid()::text, '-', '');
        tok text := replace(gen_random_uuid()::text, '-', '');
begin
  if (select count(*) from candidates where doc->>'demo' = 'true' and updated_at > now() - interval '1 hour') > 50 then
    raise exception 'limite de testes atingido';
  end if;
  insert into candidates(id, doc, token) values (nid, jsonb_build_object(
    'name','Teste (código 0000)','role',p_role,'code','0000','status','aguardando',
    'createdAt',(extract(epoch from now()) * 1000)::bigint,'demo',true,'attempts','[]'::jsonb), tok);
  return jsonb_build_object('id', nid, 'name', 'Teste (código 0000)', 'token', tok);
end $$;

-- 3c) Salvar respostas do teste (só com o token daquele candidato, e só enquanto o teste está aberto)
create or replace function public.cand_patch(p_id text, p_token text, p_patch jsonb) returns void
language plpgsql security definer set search_path = public as $$
begin
  if octet_length(p_patch::text) > 400000 then raise exception 'dados grandes demais'; end if;
  update candidates set doc = doc || p_patch, updated_at = now()
   where id = p_id and token = p_token
     and coalesce(doc->>'status','aguardando') in ('aguardando','em_andamento');
end $$;

revoke all on function public.redeem_code(text) from public;
revoke all on function public.demo_start(text) from public;
revoke all on function public.cand_patch(text,text,jsonb) from public;
grant execute on function public.redeem_code(text) to anon, authenticated;
grant execute on function public.demo_start(text) to anon, authenticated;
grant execute on function public.cand_patch(text,text,jsonb) to anon, authenticated;

-- 4) Atualização ao vivo do painel
do $$ begin
  alter publication supabase_realtime add table public.candidates;
exception when duplicate_object then null; end $$;
