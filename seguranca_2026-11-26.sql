-- =====================================================================
-- Skill Station: reforço de segurança (26/11/2026)
-- 1) Limite de tentativas ao digitar o código (impede "chutar" códigos)
-- 2) Códigos do Onboard com 6 números (9xxxxx)
-- 3) Candidato só consegue salvar os campos do próprio teste, com tipos conferidos
--    (não consegue mudar nome, decisão do RH, notas do RH, códigos, nem injetar código no painel)
-- Nenhum dado é apagado.
-- =====================================================================
begin;

-- Registro de tentativas erradas (só o banco vê)
create table if not exists public.redeem_fails (
  id bigserial primary key,
  ip text not null,
  at timestamptz not null default now()
);
create index if not exists redeem_fails_at_idx on public.redeem_fails(at);
create index if not exists redeem_fails_ip_at_idx on public.redeem_fails(ip, at);
alter table public.redeem_fails enable row level security;
revoke all on public.redeem_fails from public, anon, authenticated;

-- Quem está chamando (IP informado pelo proxy do Supabase)
create or replace function public.req_ip()
 returns text language sql stable set search_path to 'public'
as $f$
  select coalesce(
    nullif(current_setting('request.headers', true)::json->>'cf-connecting-ip',''),
    nullif(current_setting('request.headers', true)::json->>'x-real-ip',''),
    nullif(trim(split_part(current_setting('request.headers', true)::json->>'x-forwarded-for', ',', 1)),''),
    'desconhecido')
$f$;
revoke all on function public.req_ip() from public, anon, authenticated;

-- 1) Resgatar código com limite: 8 erros por aparelho/IP em 15 min, 150 erros no total em 15 min
create or replace function public.redeem_code(p_code text)
 returns jsonb language plpgsql security definer set search_path to 'public'
as $function$
declare c record; d jsonb; tok text; v_ip text := public.req_ip();
begin
  delete from redeem_fails where at < now() - interval '1 day';
  if (select count(*) from redeem_fails where ip = v_ip and at > now() - interval '15 minutes') >= 8
     or (select count(*) from redeem_fails where at > now() - interval '15 minutes') >= 150 then
    return jsonb_build_object('error','locked');
  end if;
  if coalesce(p_code,'') !~ '^[0-9]{4,6}$' then
    insert into redeem_fails(ip) values (v_ip);
    return jsonb_build_object('error','invalid');
  end if;
  select * into c from codes where code = p_code for update;
  if not found then insert into redeem_fails(ip) values (v_ip); return jsonb_build_object('error','invalid'); end if;
  if c.used then insert into redeem_fails(ip) values (v_ip); return jsonb_build_object('error','used'); end if;
  if c.exp is not null and c.exp < (extract(epoch from now()) * 1000)::bigint then
    insert into redeem_fails(ip) values (v_ip);
    return jsonb_build_object('error','expired');
  end if;
  update codes set used = true where code = p_code;
  tok := replace(gen_random_uuid()::text, '-', '');
  update candidates set token = tok, updated_at = now() where id = c.cand_id returning doc into d;
  if d is null then return jsonb_build_object('error','invalid'); end if;
  return jsonb_build_object('id', c.cand_id, 'name', d->>'name', 'role', d->>'role', 'token', tok);
end $function$;

-- Imagem de assinatura/foto só pode ser uma imagem de verdade
create or replace function public.ss_is_img(v jsonb)
 returns boolean language sql immutable set search_path to 'public'
as $f$
  select v is null or jsonb_typeof(v) = 'null'
      or (jsonb_typeof(v) = 'string' and (v #>> '{}') ~ '^data:image/(png|jpeg|jpg|webp);base64,[A-Za-z0-9+/=]+$')
$f$;

-- 2) Código do Onboard: 6 números (900000 a 999999)
create or replace function public.safety_onb_code(p_id text)
 returns text language plpgsql security definer set search_path to 'public'
as $function$
declare cd text; tries int := 0; ms bigint := (extract(epoch from now()) * 1000)::bigint;
begin
  if coalesce(public.staff_role(),'') not in ('seg','rh') then raise exception 'sem permissao'; end if;
  if not exists (select 1 from candidates where id = p_id and doc->>'status' = 'aprovado') then raise exception 'candidato nao aprovado'; end if;
  loop
    cd := '9' || lpad(floor(random() * 100000)::int::text, 5, '0');
    exit when not exists (select 1 from codes where code = cd);
    tries := tries + 1; if tries > 50 then raise exception 'sem codigo livre'; end if;
  end loop;
  insert into codes(code, cand_id, exp, used) values (cd, p_id, ms + 7*24*3600000, false);
  update candidates set doc = doc || jsonb_build_object('onboardCode', cd, 'onboardCodeAt', ms), updated_at = now() where id = p_id;
  return cd;
end $function$;

-- 3a) Candidato salvando o teste
create or replace function public.cand_patch(p_id text, p_token text, p_patch jsonb)
 returns void language plpgsql security definer set search_path to 'public'
as $function$
declare k text; v jsonb;
begin
  if p_patch is null or jsonb_typeof(p_patch) <> 'object' then raise exception 'dados invalidos'; end if;
  if octet_length(p_patch::text) > 400000 then raise exception 'dados grandes demais'; end if;
  for k, v in select * from jsonb_each(p_patch) loop
    -- campos que só o RH / Diretoria / Safety podem mexer
    if k in ('id','token','name','code','codeExp','createdAt','demo','decidedAt','interview','practical',
             'aiNote','aiLang','attempts','notes') or k like 'onboard%' then
      raise exception 'campo nao permitido';
    end if;
    if k = 'status' and (v #>> '{}') not in ('em_andamento','concluido','abandonado','recusou','psico_reprovado') then
      raise exception 'status nao permitido';
    end if;
    if k in ('score','psyScore','sstScore','avg','exits','total','lastQ','startedAt','finishedAt','abandonedAt',
             'psyAt','sstAt','refusedAt','psyVer')
       and jsonb_typeof(v) not in ('number','null') then
      raise exception 'tipo invalido';
    end if;
    if k in ('crit','psyPass','roleChanged') and jsonb_typeof(v) not in ('boolean','null') then
      raise exception 'tipo invalido';
    end if;
    if k = 'photo' and not public.ss_is_img(v) then raise exception 'imagem invalida'; end if;
    if k = 'consent' and jsonb_typeof(v) = 'object' and not public.ss_is_img(v->'sig') then raise exception 'assinatura invalida'; end if;
    if k in ('lang','role','roleRH','phone') and jsonb_typeof(v) = 'string' and (v #>> '{}') ~ '[<>"]' then
      raise exception 'texto invalido';
    end if;
  end loop;
  update candidates set doc = doc || p_patch, updated_at = now()
   where id = p_id and token = p_token
     and coalesce(doc->>'status','aguardando') in ('aguardando','em_andamento');
end $function$;

-- 3b) Contratado salvando o Onboard
create or replace function public.onboard_patch(p_id text, p_token text, p_patch jsonb)
 returns void language plpgsql security definer set search_path to 'public'
as $function$
declare k text; v jsonb;
begin
  if p_patch is null or jsonb_typeof(p_patch) <> 'object' then raise exception 'dados invalidos'; end if;
  if octet_length(p_patch::text) > 200000 then raise exception 'dados grandes demais'; end if;
  for k, v in select * from jsonb_each(p_patch) loop
    if k not in ('onboardAck','onboardAt','onboardDone','onboardErr','onboardLang','onboardScore','onboardSig',
                 'onboardTotal','onboardTries','onboardVer','onboardWrong') then
      raise exception 'campo nao permitido';
    end if;
    if k = 'onboardSig' and not public.ss_is_img(v) then raise exception 'assinatura invalida'; end if;
    if k in ('onboardScore','onboardTotal','onboardTries','onboardWrong','onboardAt') and jsonb_typeof(v) not in ('number','null') then
      raise exception 'tipo invalido';
    end if;
    if k = 'onboardErr' and jsonb_typeof(v) = 'object'
       and exists (select 1 from jsonb_each(v) e where jsonb_typeof(e.value) <> 'number') then
      raise exception 'tipo invalido';
    end if;
    if k in ('onboardLang','onboardVer') and (jsonb_typeof(v) <> 'string' or (v #>> '{}') !~ '^[A-Za-z0-9_-]{1,12}$') then
      raise exception 'texto invalido';
    end if;
  end loop;
  update candidates set doc = doc || p_patch, updated_at = now()
   where id = p_id and token = p_token and doc->>'status' = 'aprovado';
end $function$;

-- Permissões: só as funções que o app precisa
revoke all on function public.ss_is_img(jsonb) from public, anon, authenticated;
grant execute on function public.redeem_code(text) to anon, authenticated;
grant execute on function public.cand_patch(text,text,jsonb) to anon, authenticated;
grant execute on function public.onboard_patch(text,text,jsonb) to anon, authenticated;
grant execute on function public.safety_onb_code(text) to authenticated;
revoke execute on function public.safety_onb_code(text) from anon;

commit;
