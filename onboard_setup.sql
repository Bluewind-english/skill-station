-- Bluewind Skill Station — Onboard (rode UMA vez no SQL Editor do Supabase)

-- 5) Onboard (integração de segurança do contratado): o funcionário só consegue gravar
--    os campos "onboard..." do próprio cadastro, e só se o RH tiver marcado como aprovado
create or replace function public.onboard_patch(p_id text, p_token text, p_patch jsonb) returns void
language plpgsql security definer set search_path = public as $$
declare k text;
begin
  if octet_length(p_patch::text) > 20000 then raise exception 'dados grandes demais'; end if;
  for k in select jsonb_object_keys(p_patch) loop
    if k not like 'onboard%' then raise exception 'campo nao permitido'; end if;
  end loop;
  update candidates set doc = doc || p_patch, updated_at = now()
   where id = p_id and token = p_token and doc->>'status' = 'aprovado';
end $$;
revoke all on function public.onboard_patch(text,text,jsonb) from public;
grant execute on function public.onboard_patch(text,text,jsonb) to anon, authenticated;
