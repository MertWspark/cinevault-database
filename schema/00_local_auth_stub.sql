-- Yalnızca yerel deneme için.
-- Supabase'de auth şeması, auth.uid() fonksiyonu ve anon/authenticated
-- rolleri hazır gelir. Düz PostgreSQL'de çalıştırmak için bunları
-- burada taklit ediyoruz. Supabase'e uygularken bu dosya ATLANIR.

create schema if not exists auth;

create table if not exists auth.users (
  id         uuid primary key,
  email      text,
  created_at timestamptz not null default now()
);

-- Supabase'de oturum açan kullanıcının kimliği JWT'den okunur.
-- Burada aynı şeyi bir oturum ayarıyla yapıyoruz:
--   select set_config('request.jwt.claim.sub', '<uuid>', false);
create or replace function auth.uid()
returns uuid
language sql
stable
as $$
  select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid;
$$;

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then
    create role anon nologin;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then
    create role authenticated nologin;
  end if;
end
$$;

grant usage on schema public, auth to anon, authenticated;
grant execute on function auth.uid() to anon, authenticated;
