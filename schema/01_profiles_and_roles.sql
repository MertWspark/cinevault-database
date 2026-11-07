-- Profiller, roller ve yetki kontrolleri.
--
-- Uygulama mobil ve web'den erişiliyor. Bu yüzden yetki kararlarını
-- istemciye değil veritabanına bıraktım: her sorgu RLS'den geçiyor,
-- yeni bir istemci eklense bile kurallar otomatik geçerli.

create or replace function public.touch_updated_at()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

-- Üç rol: normal kullanıcı, operatör (admin) ve tek süper yönetici (master).
do $$
begin
  if not exists (select 1 from pg_type where typname = 'user_role') then
    create type public.user_role as enum ('user', 'admin', 'master');
  end if;
end
$$;

create table if not exists public.profiles (
  id            uuid primary key references auth.users(id) on delete cascade,
  display_name  text,
  avatar_url    text,
  role          public.user_role not null default 'user',

  -- null = ücretsiz, 'infinity' = süresiz, tarih = o tarihe kadar premium.
  -- Ayrı bir is_premium bayrağı tutmuyorum; iki alan zamanla birbirini
  -- tutmaz hale gelir ("premium ama süresi dolmuş" gibi).
  premium_until timestamptz,

  ai_credits          integer not null default 5,
  ai_credits_reset_at date    not null default current_date,

  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

-- Sistemde en fazla bir master olabilir.
-- Bunu uygulamada kontrol etmek yetmez: aynı anda gelen iki istek
-- "master yok" görüp ikisi de atama yapabilir. Kısmi benzersiz indeks
-- bunu veritabanı seviyesinde imkânsız kılıyor.
create unique index if not exists uniq_single_master
  on public.profiles ((role = 'master'))
  where role = 'master';

-- Yetki yardımcıları.
-- security definer: RLS politikaları profiles tablosunu okuyacak; aksi
-- halde politika kendi tablosunu okumaya çalışıp döngüye girerdi.
create or replace function public.cinevault_role()
returns public.user_role
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(
    (select role from public.profiles where id = auth.uid()),
    'user'::public.user_role
  );
$$;

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select public.cinevault_role() in ('admin', 'master');
$$;

create or replace function public.is_master()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select public.cinevault_role() = 'master';
$$;

alter table public.profiles enable row level security;

drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles
  for select to authenticated
  using (id = auth.uid() or public.is_admin());

drop policy if exists profiles_insert_self on public.profiles;
create policy profiles_insert_self on public.profiles
  for insert to authenticated
  with check (id = auth.uid());

drop policy if exists profiles_update_self on public.profiles;
create policy profiles_update_self on public.profiles
  for update to authenticated
  using (id = auth.uid())
  with check (id = auth.uid());

drop policy if exists profiles_update_admin on public.profiles;
create policy profiles_update_admin on public.profiles
  for update to authenticated
  using (public.is_admin())
  with check (public.is_admin());

-- PostgreSQL RLS'te kolon bazlı kısıt yok. Kullanıcı kendi satırını
-- güncelleyebiliyor ama rolünü veya premium süresini değiştirememeli.
-- Bunu bir trigger ile koruyorum.
create or replace function public.guard_profile_privileges()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.role is distinct from old.role then
    if not public.is_master() then
      raise exception 'role_change_requires_master';
    end if;
    -- Master kendi rolünü düşürürse sistemi yönetecek kimse kalmaz.
    if old.id = auth.uid() and old.role = 'master' then
      raise exception 'master_cannot_demote_self';
    end if;
  end if;

  if (new.premium_until is distinct from old.premium_until
      or new.ai_credits is distinct from old.ai_credits)
     and not public.is_admin() then
    raise exception 'admin_only_field';
  end if;

  new.updated_at := now();
  return new;
end;
$$;

drop trigger if exists trg_profiles_guard on public.profiles;
create trigger trg_profiles_guard
  before update on public.profiles
  for each row execute function public.guard_profile_privileges();

-- Yeni kullanıcı kaydolunca profil satırı otomatik açılsın.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id) values (new.id)
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists trg_auth_user_created on auth.users;
create trigger trg_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Yönetici işlemlerinin denetim kaydı.
-- actor_id null olabilir: hesabı silinen bir yöneticinin kaydı da
-- korunmalı (bkz. 04_account_deletion.sql).
create table if not exists public.admin_audit_log (
  id          bigserial primary key,
  actor_id    uuid references auth.users(id) on delete set null,
  target_id   uuid references auth.users(id) on delete set null,
  action      text  not null,
  detail      jsonb not null default '{}'::jsonb,
  created_at  timestamptz not null default now()
);

alter table public.admin_audit_log enable row level security;

-- Sadece yöneticiler okuyabilir. Yazma sunucu tarafında yapılır;
-- istemci kendi denetim kaydını yazabilseydi kaydın anlamı kalmazdı.
drop policy if exists audit_select_admin on public.admin_audit_log;
create policy audit_select_admin on public.admin_audit_log
  for select to authenticated
  using (public.is_admin());

create index if not exists idx_audit_created
  on public.admin_audit_log (created_at desc);

-- Tetikleyici fonksiyonları API üzerinden çağrılabilir olmasın.
revoke execute on function public.handle_new_user() from public;
revoke execute on function public.guard_profile_privileges() from public;
revoke execute on function public.touch_updated_at() from public;
revoke execute on function public.cinevault_role() from public;
revoke execute on function public.is_admin() from public;
revoke execute on function public.is_master() from public;

-- Bu üçü politikaların içinde kullanılıyor, o yüzden geri veriliyor.
-- Hepsi yalnızca çağıranın kendi rolünü döndürdüğü için sızma riski yok.
grant execute on function public.cinevault_role() to authenticated;
grant execute on function public.is_admin() to authenticated;
grant execute on function public.is_master() to authenticated;

grant select, insert, update on public.profiles to authenticated;
grant select on public.admin_audit_log to authenticated;
