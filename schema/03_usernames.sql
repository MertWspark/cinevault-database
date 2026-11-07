-- Kullanıcı adları.
--
-- İki kolon var:
--   username      kullanıcının yazdığı hali (görünen ad, Türkçe harfler dahil)
--   username_key  karşılaştırma için normalize edilmiş hali; benzersizlik bunda
-- Tek kolon olsaydı "Mert", "MERT" ve "mert1" ayrı hesaplar olurdu ve
-- birinin adını taklit etmek kolaylaşırdı.

alter table public.profiles
  add column if not exists username            text,
  add column if not exists username_key        text,
  add column if not exists username_changed_at timestamptz;

-- Kısmi indeks: henüz adı olmayan (null) birden fazla kullanıcı olabilir.
create unique index if not exists idx_profiles_username_key
  on public.profiles (username_key)
  where username_key is not null;

-- Normalizasyon.
-- 1) Türkçe ve aksanlı harfler sadeleştirilir (lower()'dan ÖNCE yapılıyor;
--    bazı ayarlarda lower('İ') iki karakter üretiyor).
-- 2) Birbirine benzeyen karakterler aynı anahtara düşer: 0 -> o, 1 -> l.
-- 3) Harf, rakam ve alt çizgi dışındaki her şey silinir.
-- Not: translate'in iki argümanı aynı uzunlukta olmalı; değilse PostgreSQL
-- hata vermeden fazlalığı siliyor.
create or replace function public.normalize_username(p_raw text)
returns text
language sql
immutable
set search_path = ''
as $$
  select regexp_replace(
    translate(
      lower(
        translate(
          coalesce(p_raw, ''),
          'ıİşŞğĞüÜöÖçÇâîûéèáíóúñ',
          'iissgguuooccaiueeaioun'
        )
      ),
      '01',
      'ol'
    ),
    '[^a-z0-9_]', '', 'g'
  );
$$;

-- Yasaklı adlar kodda değil tabloda: yeni kelime eklemek için uygulama
-- güncellemesi gerekmesin.
create table if not exists public.blocked_usernames (
  fragment   text primary key,
  -- exact: sadece tam eşleşme yasak (taklit önleme)
  -- contains: adın içinde geçmesi yasak (küfür vb.)
  match_mode text not null default 'contains'
    check (match_mode in ('exact', 'contains'))
);

alter table public.blocked_usernames enable row level security;

drop policy if exists blocked_usernames_read on public.blocked_usernames;
create policy blocked_usernames_read on public.blocked_usernames
  for select using (true);

-- Örnek liste. Üretimdeki listede küfür ve hakaret içeren kelimeler de var;
-- burada kısaltıldı.
insert into public.blocked_usernames (fragment, match_mode) values
  ('admin', 'exact'), ('root', 'exact'), ('support', 'exact'),
  ('destek', 'exact'), ('moderator', 'exact'), ('official', 'exact'),
  ('cinevault', 'exact'), ('guest', 'exact'), ('null', 'exact'),
  ('xxx', 'contains')
on conflict (fragment) do nothing;


-- ─── Güvenlik açığı ve çözümü ─────────────────────────────────────────
-- İlk sürümde kullanıcı adı yalnızca claim_username() ile alınıyordu.
-- Ancak profiles_update_self politikası kullanıcının kendi satırındaki
-- HER kolonu yazmasına izin veriyordu. Yani şu sorgu RPC'yi hiç
-- çağırmadan çalışıyordu:
--   update profiles set username = 'admin', username_key = 'zzz' ...
-- Sonuç: yasaklı kelime, normalizasyon ve bekleme süresi kuralları
-- atlanıyor, "admin" görünen adıyla taklit mümkün oluyordu.
--
-- Çözüm: kullanıcı adı kolonları sadece şu durumlarda değişebilir:
--   - claim_username / assign_default_username içinden (işlem içi bayrak),
--   - sunucu bağlamında (auth.uid() boş),
--   - bir yönetici tarafından (uygunsuz adı temizleyebilsin diye).

create or replace function public.guard_profile_username()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if (new.username is distinct from old.username
      or new.username_key is distinct from old.username_key
      or new.username_changed_at is distinct from old.username_changed_at)
     and auth.uid() is not null
     and coalesce(current_setting('cinevault.username_rpc', true), '') <> 'on'
     and not public.is_admin() then
    raise exception 'username_rpc_required';
  end if;
  return new;
end;
$$;

drop trigger if exists trg_profiles_username_guard on public.profiles;
create trigger trg_profiles_username_guard
  before update on public.profiles
  for each row execute function public.guard_profile_username();

revoke all on function public.guard_profile_username() from public, anon, authenticated;


-- Ortak doğrulama: uzunluk ve yasaklı kelime kontrolü.
create or replace function public.validate_username(p_username text)
returns text
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_key text := public.normalize_username(p_username);
begin
  if length(v_key) < 3 then
    raise exception 'too_short';
  end if;
  if length(btrim(p_username)) > 20 then
    raise exception 'too_long';
  end if;
  if exists (
    select 1 from public.blocked_usernames
     where (match_mode = 'exact'    and v_key = fragment)
        or (match_mode = 'contains' and position(fragment in v_key) > 0)
  ) then
    raise exception 'blocked_word';
  end if;
  return v_key;
end;
$$;

revoke all on function public.validate_username(text) from public, anon, authenticated;


-- Kullanıcı adı alma / değiştirme.
-- Tüm kurallar sunucuda: istemciye bırakılsaydı doğrudan update ile
-- atlatılabilirdi.
create or replace function public.claim_username(p_username text)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid  uuid := auth.uid();
  v_key  text;
  v_prev timestamptz;
begin
  if v_uid is null then
    raise exception 'auth_required';
  end if;

  v_key := public.validate_username(p_username);

  -- İlk seçimde bekleme yok, sonrasında 90 gün.
  select username_changed_at into v_prev
    from public.profiles where id = v_uid;
  if v_prev is not null and v_prev > now() - interval '90 days' then
    raise exception 'too_soon';
  end if;

  perform set_config('cinevault.username_rpc', 'on', true);

  -- Aynı adın sadece büyük/küçük harfini düzeltmek değişiklik sayılmaz.
  if exists (select 1 from public.profiles where id = v_uid and username_key = v_key) then
    update public.profiles set username = btrim(p_username) where id = v_uid;
    return btrim(p_username);
  end if;

  begin
    update public.profiles
       set username = btrim(p_username),
           username_key = v_key,
           username_changed_at = now()
     where id = v_uid;
  exception when unique_violation then
    raise exception 'taken';
  end;

  return btrim(p_username);
end;
$$;

revoke all on function public.claim_username(text) from public, anon;
grant execute on function public.claim_username(text) to authenticated;


-- Adı olmayan kullanıcıya otomatik ad atama (ör. "mert_4f2a").
-- Zaten adı varsa dokunmaz. Bekleme süresini başlatmaz; kullanıcı
-- otomatik atanan adı hemen değiştirebilir.
create or replace function public.assign_default_username(p_username text)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid      uuid := auth.uid();
  v_key      text;
  v_existing text;
begin
  if v_uid is null then
    raise exception 'auth_required';
  end if;

  select username into v_existing
    from public.profiles where id = v_uid and username_key is not null;
  if v_existing is not null then
    return v_existing;
  end if;

  v_key := public.validate_username(p_username);

  perform set_config('cinevault.username_rpc', 'on', true);
  begin
    update public.profiles
       set username = btrim(p_username), username_key = v_key
     where id = v_uid;
  exception when unique_violation then
    raise exception 'taken';
  end;

  return btrim(p_username);
end;
$$;

revoke all on function public.assign_default_username(text) from public, anon;
grant execute on function public.assign_default_username(text) to authenticated;


-- Müsaitlik sorgusu: sadece true/false döner, adın kime ait olduğunu
-- sızdırmaz.
create or replace function public.username_available(p_username text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select not exists (
    select 1 from public.profiles
     where username_key = public.normalize_username(p_username)
       and id <> coalesce(auth.uid(), '00000000-0000-0000-0000-000000000000'::uuid)
  );
$$;

revoke all on function public.username_available(text) from public;
grant execute on function public.username_available(text) to authenticated, anon;
grant select on public.blocked_usernames to anon, authenticated;
