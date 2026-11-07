-- Güvenlik testleri.
--
-- Her test, kuralın gerçekten veritabanında uygulandığını kontrol ediyor:
-- normal bir kullanıcı (authenticated rolü) olarak yasak bir işlem
-- denendiğinde beklenen hata gelmeli, izinli işlem başarılı olmalı.
-- Bir test başarısız olursa betik hata verip durur.

create schema if not exists test;

-- Verilen SQL'in belirli bir hata mesajıyla düşmesini bekler.
create or replace function test.expect_error(p_sql text, p_message text)
returns void
language plpgsql
as $$
begin
  execute p_sql;
  raise exception 'BEKLENEN HATA GELMEDİ (%): %', p_message, p_sql;
exception
  when others then
    if sqlerrm not like '%' || p_message || '%' then
      raise exception 'YANLIŞ HATA: beklenen "%", gelen "%"', p_message, sqlerrm;
    end if;
end;
$$;

create or replace function test.expect_equal(p_actual bigint, p_expected bigint, p_label text)
returns void
language plpgsql
as $$
begin
  if p_actual is distinct from p_expected then
    raise exception 'BAŞARISIZ: % (beklenen %, gelen %)', p_label, p_expected, p_actual;
  end if;
end;
$$;

grant usage on schema test to authenticated;
grant execute on all functions in schema test to authenticated;


-- ─── Hazırlık (sunucu tarafı) ─────────────────────────────────────────
-- Üç kullanıcı oluşturuluyor; profilleri trigger ile otomatik açılıyor.
insert into auth.users (id, email) values
  ('00000000-0000-0000-0000-00000000000a', 'ayse@example.com'),
  ('00000000-0000-0000-0000-00000000000b', 'burak@example.com'),
  ('00000000-0000-0000-0000-00000000000c', 'master@example.com');

select test.expect_equal((select count(*) from public.profiles), 3,
  'kayıt olan her kullanıcıya profil açılmalı');

-- İlk master ataması sunucuda yapılır. Normalde rol değişikliğini sadece
-- master yapabildiği için ilk atamada koruma trigger'ları geçici olarak
-- devre dışı bırakılıyor.
set session_replication_role = replica;
update public.profiles set role = 'master'
 where id = '00000000-0000-0000-0000-00000000000c';

-- Trigger'lar kapalıyken bile ikinci bir master olamaz: bu kuralı
-- trigger değil benzersiz indeks koruyor.
select test.expect_error(
  $$update public.profiles set role = 'master'
     where id = '00000000-0000-0000-0000-00000000000a'$$,
  'uniq_single_master');
set session_replication_role = origin;


-- ─── Ayşe olarak (normal kullanıcı) ───────────────────────────────────
set role authenticated;
select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000a', false);

-- RLS: sadece kendi profilini görür.
select test.expect_equal((select count(*) from public.profiles), 1,
  'kullanıcı sadece kendi profilini görmeli');

-- Kendini admin yapamaz.
select test.expect_error(
  $$update public.profiles set role = 'admin' where id = auth.uid()$$,
  'role_change_requires_master');

-- Kendine premium veremez.
select test.expect_error(
  $$update public.profiles set premium_until = 'infinity' where id = auth.uid()$$,
  'admin_only_field');

-- Görünen adını güncelleyebilir (izinli alan).
update public.profiles set display_name = 'Ayşe' where id = auth.uid();

-- Kullanıcı adını RPC'yi atlayarak doğrudan yazamaz (kapatılan açık).
select test.expect_error(
  $$update public.profiles set username = 'admin', username_key = 'zzz'
     where id = auth.uid()$$,
  'username_rpc_required');

-- Yasaklı ad alamaz; normalizasyon büyük harfi de yakalar.
select test.expect_error($$select public.claim_username('ADMIN')$$, 'blocked_word');
select test.expect_error($$select public.claim_username('ab')$$, 'too_short');

-- Geçerli bir ad alabilir.
select public.claim_username('Mertl');

-- Hemen tekrar değiştiremez (90 gün kuralı).
select test.expect_error($$select public.claim_username('yeniad')$$, 'too_soon');

-- Kütüphanesine içerik ekler.
insert into public.library_items (user_id, tmdb_id, media_type, is_favorite)
values (auth.uid(), 550, 'movie', true);

-- Başkası adına kayıt ekleyemez.
select test.expect_error(
  $$insert into public.library_items (user_id, tmdb_id, media_type)
    values ('00000000-0000-0000-0000-00000000000b', 13, 'movie')$$,
  'row-level security');


-- ─── Burak olarak ─────────────────────────────────────────────────────
select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000b', false);

-- Ayşe'nin kütüphanesini göremez.
select test.expect_equal((select count(*) from public.library_items), 0,
  'başka kullanıcının kütüphanesi görünmemeli');

-- "MERT1" normalize edilince "mertl" olur; Ayşe'nin adıyla çakışır.
select test.expect_error($$select public.claim_username('MERT1')$$, 'taken');
select test.expect_equal(
  (select case when public.username_available('mert1') then 1 else 0 end), 0,
  'benzer görünen ad müsait görünmemeli');

-- Denetim kaydını okuyamaz.
select test.expect_equal((select count(*) from public.admin_audit_log), 0,
  'normal kullanıcı denetim kaydını görmemeli');


-- ─── Master olarak ────────────────────────────────────────────────────
select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000c', false);

-- Tüm profilleri görebilir ve rol atayabilir.
select test.expect_equal((select count(*) from public.profiles), 3,
  'master tüm profilleri görmeli');
update public.profiles set role = 'admin'
 where id = '00000000-0000-0000-0000-00000000000b';

-- Kendi rolünü düşüremez.
select test.expect_error(
  $$update public.profiles set role = 'user' where id = auth.uid()$$,
  'master_cannot_demote_self');

-- Hesabını uygulama içinden silemez.
select test.expect_error($$select public.delete_own_account()$$, 'master_cannot_delete_self');


-- ─── Hesap silme (Ayşe) ───────────────────────────────────────────────
select set_config('request.jwt.claim.sub', '00000000-0000-0000-0000-00000000000a', false);
select public.delete_own_account();

reset role;
select test.expect_equal(
  (select count(*) from public.profiles where id = '00000000-0000-0000-0000-00000000000a'), 0,
  'silinen kullanıcının profili kalmamalı');
select test.expect_equal(
  (select count(*) from public.library_items where user_id = '00000000-0000-0000-0000-00000000000a'), 0,
  'silinen kullanıcının kütüphanesi kalmamalı (cascade)');
select test.expect_equal(
  (select count(*) from public.admin_audit_log
    where action = 'account_self_delete' and actor_id is null), 1,
  'silme işlemi kimliksiz olarak kaydedilmeli');

select 'TÜM TESTLER GEÇTİ' as sonuc;
