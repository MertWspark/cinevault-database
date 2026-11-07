-- Hesap silme.
--
-- Google Play, hesap açılabilen uygulamalarda uygulama içinden hesap
-- silme yolu istiyor; KVKK/GDPR'daki "unutulma hakkı" da bunu gerektiriyor.
--
-- Tablo tablo silmek yerine sadece auth.users satırını siliyorum. Tüm
-- veri tabloları "on delete cascade" ile ona bağlı, gerisini veritabanı
-- hallediyor. Böylece ileride eklenen bir tabloyu burada unutup silinmiş
-- kullanıcının verisini sessizce bırakma riski yok.
--
-- Bu adımı eklerken bir hata ortaya çıktı: admin_audit_log.actor_id hem
-- NOT NULL hem de "on delete set null" idi. Bu ikisi birlikte imkânsız;
-- denetim kaydında satırı olan hiçbir kullanıcı silinemiyordu. Çözüm
-- olarak kolon null olabilir yapıldı (01_profiles_and_roles.sql).

create or replace function public.delete_own_account()
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user uuid := auth.uid();
begin
  if v_user is null then
    raise exception 'auth_required';
  end if;

  -- Master hesabı uygulama içinden silinemez; yoksa sistemi yönetecek
  -- kimse kalmayabilir.
  if exists (select 1 from public.profiles where id = v_user and role = 'master') then
    raise exception 'master_cannot_delete_self';
  end if;

  -- Silme işlemi kimliksiz olarak kaydediliyor: olay biliniyor ama
  -- silinen kişiye geri gidilemiyor.
  insert into public.admin_audit_log (actor_id, action, detail)
  values (null, 'account_self_delete', jsonb_build_object('at', now()));

  -- Parametre olarak kimlik alınmıyor; yalnızca çağıranın kendi hesabı
  -- silinebilir.
  delete from auth.users where id = v_user;
end;
$$;

revoke all on function public.delete_own_account() from public, anon;
grant execute on function public.delete_own_account() to authenticated;
