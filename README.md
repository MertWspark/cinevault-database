# CineVault — Veritabanı Tasarımı

CineVault, film ve dizi keşfetme, liste oluşturma ve paylaşma uygulamam (Flutter, mobil ve web). Bu depo uygulamanın **Supabase (PostgreSQL)** veritabanından seçilmiş ve sadeleştirilmiş bölümleri içeriyor.

Üretimdeki şema 48 migration dosyasından oluşuyor. Burada güvenlik ve veri modeli açısından en öğretici kısımları, tek başına çalıştırılabilecek ve test edilebilecek şekilde topladım. Uygulama kodu bu depoda yok.

**Web sürümü:** [cinevault-by-mk.netlify.app](https://cinevault-by-mk.netlify.app/)

## İçerik

| Dosya | Ne var |
| --- | --- |
| `schema/00_local_auth_stub.sql` | Düz PostgreSQL'de çalıştırmak için Supabase'in `auth` şemasının basit bir taklidi |
| `schema/01_profiles_and_roles.sql` | Profiller, rol hiyerarşisi, yetki trigger'ı, denetim kaydı |
| `schema/02_library.sql` | Kullanıcı kütüphanesi (favori / liste / izlendi), RLS ve kısmi indeksler |
| `schema/03_usernames.sql` | Kullanıcı adı sistemi ve kapatılan güvenlik açığı |
| `schema/04_account_deletion.sql` | Uygulama içinden hesap silme |
| `tests/security_tests.sql` | Kuralların gerçekten veritabanında uygulandığını kontrol eden testler |
| `docs/er-diagram.md` | Varlık-ilişki diyagramı |

## Temel tasarım kararları

**1. Yetki kararları veritabanında.**
Uygulamaya mobil ve web'den erişiliyor. "Sen adminsin" bilgisini istemciye bırakmak yerine her tabloda Row Level Security (RLS) açık. Her kullanıcı yalnızca kendi satırlarını görüyor ve değiştiriyor. Yeni bir istemci eklense bile kurallar otomatik olarak geçerli.

**2. Üç rol ve tek master.**
`user`, `admin` ve `master` rolleri var. Sistemde en fazla bir master olabilir ve bu kural uygulamada değil, **kısmi benzersiz indeksle** korunuyor. Böylece aynı anda gelen iki istek bile ikinci bir master oluşturamıyor.

**3. Kolon bazlı koruma trigger ile.**
PostgreSQL RLS'te kolon bazlı kısıt yok: kullanıcı kendi satırını güncelleyebiliyorsa rol ve premium alanlarını da güncelleyebilir. Bunu `guard_profile_privileges` trigger'ı engelliyor. Rolü sadece master, premium süresini sadece yöneticiler değiştirebiliyor.

**4. Kullanıcı adları: taklide karşı normalizasyon.**
Görünen ad (`username`) ve karşılaştırma anahtarı (`username_key`) ayrı tutuluyor. Anahtar üretilirken Türkçe harfler sadeleştiriliyor ve birbirine benzeyen karakterler (`0`/`o`, `1`/`l`) aynı değere indiriliyor. Bu yüzden `Mertl`, `MERT1` ve `mertl` aynı ad sayılıyor.

**5. Hesap silmede tek satır, gerisi cascade.**
Hesap silinirken tablo tablo silmek yerine sadece `auth.users` satırı siliniyor. Tüm tablolar `on delete cascade` ile ona bağlı. İleride eklenen bir tabloyu silme fonksiyonuna eklemeyi unutma riski yok.

## Bulunan ve düzeltilen hatalar

**Kullanıcı adı kuralları atlanabiliyordu.**
İlk sürümde kullanıcı adı yalnızca `claim_username()` fonksiyonuyla alınıyordu ve tüm kurallar (yasaklı kelimeler, normalizasyon, 90 günlük değiştirme süresi) bu fonksiyonun içindeydi. Ancak profil güncelleme politikası kullanıcının kendi satırındaki *her* kolonu yazmasına izin veriyordu. Yani şu sorgu fonksiyonu hiç çağırmadan çalışıyordu:

```sql
update profiles set username = 'admin', username_key = 'zzz' where id = auth.uid();
```

Çözüm olarak `guard_profile_username` trigger'ı eklendi: kullanıcı adı kolonları artık yalnızca bu fonksiyonların içinden (işlem içi bir bayrakla), sunucu tarafından veya bir yönetici tarafından değiştirilebiliyor.

**Bazı kullanıcılar hiç silinemiyordu.**
Hesap silme eklenirken `admin_audit_log.actor_id` kolonunun hem `NOT NULL` hem de `on delete set null` olduğu fark edildi. Bu ikisi birlikte çalışamaz; denetim kaydında satırı olan hiçbir kullanıcı silinemiyordu. Kolon null olabilir hale getirildi; silinen kullanıcının işlem kaydı korunuyor ama kimliği tutulmuyor.

## Çalıştırma

Düz PostgreSQL'de (14 veya üzeri) dosyaları sırasıyla çalıştırmak yeterli:

```bash
createdb cinevault_demo
for f in schema/*.sql tests/security_tests.sql; do
  psql -d cinevault_demo -v ON_ERROR_STOP=1 -f "$f"
done
```

Testler başarılıysa son satırda `TÜM TESTLER GEÇTİ` yazar. Supabase'e uygularken `00_local_auth_stub.sql` atlanır, çünkü `auth` şeması orada hazır geliyor.

## Notlar

- Bu kodu yazarken yapay zeka destekli geliştirme araçlarını kullandım. Veri modelini, güvenlik kurallarını ve bu kararları ben belirledim, testlerle doğruladım.
- Uygulamanın Flutter/Dart kodu büyük ölçüde yapay zeka araçlarıyla yazıldı; Flutter'ı yeni öğreniyorum. Bu projedeki katkım ürün tasarımı, özellik kararları, test ve veritabanı tarafı.
- Yasaklı kullanıcı adı listesi bu depoda kısaltıldı.
- Bu depodaki kod yalnızca inceleme amaçlıdır; kullanım izni verilmemiştir (bkz. `LICENSE`).
