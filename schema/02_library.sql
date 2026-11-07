-- Kullanıcı kütüphanesi: favoriler, izleme listesi, izlenenler.
--
-- Uygulama çevrimdışı çalışıyor; cihazdaki yerel veritabanı birincil
-- kaynak, bu tablo cihazlar arası senkron için.

create table if not exists public.library_items (
  user_id      uuid    not null references auth.users(id) on delete cascade,
  tmdb_id      integer not null,
  media_type   text    not null check (media_type in ('movie', 'series', 'person')),

  is_favorite  boolean not null default false,
  is_in_list   boolean not null default false,
  is_watched   boolean not null default false,

  user_rating  real check (user_rating is null or user_rating between 0 and 10),

  -- Listeyi internete çıkmadan çizebilmek için başlık ve afiş saklanıyor.
  title_snapshot       text,
  poster_path_snapshot text,

  updated_at   timestamptz not null default now(),
  primary key (user_id, tmdb_id, media_type)
);

alter table public.library_items enable row level security;

-- Her kullanıcı yalnızca kendi satırlarını görür ve değiştirir.
drop policy if exists library_select_own on public.library_items;
create policy library_select_own on public.library_items
  for select to authenticated using (auth.uid() = user_id);

drop policy if exists library_insert_own on public.library_items;
create policy library_insert_own on public.library_items
  for insert to authenticated with check (auth.uid() = user_id);

drop policy if exists library_update_own on public.library_items;
create policy library_update_own on public.library_items
  for update to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

drop policy if exists library_delete_own on public.library_items;
create policy library_delete_own on public.library_items
  for delete to authenticated using (auth.uid() = user_id);

drop trigger if exists trg_library_touch on public.library_items;
create trigger trg_library_touch
  before update on public.library_items
  for each row execute function public.touch_updated_at();

-- İndeksler.
-- Profil ekranında üç raf var ve her biri "bu kullanıcının şu işaretli
-- içerikleri, en yeniden eskiye" diye soruyor. Kısmi indeksler sadece
-- işaretli satırları taşıdığı için küçük ve hızlı.
create index if not exists idx_library_favorites
  on public.library_items (user_id, updated_at desc) where is_favorite;

create index if not exists idx_library_watchlist
  on public.library_items (user_id, updated_at desc) where is_in_list;

create index if not exists idx_library_watched
  on public.library_items (user_id, updated_at desc) where is_watched;

-- "Topluluk favorileri": bir içeriğin kaç kişide favori olduğu.
create index if not exists idx_library_content
  on public.library_items (tmdb_id, media_type) where is_favorite or is_watched;

grant select, insert, update, delete on public.library_items to authenticated;
