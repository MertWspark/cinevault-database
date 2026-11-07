# Varlık-İlişki Diyagramı

Bu depodaki tabloların ilişkileri. GitHub bu diyagramı otomatik olarak çizer.

```mermaid
erDiagram
    AUTH_USERS ||--|| PROFILES : "kaydolunca otomatik açılır"
    AUTH_USERS ||--o{ LIBRARY_ITEMS : "sahibi"
    AUTH_USERS |o--o{ ADMIN_AUDIT_LOG : "işlemi yapan (actor_id)"
    AUTH_USERS |o--o{ ADMIN_AUDIT_LOG : "işlemden etkilenen (target_id)"

    AUTH_USERS {
        uuid id PK
        text email
        timestamptz created_at
    }

    PROFILES {
        uuid id PK "auth.users.id"
        text display_name
        user_role role "user | admin | master"
        timestamptz premium_until "null = ücretsiz"
        int ai_credits
        text username "görünen ad"
        text username_key UK "normalize, benzersiz"
        timestamptz username_changed_at
    }

    LIBRARY_ITEMS {
        uuid user_id PK "auth.users.id"
        int tmdb_id PK
        text media_type PK "movie | series | person"
        bool is_favorite
        bool is_in_list
        bool is_watched
        real user_rating "0-10"
        timestamptz updated_at
    }

    ADMIN_AUDIT_LOG {
        bigint id PK
        uuid actor_id "null olabilir"
        uuid target_id
        text action
        jsonb detail
        timestamptz created_at
    }

    BLOCKED_USERNAMES {
        text fragment PK
        text match_mode "exact | contains"
    }
```

## Kurallar özeti

| Tablo | Okuma | Yazma |
| --- | --- | --- |
| `profiles` | Kendi satırı; yöneticiler hepsi | Kendi satırı. Rol: sadece master. Premium: sadece yönetici. Kullanıcı adı: sadece RPC |
| `library_items` | Kendi satırları | Kendi satırları |
| `admin_audit_log` | Sadece yöneticiler | Sadece sunucu |
| `blocked_usernames` | Herkes | Sadece sunucu |
