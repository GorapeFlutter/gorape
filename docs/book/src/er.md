# ER diagram

<pre class="mermaid">
erDiagram
  PROJECTS ||--o{ GROUPS : contains
  PROJECTS ||--o{ PRINCIPALS : identifies
  PROJECTS ||--o{ ROLE_DEFINITIONS : defines
  PRINCIPALS ||--o{ ROLE_BINDINGS : receives
  ROLE_DEFINITIONS ||--o{ ROLE_BINDINGS : grants
  GROUPS o|--o{ ROLE_BINDINGS : scopes
  PRINCIPALS ||--o{ DEVICES : owns
  DEVICES ||--o{ DEVICE_KEYS : has
  DEVICE_KEYS ||--o{ ATTESTATIONS : verifies
  DEVICES ||--o{ DEVICE_GROUP_BINDINGS : assigned
  GROUPS ||--o{ DEVICE_GROUP_BINDINGS : includes
  DEVICES ||--o{ DEVICE_EVENTS : emits
  PRINCIPALS ||--o{ DEVICE_EVENTS : acts

  PROJECTS {
    uuid id PK
    text slug UK
    text issuer UK
    text realm
    text status
  }
  GROUPS {
    uuid id PK
    uuid project_id FK
    text slug
  }
  PRINCIPALS {
    uuid id PK
    uuid project_id FK
    text issuer
    text subject
  }
  ROLE_DEFINITIONS {
    uuid id PK
    uuid project_id FK
    text key
    jsonb permissions
  }
  ROLE_BINDINGS {
    uuid id PK
    uuid project_id FK
    uuid principal_id FK
    uuid group_id FK
    text role_key FK
  }
  DEVICES {
    uuid id PK
    uuid project_id FK
    uuid owner_id FK
    text platform
    text status
  }
  DEVICE_KEYS {
    uuid id PK
    uuid project_id FK
    uuid device_id FK
    bytea public_key
  }
  ATTESTATIONS {
    uuid id PK
    uuid project_id FK
    uuid key_id FK
    text verification_status
  }
</pre>

<script type="module">
import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs";
mermaid.initialize({ startOnLoad: true, theme: "default" });
</script>
