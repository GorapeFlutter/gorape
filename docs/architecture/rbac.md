# RBAC matrix

| Operation | Admin | Editor | Viewer |
|---|---:|---:|---:|
| Domain/device/attestation read | Yes | Yes | Yes |
| Device registration/revocation | Yes | Yes | No |
| Group and role management | Yes | No | No |

Project roles inherit into all groups. A group role applies only to that group. Effective access is the stronger of the project and group role. Only a Project Admin grants Group Admin. Group Admin manages Group Editor/Viewer. The database transaction prevents deletion of the last Project Admin.
