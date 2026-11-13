CREATE TYPE gorape_role AS ENUM ('admin','editor','viewer');

CREATE TABLE project_role_bindings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL,
  principal_id UUID NOT NULL,
  role gorape_role NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(project_id, principal_id),
  FOREIGN KEY(project_id,principal_id) REFERENCES principals(project_id,id) ON DELETE CASCADE
);

CREATE TABLE group_role_bindings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL,
  group_id UUID NOT NULL,
  principal_id UUID NOT NULL,
  role gorape_role NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(project_id, group_id, principal_id),
  FOREIGN KEY(project_id,group_id) REFERENCES groups(project_id,id) ON DELETE CASCADE,
  FOREIGN KEY(project_id,principal_id) REFERENCES principals(project_id,id) ON DELETE CASCADE
);

INSERT INTO project_role_bindings (project_id, principal_id, role)
SELECT project_id, principal_id, role_key::gorape_role
FROM role_bindings WHERE scope = 'project';

INSERT INTO group_role_bindings (project_id, group_id, principal_id, role)
SELECT project_id, group_id, principal_id, role_key::gorape_role
FROM role_bindings WHERE scope = 'group';

DROP TABLE role_bindings;
DROP TABLE role_definitions;
