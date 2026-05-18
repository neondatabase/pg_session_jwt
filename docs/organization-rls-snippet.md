# Neon docs snippet: organization-scoped RLS

Use with [Neon RLS](https://neon.tech/docs/guides/neon-rls) and the **[Neon Auth organization plugin](https://neon.tech/docs/neon-auth/overview)** only.

`auth.organization()` and `auth.organization_id()` read Neon Auth’s `"o"` claim. They are **not** portable across arbitrary auth providers (Auth0, Clerk, Supabase, etc.), which use different claim names and shapes or omit organization from the JWT entirely. For other issuers, use `auth.jwt()` and the claim path your provider documents.

The active organization claim shape:

```json
{"id": "<uuid>", "slug": "<string>", "role": "<member-role>"}
```

When `"o"` is missing or malformed, both functions return SQL `NULL` (RLS policies using them fail closed).

## Functions

- `auth.organization()` — full `"o"` object as `jsonb`, or SQL `NULL` if there is no active organization
- `auth.organization_id()` — `"o"."id"` as `text`, or SQL `NULL` if there is no active organization

## Row Level Security example

```sql
-- Team rows: scope to the active organization
CREATE POLICY team_select ON team
  FOR SELECT
  USING (organization_id = auth.organization_id());

-- Role-gated writes (optional)
CREATE POLICY team_admin_update ON team
  FOR UPDATE
  USING (
    organization_id = auth.organization_id()
    AND (auth.organization() ->> 'role') IN ('admin', 'owner')
  );
```

## Other auth providers

Example using the generic payload instead of Neon-specific helpers:

```sql
-- Replace 'your_org_claim' with the claim name your issuer documents
USING (organization_id = auth.jwt() -> 'your_org_claim' ->> 'id')
```
