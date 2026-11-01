# FILESYSTEM_REPORT - issues seen from client sessions

## 2026-10-24, internal ML development session: `mem_put` cannot be called from the schema the tool exposes

Repro (three attempts, each a different error):
1. `mem_put {item: {key, content}}` -> `failed to deserialize parameters: unknown field 'key', expected one of
   itemType, content, title, summaryText, visibility, status, tags, ownerActorId, sourceKind, sourceRef, confidence,
   expiresAt, supersedesId`
2. `mem_put {item: {itemType: "note", title, tags, content}}` -> `unknown variant 'note', expected one of fact,
   episode, task, decision, artifact, summary`
3. `mem_put {item: {itemType: "summary", title, tags, content}}` -> `missing field 'workspaceId'`

Problems:
- `workspaceId` is required but is not in the list of accepted fields printed by error 1, and neither the tool
  description nor any error says where a client gets a workspace id (no `mem_workspaces` / default workspace).
- The required fields and the `itemType` enum are only discoverable by trial and error; the deferred tool schema the
  client sees does not list them.
- Earlier (2026-10-23) the same tool failed with "missing field item" when called with flat arguments.

Expected: either a default workspace (per allowed root / per client) so `workspaceId` is optional, or a tool that
lists/creates workspaces, plus the full item schema (required fields, enums) in the tool description.
