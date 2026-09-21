# Data Layer

> SCOPE: Load when list, search, filter, pagination, aggregation, export, resolver, or search-engine behavior can leak records or bypass authorization, across REST, GraphQL, direct query, or engine DSL surfaces.

## Research families

- ORM authorization-filter leakage (missing or inconsistent scope on querysets)
- Relationship and nested-object traversal (parent authorized, child unscoped)
- Aggregation, count, and facet side channels revealing hidden records
- Raw-query and query-builder escape (raw fragments, literal, text blocks)
- NoSQL operator semantics (comparison, regex, element-match, schema bypass)
- Search, sort, filter, and pagination differentials (cursor, offset, total counts)
- Export, report, and bulk-fetch paths with weaker checks than list views
- GraphQL resolver versus REST authorization mismatches on the same data
- Cache-versus-database authorization mismatch (cached aggregate served past revocation)
- JSON and query serialization mismatches (null, array, object, negative, string-null)
- Soft-delete, archive, and trash scope gaps (row dropped from list but alive in aggregate, search, export, or history)
- Field-level versus object-level authorization (guarded container exposes an unguarded field or nested edge)
- Filter-builder precedence bugs (an injected `OR`/`Q` clause widens past the mandatory tenant/owner predicate)
- Nested-filter and bracketed query-parameter operator injection (`filter[owner]=`, `field[$ne]=` mapped into the query language)
- Join / `through`-table scope gaps (association row scoped on the parent but not the join)
- Secondary-index authorization (denormalized search/cache index carrying rows the primary store would scope out — confirm per engagement)
- GraphQL global-ID resolution (`node`/`nodes`) reaching objects the owning query guards
- Create-path authorization gaps (scope applied on read but never on create, letting a user mint a row owned by another principal)
- Projection / `only` / `select` omissions (authorization enforced on the default columns but a sparse fieldset or `fields=` parameter bypasses it)
- Read-replica and reporting-database scope drift (the same dataset served by a path that reimplements weaker filtering)
- Search-engine access control that re-implements authorization in the engine (Elasticsearch/OpenSearch DLS+FLS, Solr filter queries) and drifts from the application's scope
- Sort-by-hidden-field inference (rows ordered by a field the projection withholds; binary-search extraction from ordering alone)
- Cursor tampering (opaque/base64 cursors that encode offsets or sort values, replayed stale search contexts, PIT/scroll ids)
- Engine aggregation approximation as oracle and as false positive (`hits.total.relation`, cardinality/terms estimates, Solr `numFoundExact`)
- Analyzer/tokenization filter bypass (a `match`-style rule on an analyzed `text` field matches token spans, not identities)
- Raw-wrapper injection (`$queryRawUnsafe`, `Prisma.raw`, fabricated tagged templates, Mongo `findRaw`/`aggregateRaw` filter objects, `order_by`-style identifier builders)
- Row-level-security representation drift (SUPERUSER-owned views, `SECURITY DEFINER` functions, and `security_invoker` gaps)
- Column-level authorization gaps (RLS guards rows only; over-broad `GRANT SELECT`/`UPDATE(col)` exposes columns)

## Preconditions

- At least two researcher-controlled records in distinct ownership or tenant states plus a known hidden record owned by the second account.
- Observable list, search, aggregate, or export surface with researcher-seeded canary values.
- Fingerprinted stack hint (ORM, query builder, NoSQL store, GraphQL versus REST duality) sufficient to pick operator and syntax probes.
- For resolver differentials: the same dataset reachable through two representations (REST list plus GraphQL query, or list plus export).
- For cache mismatches: an observable cache layer or stored aggregate with a permission-change or revocation event available on researcher data.
- Canonical injection detail (SQL, NoSQL, SSTI, XXE) lives in parsers-injection/parsers.md and is referenced, not duplicated, here.
- For GraphQL batching: the endpoint accepts a JSON array of operations or field aliases, so many object requests travel in one network call.
- For NoSQL operator probes: the endpoint accepts a JSON body or bracketed URL parameters (`field[$ne]=`) that reach the query object.
- For ORM injection: at least one user-reachable filter, sort, or operator parameter that reaches the query builder without a strict allowlist.
- For aggregation oracles: a stat, facet, autocomplete, or typeahead endpoint observable alongside the list for the same dataset.
- For raw-query paths: a feature (report, geo, full-text, `annotate`/`extra`) that plausibly builds SQL from a non-occurrence-only parameter.
- For projection probes: a sparse-fieldset / `fields` / `select` / `?expand=` parameter that changes which columns the serializer returns.
- For create-path probes: a writable endpoint where an owner/tenant field is accepted, defaulted, or inferred from a value the caller controls.
- For replica drift: evidence of more than one read path (reporting DB, read replica, search index, materialized view) serving the same entity.
- For search-engine probes: direct or proxied access to a search service whose reads are role-scoped (DLS/FLS configured, or absent where the app assumes it), plus the role definition if readable.
- For cursor probes: a client-visible cursor/keyset parameter (`cursorMark`, `search_after`, `after`/`before`, `page_token`, PIT/scroll id) and two pages that can be diffed.
- For sort probes: a client-settable sort field accepted even when that field is excluded from the response projection.
- For raw-wrapper probes: call sites that build query text from identifiers or fragments (raw SQL wrappers, `extra()`, `order_by()`, Mongo `findRaw` filter passthrough, `rules=`/`{!}` Solr local params).
- For RLS/representation checks: an auto-API (PostgREST/Supabase-style) or view/function layer over RLS tables, plus a column the role should not read and a function/view whose definer rights widen scope.

## Oracles

- Cross-account row inclusion: second-account canary appears in first-account list, search, facet, or total-count response.
- Filter-bypass inclusion: a record excluded by a secure filter appears when sort, operator, null, array, or pagination parameter changes with no other variable moved.
- Aggregation disclosure: count, sum, histogram, or facet bucket changes predictably with hidden-record creation while the rows themselves stay hidden.
- Resolver differential: GraphQL field or nested edge returns the hidden record while the REST equivalent returns 403 or omits it, or vice versa.
- Export overreach: CSV, report, or bulk endpoint contains researcher-hidden rows that the list view correctly omits.
- Raw-query signal: database-shaped error, ordering anomaly, or timing shift from a single benign operator probe on researcher data only.
- Revocation persistence: post-permission-change or post-revocation list, aggregate, or cached export still contains the removed researcher record.
- Pagination leak: impossible-offset, negative-offset, or oversized-page request returns rows outside the authorized window.
- Field-level bypass: a guarded object exposes a nested edge or attribute whose resolver or serializer omits the owner/tenant check.
- Batched/aliased differential: aliased fields or an array of operations return records that the single-operation form denies.
- Global-ID node oracle: `node(id:)`/`nodes(ids:)` resolves an object by opaque global ID without the scope the owning query enforces.
- Count/count-differential: list rows are correctly scoped but `total`, `totalCount`, or facet buckets reflect the unscoped store.
- Soft-delete leak: a deleted, archived, or trashed researcher record resurfaces in aggregate, search, export, or history after vanishing from the list.
- Operator-injection oracle: a single boolean or time-based operator probe on researcher data widens the result set or delays the response deterministically.
- Projection bypass: a sparse fieldset or `fields=`/`select=` parameter returns a guarded attribute the default representation withholds.
- Create-path ownership injection: a create request that sets an owner/tenant field (or an ID the caller chooses) yields a row readable only with the injected principal's scope.
- Replica/representation drift: list scoped correctly but the search index, materialized view, or reporting endpoint returns the hidden researcher record for the same query.
- Sort-order oracle: rows reorder predictably when the caller sets a sort field that is absent from the response projection, permitting binary-search inference of unseen values one comparison at a time.
- Cursor-tamper oracle: after decoding, replaying, or shifting a client-supplied cursor, rows outside the authorized page window, out-of-order rows, or duplicates across windows appear.
- Engine count oracle (exact mode): `hits.total.value` with `relation:eq` (Elasticsearch `track_total_hits:true`), or Solr `numFound` with `numFoundExact:true`, changes with the hidden canary while rows stay hidden.
- DLS tokenization oracle (OpenSearch): a DLS rule written as `match` on a `text` field matches two principals whose IDs differ only in tokenized characters (`User-1` versus `User-2`) — documented cross-principal access class.
- RLS representation oracle: a view or `SECURITY DEFINER` function returns base-table rows the same principal cannot fetch through the table route.
- Column-grant oracle: `select=` / `fl` / `fields` returns a column that a column-scoped `GRANT` or field policy should have withheld.
- Raw-wrapper oracle: one benign metacharacter or type variant in an identifier/order position produces a database error, ordering change, or differential only on the wrapper path.
- DLS write/read asymmetry oracle (OpenSearch): a DLS-restricted principal with write permissions indexes a document that never appears in its own scoped reads — scope gap at the write path.

## Minimal safe proof

1. Seed: create one record per researcher account with unique canary strings; baseline list, search, count, and export responses per account.
2. Single-variable filter probe: change one parameter at a time (operator, sort key, null versus absent, array versus scalar) and diff row sets and totals against baseline.
3. Resolver cross-check: request the same researcher records through REST and GraphQL paths from both sessions and compare authorization decisions.
4. Aggregation oracle: record counts and facet buckets before and after creating one hidden canary record; attribute only the delta, never third-party rows.
5. Revocation check: downgrade or revoke access on one researcher record, then re-request list, aggregate, and export from the downgraded session and a clean session.
6. Resolver/graph sweep: for each representation, walk top-level fields, nested edges, aliased duplicates, the `node`/`nodes` global-ID entry, and every sparse-fieldset variant; re-request each after every state change.
7. Create-path check: submit a create/import request that supplies an owner/tenant/ID field and read the created row back as the injected principal and as the creator.
8. Sort/projection probe: dump the default projection, then request the same set sorted by each sortable field (including fields absent from the projection) and diff orderings; binary-search one canary only if a real differential appears.
9. Cursor/pagination probe: capture page 1, decode candidate cursors, replay a stale cursor, jump offsets past the window, and mismatch sort versus `search_after`; record which requests error versus widen, and re-apply at most one variable per request.
10. Search-engine authorization probe: per role, rerun the same query with exact counting (Elasticsearch `track_total_hits:true`; Solr `minExactCount` above the observed total), one `terms` and one `cardinality` aggregation, and diff against page rows; keep approximation caveats in the write-up.
11. Raw-wrapper probe: locate wrapper call sites in scope; send one metacharacter or type variant from researcher-controlled input and compare against the same input on the safe path.
12. Stop conditions: any non-researcher record, production table name, stack trace with secrets, or heavy-query slowdown — halt, record the oracle, and report without enumeration or extraction.

## False positives

- Total counts that include public or shared records by design — rule out by confirming the hidden researcher canary is absent from rows and facets.
- Empty-list with nonzero total caused by UI pagination defaults — cosmetic mismatch, not leakage; require the hidden canary in returned rows or a canary-driven delta.
- Sort-order change with identical row sets — reordering is not bypass; require previously excluded rows to appear.
- GraphQL field error that names a type but returns no hidden data — schema disclosure alone is not record disclosure; require canary bytes.
- Benign timing jitter from cold cache or PoP routing — rule out with medians over repeated samples plus an interleaved control query.
- Export containing only the requester's own rows in a different shape — representation change, not overreach; require second-account canary rows.
- Database error mentioning syntax without reflecting or differentiating hidden data — parser noise, not injection; require a controlled boolean or timing oracle on researcher data.
- Cached aggregate that refreshes after TTL with correct values — stale-while-revalidate window, not persistent bypass; require survival past documented expiry plus revocation.
- `total`/count including soft-deleted or archived rows the UI intentionally omits — status filtering, not authorization; require an authorization-relevant delta or the hidden canary's bytes.
- `node`/`nodes` returning an object the caller already reaches through a legitimate share grant — intended access, not a global-ID bypass; require access outside any grant.
- Field omitted from one serializer but present in another the same principal legitimately uses — representation difference; require the extra field on a record the caller must not read.
- Aggregate delta that tracks a *public* canary (e.g. a public counter) — attribution error; require the hidden researcher canary as the only changing input.
- Owner/tenant field accepted on create but overridden server-side before persistence — require read-back showing the injected principal actually owns the row.
- Sparse-fieldset response that includes an attribute the caller may read anyway — projection difference; require a field that a default scoped call withholds for that principal.
- Larger result set from a filter change that simply matches more of the caller's own rows — require a row the caller does not own.
- Elasticsearch `hits.total` stuck at 10,000 with `relation:"gte"` — `track_total_hits` default cap, not a scope artifact; re-run with `track_total_hits:true` before interpreting a count.
- Cardinality aggregation drift — HyperLogLog++ approximation (default `precision_threshold` 3000, max 40000, percent-level error); small deltas are not authorization deltas, require canary row inclusion.
- Terms aggregation partial counts — `doc_count` may be approximate across shards; check `doc_count_error_upper_bound` and `sum_other_doc_count`, and use `composite` aggregation when exact enumeration is required.
- Solr approximate `numFound` when `minExactCount` is set — `numFoundExact:false` means the true total is greater or equal; also `timeAllowed`/`cpuAllowed` can return `partialResults` with inaccurate counts.
- Solr `cursorMark == nextCursorMark` while `partialResults:true` — not end of results; increase `timeAllowed` and repeat before concluding.
- Elasticsearch `search_after`/scroll duplicates or gaps — replica Lucene doc-ID tiebreaks and index refresh change boundaries; verify with a PIT and a unique tiebreaker before claiming disclosure.
- Elasticsearch multi-role union — a role without DLS (or without FLS) grants all documents (or all fields) for that index by documented combination rules; verify role assignment before claiming a bypass.
- OpenSearch multi-role DLS — a DLS-free role filters to the DLS role by default, and `plugins.security.dfm_empty_overrides_all: true` inverts that; the observed behavior is configuration-dependent.
- MySQL `str_col = 0` matching every row — documented implicit float coercion, not an injected predicate; require attacker-controlled operator/operand before counting it as a filter bypass.
- PostgREST/Supabase column returned via `select=` while the role holds `SELECT` on it — row-level security is row-level only; column exposure needs a missing column `REVOKE`, not an RLS bug.
- MongoDB case/accent-insensitive match under a non-`simple` collation (`strength` 1/2) — configured comparison semantics; only a finding when the security filter assumed byte equality on identity fields.
- Elasticsearch FLS role audit confusion — absent `field_security` means all fields, `"grant": []` means no fields; read the role definition before calling one of these outcomes correct.

## Version/implementation notes

### ORM scoping — Django / Django REST Framework

- DRF runs **view-level** `has_permission()` on every action but **object-level** `has_object_permission()` only when `get_object()` is called, i.e. retrieve/update/destroy — never on **list** (performance) and never on **create**. A list view whose scope lives only in object permissions is unscoped; a create endpoint that relies on `has_object_permission()` never runs it. Port creation restriction to the serializer or `perform_create()`. [T1 DRF]
- `queryset`/`get_queryset()` is the correct list-scoping seam and may differ **per action**; test `list`, `retrieve`, `update`, `destroy`, and any custom/export action separately because each can return a different queryset.
- Of the built-in classes only `DjangoObjectPermissions` wires object permissions, and it needs an object backend such as **django-guardian**; the plain classes (`IsAuthenticated`, `IsAdminUser`, model perms) do **not** implement `has_object_permission()`. `DjangoObjectPermissionsFilter` (djangorestframework-guardian) is required to make **list** endpoints honor view permissions. [T1 DRF]
- `DjangoModelPermissions` maps POST→`add`, PUT/PATCH→`change`, DELETE→`delete`, and grants only when the user holds the model permission; a view-`perms_map` override that forgets `GET`/`view` leaves reads ungated. Probe each HTTP verb against the same object.

Which restriction mechanism covers which action (DRF's own matrix) — a gap in the relevant cell is the bug:

| Action | `queryset` / `get_queryset()` | `permission_classes` | `serializer_class` |
|---|---|---|---|
| list | global | global | object-level\* |
| create | none | global | object-level |
| retrieve | global | object-level | object-level |
| update | global | object-level | object-level |
| partial_update | global | object-level | object-level |
| destroy | global | object-level | none |

\* A serializer must not raise `PermissionDenied` in a list action, or the whole list fails.

### Raw-query surfaces — Django, Rails, Prisma, PostgREST

- Django `Manager.raw()`, `connection.cursor().execute()`, `extra()`, and `RawSQL` perform **no** checks; `params` (`%s`/`%(key)s`, unquoted) is the only guard. String-formatting a raw query or quoting the placeholder is the injection. [T1 Django]
- `raw()` maps columns to model fields **by name** (order irrelevant); an unmapped/omitted primary key raises `FieldDoesNotExist`, and fields left out become deferred (extra queries) — a sign the raw path is reachable through an ordinary list view. [T1 Django]
- **MySQL silent type coercion**: comparing a string column to an integer makes MySQL coerce the column, so `WHERE mycolumn = 0` matches rows whose value is `'abc'` — a type-confusion filter differential that can widen a scoped result set. [T1 Django] [T1 MySQL]
- Rails: `where("name = '#{params[:name]}'")` is injection; the safe forms are positional (`where("zip_code = ?", v)`), named (`where("zip_code = :zip", {zip: v})`), or hash (`where(zip_code: v)`). `find_by_sql`, `connection.execute`, and interpolated `find_by(...)` must be sanitized by hand. [T1 Rails]
- Rails default application scoping is `@current_user.projects.find(params[:id])`, not `Project.find(params[:id])` — the same pattern to look for in any stack where a controller fetches by a global ID. [T1 Rails]
- Django **CVE-2021-35042**: unsanitized user input passed to `QuerySet.order_by()` bypassed intended column-reference validation and was a potential SQL injection (fixed in 3.2.5 / 3.1.13; regression present in 3.1/3.2). Treat every order/sort parameter as an identifier-injection surface, not just an ordering choice. [T1 Django advisory]
- Prisma `$queryRaw`/`$executeRaw` are tagged templates compiled to prepared statements; `$queryRawUnsafe`/`$executeRawUnsafe` take raw strings and Prisma documents the "significant risk" of SQL injection with them. The alias is the vulnerability: `$queryRaw` can also be made injectable by feeding it a fabricated strings array (setting `.raw`) or by wrapping user input in `Prisma.raw()`; `Prisma.sql` with trusted segments is the safe composition form. [T1 Prisma]
- Prisma placeholders cannot carry identifiers: table, column, and `ORDER BY` keywords cannot be interpolated, so those cases force `$queryRawUnsafe` — grep for exactly those call sites when the app uses Prisma. [T1 Prisma]
- Prisma MongoDB surface: `<model>.findRaw({filter, options})`, `<model>.aggregateRaw({pipeline, options})`, and `$runCommandRaw(command)` pass JSON straight to the driver; user JSON in `filter`/`pipeline` is operator/pipeline injection, and the documented `$runCommandRaw` example passes `bypassDocumentValidation: true`. [T1 Prisma]
- PostgREST query strings are a query language: `?or=(age.lt.18,age.gt.21)`, `not.`, `any/all` modifiers, `like/ilike/match/imatch`, and JSON/array path filters (`json_data->>blood_type=eq.A-`) all compile into SQL boolean trees; `order=` sorts by columns or JSON paths; `select=` shapes columns, with renaming (`alias:col`), casts (`col::text`), and JSON arrow paths. User input concatenated into any of these is query-language injection. [T1 PostgREST]
- PostgREST authorization model: `GRANT` decides endpoints, verbs, and columns (`GRANT SELECT, UPDATE(message_body) ON chat TO webuser`); RLS policies decide rows (`USING`/`WITH CHECK`). Functions default to `EXECUTE ... PUBLIC` unless default privileges are revoked; `SECURITY DEFINER` functions run with owner rights. Views run with owner privileges and a SUPERUSER-created view bypasses RLS unless `security_invoker = true` (PostgreSQL >= 15) or the view owner is a non-superuser. [T1 PostgREST]

Rails `deep_munge` (CVE-2012-2660 / CVE-2012-2694 / CVE-2013-0155) normalizes hostile parameter shapes that bypassed `nil` guards while still injecting `IS NULL`/`IN (...)` predicates:

| JSON sent | Parsed `params` after `deep_munge` |
|---|---|
| `{ "person": null }` | `{ :person => nil }` |
| `{ "person": [] }` | `{ :person => [] }` |
| `{ "person": [null] }` | `{ :person => [] }` |
| `{ "person": [null, null, ...] }` | `{ :person => [] }` |
| `{ "person": ["foo", null] }` | `{ :person => ["foo"] }` |

Setting `config.action_dispatch.perform_deep_munge = false` reintroduces the unsafe behavior. [T1 Rails] [T3 vuln intel]

### Type coercion, case, and collation

- **MySQL implicit conversion in comparisons**: when one operand is a number and the other a string column, the comparison is performed as floating-point; `WHERE c3 = 0` returns every row whose non-numeric string converts to `0` (the manual's own example returns all five rows, `*even in strict SQL mode*` — strict mode is not applied while processing `SELECT`). Quoting the value (`c3 = '0'`) restores string comparison. A scoped `WHERE owner = ?` that receives a numeric `0` can therefore widen to all rows. [T1 MySQL]
- **MySQL index/rounding effects**: string-column-versus-number comparisons cannot use an index on the string column (many strings convert to the same number); large-int/float comparisons round (`'9223372036854775807' = 9223372036854775806` is true; `CAST(... AS UNSIGNED)` restores exactness). Both matter when validating equality oracles. [T1 MySQL]
- **PostgreSQL strict typing plus collations**: Postgres does not perform MySQL-style numeric coercion, but comparisons follow the expression's collation; a **nondeterministic** ICU collation (`CREATE COLLATION ... deterministic = false`, e.g. `und-u-ks-level2`) makes `=` ignore case and other level-2 differences by design, so a scope predicate `WHERE owner = 'alice'` can match a variant-case record if the column or operation carries that collation. Standard and predefined collations are deterministic; user-defined ones default to deterministic. Pattern matching against nondeterministic collations is limited. [T1 PG]
- **MongoDB collation compares by level**: `strength` 1 ignores case and diacritics, 2 ignores case, 3 (default) is case/diacritic sensitive; `locale:"simple"` is binary. Views do **not** inherit the collection's default collation (they default to `simple`, and an operation cannot override a view's collation); document **keys** always compare binary even under a non-simple strength; `text` and `2d` indexes support only simple binary and need explicit `{collation:{locale:"simple"}}` when the collection has a non-simple default. An index only serves a comparison when the operation specifies the same collation. [T1 Mongo]
- **OpenSearch analyzer caveat in access control**: the security docs warn that a DLS rule using `match` on a `text` field tokenizes values containing Unicode special characters, so `User-1` and `User-2` can be treated as the same value (`user.id` example), unintentionally widening or filtering access; map the field as `keyword` (exact match) or use a custom analyzer. Test DLS predicates with principal names that differ only by tokenized characters and by case. [T1 OpenSearch]
- **Collation-level bypass probes**: when the store supports sensitivity levels (ICU `ks`, Mongo `strength`, MySQL `_ci`), replay the security predicate with the same identity in a different case, accent, or Unicode normalization form; a match that should fail is a configured-semantics bypass, and the finding is the guard assuming byte equality. [T1 PG] [T1 Mongo]

### NoSQL operator and syntax injection — MongoDB family

- Two distinct classes: **syntax injection** (break the query string, then boolean-condition it: `' || '1'=='1`, `' && 1 && 'x`) and **operator injection** (send query operators as data). Test both on every input that reaches the query object. [T2 PortSwigger]
- A MongoDB syntax fuzz string to seed a filter probe (URL-encoded when injected into a URL): `' " \` { ; $Foo } $Foo \xYZ \x00`. [T2 PortSwigger]
- Operator delivery: nested JSON `{"username":{"$ne":"invalid"}}`; URL brackets `username[$ne]=invalid`; if the URL form is rejected, switch GET→POST, set `Content-Type: application/json`, resend the operator in the body. [T2 PortSwigger]
- Classic auth bypasses: `{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}` (first doc in the collection) and `{"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}`. [T2 PortSwigger]
- JavaScript-bearing operators (`$where`, `mapReduce`) enable extraction: `admin' && this.password[0]=='a' || 'a'=='b'`, field discovery via `Object.keys(this)[0].match(...)`, and time oracles via `{"$where":"sleep(5000)"}`. Without JS, `{"password":{"$regex":"^a.*"}}` extracts byte-by-byte. [T2 PortSwigger]
- **Null-byte truncation**: appending `%00` (`category=fizzy'%00`) can make MongoDB ignore everything after it, dropping an appended `&& this.released == 1` restriction — hidden/unreleased documents appear. [T2 PortSwigger]
- Operator families to fingerprint per driver/version (support varies): comparison (`$ne`,`$gt`,`$gte`,`$lt`,`$lte`,`$in`,`$nin`), logical (`$and`,`$or`,`$nor`,`$not`), array (`$all`,`$elemMatch`,`$size`), type (`$exists`,`$type`), and misc (`$expr`,`$jsonSchema`,`$regex`,`$where`,`$mod`). `$expr` allows aggregation expressions (including field references) in a *query* predicate, so any user input that reaches `$expr` can compare server-side fields; `$jsonSchema` is a *validator*, not an authorization scope. [T1 MongoDB]
- Aggregate pipelines (`$lookup`, `$group`, `$match`) and `$where` are a separate execution surface from the find predicate; scope enforced on the find path is not automatically applied to an aggregation path.
- JavaScript execution is a **server-side scripting** feature: enabled by default; disable via `security.javascriptEnabled` / `--noscripting` on both `mongod` and `mongos`. `$where`, `$function`, and `$accumulator` all require it and are **deprecated as of MongoDB 8.0** (a warning is logged). MongoDB 6.0 moved the internal engine from MozJS-60 to MozJS-91, removing several legacy array/string helpers. `$expr` with non-JS operators is preferred and faster than `$where`. [T1 Mongo]
- `$function` can be invoked inside `$expr` in a query predicate (documented), so an `$expr` injection point is also a JavaScript-execution point while scripting is on. [T1 Mongo]
- `$accumulator` document processing order is not guaranteed (sharded merges, `allowDiskUse` spilling, `merge()`); do not build ordering or aggregation-count oracles that assume pipeline order. [T1 Mongo]

Operator class → probe shape → oracle:

| Operator class | Example predicate | Bypass / oracle shape |
|---|---|---|
| Comparison | `{"p":{"$ne":""}}`, `$in` | auth bypass / widen past equality |
| Logical | `$or`, `$nor` | injected clause bypasses an ANDed scope |
| Element/type | `$exists`, `$type` | reveal fields a projection should hide |
| Misc (JS/expr) | `$where`, `$expr`, `$regex` | boolean/timing extraction, field comparison |
| Array | `$elemMatch`, `$size` | match hidden array members |

### GraphQL — edges, nodes, batching, introspection

- Enforce authorization on **both edges and nodes**; the canonical bug class is edges checked while the node resolver is not (HackerOne report 489146, cited by OWASP). Walk every nested edge, not just the root query. [T1 OWASP]
- The `node`/`nodes` fields resolve objects by global ID even when not intended; detect them by grepping the schema (`... select(.name=="Query") | .fields[].name | grep node`) and then confirm whether the owning query's scope is applied. [T1 OWASP]
- **Batching attacks**: an array of operations or aliased fields in one request enumerates objects, brute-forces tokens/OTPs, and evades WAFs, IDS, and request-count rate limits that see a single request. Mitigations that *are* the bypass when absent: per-object request limits, disabled batching for sensitive objects, and a cap on concurrent operations. [T1 OWASP]
- Introspection and GraphiQL are commonly enabled by default; when introspection is disabled, the "Did you mean" field suggestion still leaks field names, so absence of introspection is not absence of a schema oracle. [T1 OWASP]
- Cost controls (depth limit, amount limit, pagination, query-cost analysis, timeouts) are the documented defenses; their absence is the availability counterpart to the authorization bugs above. [T1 OWASP]
- **Translation-layer drift**: engines that compile a GraphQL request into one SQL statement derive constraints from declarative permission rules (Hasura: boolean expressions plus column selections, per table/role/operation), so drift appears wherever a path — nested relationship, aggregate, computed field, `_or`/`_not` combination — does not receive the same predicate as the root. Probe every path independently, not the query as a whole. [T1 Hasura]
- Session variables (`X-Hasura-Role`, `X-Hasura-Allowed-Roles`, `X-Hasura-Default-Role`) select the permission rule, so a client-forgeable role header is the entire boundary; test role downgrade by editing the header and confirming which rule fired. [T1 Hasura]

Batched/aliased shape to test (one request, many objects):

```graphql
query { a: droid(id:"2000"){name} b: droid(id:"2001"){name} c: droid(id:"2002"){name} }
```

Depth and amount shapes to test (measure the server's own limits):

```graphql
query evil { album(id:42){ songs{ album{ songs{ album{ id } } } } } }   # unbounded depth
query       { author(id:"abc"){ posts(first: 99999999){ title } } }     # unbounded amount
```

### Pagination, cursors, and aggregation

- Pagination implementations differ on negative offsets, cursor tampering, and oversized limits; each variant is a separate single-variable probe.
- Aggregation/facet/count responses are a distinct surface: scope enforced on the row list is frequently not re-applied to the count, histogram, or facet query.
- Cache layers and read replicas introduce propagation delay that mimics revocation failure; re-check after the documented window before claiming persistence.
- Multi-database / replica routing can apply scope on the primary but serve an aggregate from an unscoped replica path — enumerate every read path for the same dataset.
- **Elasticsearch offset pagination**: `from` + `size` is capped at 10,000 hits by default (`index.max_result_window`); beyond it use `search_after`, which requires the same `query` and `sort` across requests, `from` of `0` or `-1`, and a unique tiebreaker (documented recommendation: a `_id` copy with `doc_values`). Without a tiebreaker, pages can miss or duplicate hits, and replica Lucene doc IDs are not stable. [T1 Elastic]
- **Elasticsearch PIT/scroll**: a PIT (`POST /my-index/_pit?keep_alive=1m`) adds the implicit `_shard_doc` tiebreaker, stable within the PIT; delete the PIT when done. Scroll is no longer recommended for deep pagination, holds snapshots (stale documents), and is limited to 500 open contexts by `search.max_open_scroll_context`. [T1 Elastic]
- **Elasticsearch counts**: `track_total_hits` defaults to 10,000 — search responses count accurately up to that, then `hits.total.relation` becomes `gte` (a lower bound); `true` forces exact counts; `false` omits the total. `size:0&terminate_after=1` is the cheap existence oracle. [T1 Elastic]
- **Elasticsearch aggregation approximation**: `cardinality` is HyperLogLog++ (approximate by design; `precision_threshold` default 3000, max 40000, error grows above it); `terms` returns top-`size` buckets (default 10) with `shard_size` default `size*1.5+10`, reports `doc_count_error_upper_bound` only under descending-count ordering, and `sum_other_doc_count` for dropped buckets; `"order":{"_count":"asc"}` has unbounded error and is discouraged. Use `composite` + pagination for exact enumeration. [T1 Elastic]
- **Solr offsets and cursors**: `start`/`rows` recomputes the whole sorted prefix per request (deep paging is O(start)) and pages shift when the index changes. `cursorMark=*` starts a stateless cursor whose only state is the last hit's sort values: `start` must be absent or `0`; the `sort` must include the `uniqueKey`; `score` sorts can skip/repeat across replicas; Date Math using `NOW` changes sort values every request; and `cursorMark == nextCursorMark` only proves exhaustion when `partialResults` is absent. [T1 Solr]
- **Solr approximate counts**: `minExactCount` lets Solr approximate `numFound` after a threshold and sets `numFoundExact:false` (true total is greater or equal); approximation applies only when `score desc` is the primary sort, and facets/other params can force exact counting. `timeAllowed`/`cpuAllowed` expiry also returns partial results with the flag set. [T1 Solr]
- **PostgREST limited writes**: `limit` on PATCH/DELETE requires an explicit `order` on unique columns (or `ctid` in PostgreSQL) and supports `offset` — the same `order`/`offset` tampering as reads applies to writes. [T1 PostgREST]
- **Relay-style cursors**: the connection spec defines cursors as opaque strings and requires ordering to be consistent between `first`/`after` and `last`/`before`; a server that encodes offsets or sort values in the cursor must still re-apply authorization at decode time. Decode the cursor, shift it by one, and compare the authorized window boundary. [T0 Relay]

### Search-engine DLS/FLS — Elasticsearch versus OpenSearch

- **Elasticsearch** DLS and FLS are restrictions on document-based **read** APIs, intended for read-only privileged accounts; omitting the `query` parameter disables DLS, and omitting `field_security` disables FLS for that entry. Sets combine across roles with OR (DLS) and union (FLS), so a second role without DLS/FLS wins for that index. `_id`, `_index`, `_type`, `_routing`, and the other listed metadata fields are always readable; `"grant": []` grants nothing; FLS should not be set on `alias` fields. [T1 Elastic]
- **Elasticsearch documented limitations**: relevancy scores are computed without the role query; suggesters are ignored; the terms-enum API returns nothing; profiling is unsupported; `multi_match` cannot use wildcard fields in DLS. Crucially, DLS does not prevent aggregate information leaks — a restricted user can still learn field names and terms that only exist in inaccessible documents and count how many inaccessible documents contain a term. Treat pure aggregate/term leakage as a documented limitation, not automatically a finding. [T1 Elastic]
- **Elasticsearch write/API coupling**: DLS/FLS users cannot use the update API or updates inside bulk requests, and the role query must not use `terms` lookup, `geo_shape` indexed shapes, or `percolate` queries; cross-cluster API keys support DLS/FLS on `search` but not on `replication`. [T1 Elastic]
- **OpenSearch** DLS also restricts only read operations (search, get) and explicitly does **not** restrict writes: a DLS-restricted user with index/update/delete permissions can modify or remove documents it cannot read, and can index documents it will not be able to retrieve. Role combination differs from Elasticsearch: when a DLS role is combined with a role that has no DLS, results are filtered to the DLS role unless `plugins.security.dfm_empty_overrides_all: true` makes the DLS-free role override all. [T1 OpenSearch]
- **OpenSearch DLS mechanics**: queries are OpenSearch DSL strings; parameter substitution supports `${user.name}`, `${user.roles}`, `${user.securityRoles}`, `${attr.<TYPE>.<NAME>}`, with fallback values added in 3.7.0; attribute-based security uses `terms_set` on `keyword`-mapped attribute fields. Evaluation modes: `lucene-level` (no term-lookup queries), `filter-level` (allows TLQs, but retrieval limited to get/search/mget/msearch and cross-cluster support limited), `adaptive` (default). DLS config max size is 1024 KB. [T1 OpenSearch]
- **Solr has no built-in DLS equivalent in the reference guide** — when scope is enforced by an `fq` or an auth plugin at the query layer, treat every request shape as a separate guard test: does a client-supplied `q`, `fq`, `sort`, `fl`, facet, or `cursorMark` value re-apply the scope, or replace it? (Deployment-specific; verify per engagement.) (UNVERIFIED: no cross-engine Solr DLS guarantee exists to cite.)

### Projection, field-level, and sort surfaces

- **Solr `fl`** limits response fields but accepts any `stored="true"` or `docValues="true"` field, globs (`na*`), functions (`product(price,popularity)`), pseudo-fields (`score`), document transformers (`[explain]`), and aliases (`sales_price:price`, `why_score:[explain style=nl]`). A server-side "hide this column" default `fl` means nothing while the schema still exposes the field; `[explain]` additionally returns score internals usable as an index oracle. [T1 Solr]
- **Solr `sort`** works on any single-valued docValues/indexed field independent of `fl`, so a client that can sort by a field it cannot see has an ordering oracle over that field; `fq` is the Solr filter seam and its caches are independent of the main query. [T1 Solr]
- **Elasticsearch**: field-level authorization is FLS, not response shaping (`_source` filtering and `fields` only select what the read API returns); FLS restrictions appear as if the field does not exist. When auditing a role, remember that FLS with `except` must be a subset of `grant`, and that union across roles can widen what a single role appears to deny. [T1 Elastic]
- **PostgREST** vertical filtering: `select` defaults to `*`, supports renaming, nested JSON/array paths (`json_data->>blood_type`), composite fields (`location->>lat`), array indexes (`languages->0`), and casts (`col::type`); the same paths work in `order=` and filters. Column authorization is the column-scoped `GRANT`/`REVOKE`, since RLS constrains rows only. [T1 PostgREST]
- **MongoDB/Prisma**: `findRaw` accepts an `options.projection` passthrough; `aggregateRaw` accepts a full pipeline, so projection and aggregation semantics are decided by the app-passed JSON, not by the ORM model. [T1 Prisma]

### Fingerprinting before choosing a payload

1. Identify the ORM/query builder/ODS from errors, headers, and response shape; map it to the section above before probing.
2. Find the list-scoping seam (`get_queryset`/`default_scope`/filter class) and confirm whether it also feeds count, facet, detail, and export views.
3. Detect the query surface: JSON body vs bracketed URL params (NoSQL), batched arrays vs single operation (GraphQL), DSL body vs `q`/`fq` strings (search engines), query-string operators (`or=`, `not.`, `->>`) versus JSON (PostgREST).
4. Confirm which representations exist for one dataset (list, detail, export, preview, GraphQL, search) and diff them before moving to the next record.
5. Note whether sparse fieldsets, `select`, `fields`, `fl`, or `expand` parameters exist and whether they pass through the same authorization seam; then test sort-by-hidden-field and cursor tampering.
6. For search engines, check whether DLS/FLS exist at all (role API), whether multiple roles combine to widen access, and whether the application queries the engine with a service/admin credential that bypasses the engine's own scope.

## References

- [T1 vendor] Django REST framework — permissions (object-level `has_object_permission`, list/create limits, access-restriction matrix, `DjangoObjectPermissions`/Filter): https://www.django-rest-framework.org/api-guide/permissions/
- [T1 vendor] Django docs — Performing raw SQL queries (`raw()` field mapping, `connection.cursor()`, `params`, MySQL type coercion): https://docs.djangoproject.com/en/5.1/topics/db/sql/
- [T1 vendor] Django security releases 3.2.5 / 3.1.13 — CVE-2021-35042, SQL injection via unsanitized `QuerySet.order_by()` input: https://www.djangoproject.com/weblog/2021/jul/01/security-releases/
- [T1 vendor] Ruby on Rails Security Guide (SQLi, `deep_munge` shape table, CVE-2012-2660/2694, CVE-2013-0155, default `nosniff`): https://guides.rubyonrails.org/security.html
- [T1 vendor] Prisma — Raw queries (tagged-template `$queryRaw` vs `$queryRawUnsafe`/`$executeRawUnsafe`, `Prisma.raw` injection paths, `findRaw`/`aggregateRaw`/`$runCommandRaw`): https://www.prisma.io/docs/orm/prisma-client/using-raw-sql/raw-queries
- [T1 vendor] PostgREST — Tables and Views (horizontal/vertical filtering, `or=`/`not.`/`any`/`all`, JSON paths, casts, `order`, `columns`, limited update/delete): https://docs.postgrest.org/en/v12/references/api/tables_views.html
- [T1 vendor] PostgREST — Database Authorization (roles, RLS `USING`/`WITH CHECK`, column-scoped `GRANT`, `SECURITY DEFINER`, views bypassing RLS / `security_invoker`): https://docs.postgrest.org/en/v12/explanations/db_authz.html
- [T1 vendor] MySQL Reference Manual — Type Conversion in Expression Evaluation (`c3 = 0` coercion, strict-mode non-application to SELECT, float rounding, index loss): https://dev.mysql.com/doc/refman/8.4/en/type-conversion.html
- [T1 vendor] PostgreSQL — Collation Support (deterministic vs nondeterministic collations, ICU levels, `und-u-ks-level2`, pattern-matching limits): https://www.postgresql.org/docs/current/collation.html
- [T1 vendor] MongoDB manual — `$function` (server-side scripting enablement/disablement, 8.0 deprecation, MozJS-91, `$expr` alternative): https://www.mongodb.com/docs/manual/reference/operator/aggregation/function/
- [T1 vendor] MongoDB manual — `$accumulator` (JS enablement, `merge`/`allowDiskUse`, non-guaranteed document processing order): https://www.mongodb.com/docs/manual/reference/operator/aggregation/accumulator/
- [T1 vendor] MongoDB manual — Collation (strength levels, `locale:"simple"`, views not inheriting collection collation, binary document keys, text/2d index restriction): https://www.mongodb.com/docs/manual/reference/collation/
- [T1 vendor] Elastic — Controlling access at the document and field level (DLS/FLS semantics, multi-role OR/union, metadata fields, alias caution, limitations incl. aggregate info leak, write/API coupling): https://www.elastic.co/docs/deploy-manage/users-roles/cluster-or-deployment-auth/controlling-access-at-document-field-level
- [T1 vendor] Elastic — Paginate search results (`from`+`size` 10,000 window, `search_after` requirements, PIT/`_shard_doc`, scroll context limit): https://www.elastic.co/docs/reference/elasticsearch/rest-apis/paginate-search-results
- [T1 vendor] Elastic — The `_search` API (`track_total_hits` default 10,000, `relation: gte/eq`, `terminate_after` existence check): https://www.elastic.co/docs/solutions/search/the-search-api
- [T1 vendor] Elastic — Cardinality aggregation (HyperLogLog++, `precision_threshold` 3000 default / 40000 max, error characteristics): https://www.elastic.co/docs/reference/aggregations/search-aggregations-metrics-cardinality-aggregation
- [T1 vendor] Elastic — Terms aggregation (`size`, `shard_size`, `doc_count_error_upper_bound`, `sum_other_doc_count`, ordering accuracy notes): https://www.elastic.co/docs/reference/aggregations/search-aggregations-bucket-terms-aggregation
- [T1 vendor] OpenSearch — Document-level security (read-only scope, no write restriction, multi-role `dfm_empty_overrides_all`, analyzer warning, parameter substitution/fallbacks, evaluation modes, 1024 KB limit): https://docs.opensearch.org/latest/security/access-control/document-level-security/
- [T1 vendor] Solr Reference Guide — Pagination of Results (`start`/`rows` deep-paging cost, `cursorMark` constraints, uniqueKey sort, replica/score and `NOW` caveats, `partialResults`): https://solr.apache.org/guide/solr/latest/query-guide/pagination-of-results.html
- [T1 vendor] Solr Reference Guide — Common Query Parameters (`fl` field list/globs/functions/transformers/aliases, `sort` requirements, `fq`, `minExactCount`/`numFoundExact`, `partialResults`): https://solr.apache.org/guide/solr/latest/query-guide/common-query-parameters.html
- [T1 vendor] Hasura — Configuring Permission Rules (GraphQL request compiled to a single SQL query with permission constraints; table/role/operation granularity; row expressions and column selections; session variables): https://hasura.io/docs/2.0/auth/authorization/permissions/
- [T0 spec] Relay — GraphQL Cursor Connections Specification (opaque cursors, consistent ordering across `first/after` and `last/before`, `PageInfo`): https://relay.dev/graphql/connections.htm
- [T1 vendor] OWASP GraphQL Cheat Sheet (edges+node authz, `node`/`nodes`, batching attacks, depth/amount examples, introspection/suggestions): https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- [T2 research] PortSwigger Web Security Academy — NoSQL injection (syntax vs operator, fuzz string, `$ne`/`$where`/`$regex`, null-byte truncation, JSON switch): https://portswigger.net/web-security/nosql-injection
- [T1 vendor] MongoDB manual — Query Predicates / operator reference (`$expr`, `$jsonSchema`, `$where`, `$elemMatch`, `$type`): https://www.mongodb.com/docs/manual/reference/mql/query-predicates/
- [T3 vuln intel] CVE-2012-2660 / CVE-2012-2694 / CVE-2013-0155 (Rails `deep_munge` parameter → `IS NULL` query bypass), linked from the Rails Security Guide
- [T3 vuln intel] CVE-2021-35042 (Django `QuerySet.order_by()` SQL injection), linked from the Django 3.2.5/3.1.13 release note
- [T2 research] HackerOne report 489146 (GraphQL nodes lacked authorization while edges were checked), linked from the OWASP GraphQL Cheat Sheet
- [T0 standards] OWASP Cheat Sheet Series (Authorization, Input Validation) and OWASP API Security Top 10 (BOLA/BFLA, excessive data exposure): https://cheatsheetseries.owasp.org ; https://owasp.org/API-Security/
- [T1 vendor] Framework ORM and query-builder authorization documentation for the fingerprinted stack, checked per engagement
- [T1 vendor] Database engine documentation for the observed store (query operators, raw-query guards, aggregation semantics, collation comparison rules)
- [T1 vendor] GraphQL authorization guidance for resolver-level checks, batching, and nested-edge scoping: https://graphql.org/learn/authorization/
- parsers-injection/parsers.md for canonical SQL, NoSQL, SSTI, and XXE injection detail referenced by this pack
