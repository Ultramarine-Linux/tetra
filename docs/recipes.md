# Recipe Authoring Guide

Recipes are YAML documents that declare how to render a host application into
Podman Quadlet units and companion files. The Ultramarine Server dashboard uses
recipes to let users install and configure apps without touching a terminal.

This guide covers the recipe schema, how templates work, and how to test your
recipes locally.

## Recipe schema overview

A recipe has three top-level sections:

| Section | Purpose |
|---------|---------|
| `recipe_id`, `name`, `description`, `category`, `icon`, `version` | Metadata shown by the dashboard/catalog. |
| `requires` | Host capabilities the recipe expects (e.g. `podman`, `quadlets`). Declarative only — not enforced at render time. |
| `parameters` | User-facing inputs that become template variables. |
| `resources` | Files to render (Quadlet units and companion files). |

### Minimal example

```yaml
recipe_id: demo-app
name: Demo App
description: A minimal example application
category: web
icon: demo
version: 1.0.0

requires:
  - podman
  - quadlets

parameters:
  - key: app_id
    label: App ID
    type: string
    required: true
    default: demo-app

resources:
  - type: container
    filename: "{{ app_id }}.container"
    template: containers/demo.container.tera
```

## Parameters

Each parameter becomes a variable in the Tera template context. Parameter `key`
must be unique within the recipe.

### Supported types

| YAML `type` | Rust type | Dashboard behavior |
|-------------|-----------|-------------------|
| `string` | `String` | Free-form text input. |
| `secret` | `String` | Masked input; value is not logged, and `apps.get` shows it as `********`. |
| `integer` | `i64` | Numeric input with optional `min`/`max`. |
| `boolean` | `bool` | Toggle/checkbox. |
| `choice` | `String` | Dropdown; requires `options` list. |

### Parameter fields

```yaml
parameters:
  - key: domain
    label: Domain name
    type: string
    required: true
    placeholder: cloud.example.com

  - key: host_port
    label: Host port
    type: integer
    required: true
    default: 8080
    min: 1
    max: 65535

  - key: enable_redis
    label: Enable Redis caching
    type: boolean
    default: true

  - key: protocol
    label: Public protocol
    type: choice
    required: true
    default: https
    options:
      - https
      - http

  - key: db_password
    label: Database password
    type: secret
    required: true
    generate: random_32
```

**Field reference**

- `key` — Template variable name (e.g. `{{ domain }}`). Unique within a recipe.
- `label` — Human-readable label shown in the dashboard.
- `type` — One of the supported types above.
- `required` — Whether a value must be provided. Defaults to `false`.
- `placeholder` — Optional hint text for empty inputs.
- `default` — Value used when the operator does not supply one.
- `min` / `max` — Inclusive bounds for `integer` parameters.
- `generate` — Auto-generation strategy when no value and no default exist. Only `random_32` is supported today (useful for passwords/keys). When an app is installed with `apps.create`, the generated value is stored in the app's manifest, so `apps.update` reuses it instead of generating a new one.
- `options` — Required for `choice`; list of allowed strings.

### Value resolution order

When a recipe is rendered, each parameter is resolved in this priority:

1. Explicit value from the operator (`values.yaml` or dashboard form).
2. Recipe-declared `default`.
3. Parameter `generate` strategy (e.g. `random_32`).
4. If `required: true` and none of the above, rendering fails with a clear error.
5. Otherwise, `Null` (templates can use Tera's `default` filter).

## Resources

Resources are the files Tetra produces from a recipe. Each resource declares a
`type`, output `filename`, source `template`, and optional `condition` and
`depends_on`.

### Resource types

| `type` | Output extension | Typical use |
|--------|------------------|-------------|
| `container` | `.container` | Podman container Quadlet unit. |
| `image` | `.image` | Digest-pinned image pull Quadlet unit. |
| `network` | `.network` | Podman network Quadlet unit. |
| `volume` | `.volume` | Podman volume Quadlet unit. |
| `pod` | `.pod` | Podman pod Quadlet unit. |
| `kube` | `.kube` | Podman kube Quadlet unit. |
| `file` | (none) | Companion file (e.g. `index.html`, nginx config). |

### Resource fields

```yaml
resources:
  - type: container
    filename: "{{ app_id }}.container"
    template: containers/app.container.tera
    depends_on:
      - "{{ app_id }}-db.container"

  - type: container
    filename: "{{ app_id }}-redis.container"
    template: containers/redis.container.tera
    condition: "enable_redis == true"
```

- `filename` — Rendered through Tera; can embed parameter values.
- `template` — Path relative to `templates_dir` (disk) or key in inline bundle.
- `condition` — Optional predicate string. Supported operators: `==`, `!=`, `<`, `>`, `<=`, `>=`. The right-hand side is parsed as a string, boolean, integer, or null literal. Resources whose condition does not hold are skipped.
- `depends_on` — Metadata for dashboards; not enforced by the renderer.

### Conditional resources

Use `condition` to make resources optional based on a parameter value:

```yaml
parameters:
  - key: enable_redis
    label: Enable Redis caching
    type: boolean
    default: true

resources:
  - type: container
    filename: "{{ app_id }}-redis.container"
    template: containers/redis.container.tera
    condition: "enable_redis == true"
```

## Templates

Resources are produced by rendering [Tera](https://keats.github.io/tera/docs/)
templates. Tetra provides a two-pass render context:

1. **Base context** — used to render `filename`:
   - `recipe_id`
   - `name`
   - `version`
   - `recipe` (full recipe metadata object)
   - Every parameter `key`

2. **Enriched context** — used to render the template body:
   - All base context keys
   - `resource` — the full resource declaration
   - `resource_filename` — the already-rendered filename
   - `resource_name` — the unit basename (filename without the Quadlet extension)

### Example template: container unit

```ini
[Unit]
Description={{ name }} application
Requires={{ app_id }}-db.service
After={{ app_id }}-db.service
{% if enable_redis %}Wants={{ app_id }}-redis.service
After={{ app_id }}-redis.service
{% endif %}

[Container]
ContainerName={{ app_id }}-app
Image=docker.io/library/nextcloud:latest@sha256:301e07b7f661c122752cc2c01b76f15036a156f2b6d794c76621b7d0a6bb8a50
Network={{ app_id }}-net.network
{% if trusted_proxies %}Environment=TRUSTED_PROXIES={{ trusted_proxies }}
{% endif %}
PublishPort={{ host_port }}:80

[Service]
Restart=always

[Install]
WantedBy=default.target
```

### Example template: volume unit

```ini
[Volume]
VolumeName={{ resource_name }}
```

Notice `resource_name` resolves to the filename without the `.volume`
extension — this makes cross-unit references consistent.

## Testing recipes locally

### Render to disk

```sh
cargo run -- render my-recipe.yaml \
  --templates-dir ./templates \
  --values my-values.yaml \
  --output-dir ./quadlets
```

### Dry-run preview

```sh
cargo run -- render my-recipe.yaml \
  --templates-dir ./templates \
  --values my-values.yaml \
  --dry-run
```

### Values file format

`values.yaml` is a simple YAML map:

```yaml
domain: cloud.example.com
enable_redis: true
host_port: 8081
```

### Validation errors

Tetra validates recipes before rendering. Common issues:

- Missing or empty `recipe_id`, `name`, or `version`.
- Duplicate parameter `key` values.
- `choice` parameter without `options`.
- Missing required parameter values.
- Template file not found under `templates_dir`.

## Inline recipes (agent protocol)

The dashboard can ship recipes without installing them on the host first. The
agent `recipes.render_inline` and `recipes.context_inline` actions (and
`apps.create`) accept:

- `recipe` — the full recipe YAML as a string.
- `templates` — a map of template name → template body (not used by
  `context_inline`).
- `values` — the parameter value map.

This lets a remote catalog publish new recipes without updating Tetra, as long
as the recipe schema is one the agent understands.

## Install-time source verification and image pinning

`apps.create/update` and `recipes.render/render_inline` accept
`source: {catalog: "official"|"community"|"custom", url?, sha256}` and
`allow_unpinned_images` (default false). `sha256` is 64 hex characters without a
prefix. Supplied digests must match even for custom recipes. Omitted source means
custom, **not** permission to use mutable tags. Official/community opt-out is an
error. Verification happens before output/install writes, even in dry runs.
Context-only actions and the CLI pure renderer do not enforce this install policy.
Tetra never fetches catalogs, recipe URLs, or registry metadata.

### Canonical bundle digest (v1)

SHA-256 covers this byte stream:

1. ASCII `tetra-recipe-bundle-v1` followed by one NUL byte.
2. Recipe byte length (unsigned 64-bit big-endian), then exact UTF-8 recipe bytes.
3. Template count (unsigned 64-bit big-endian).
4. Templates in ascending UTF-8 name byte order: name byte length (u64 BE), exact
   name bytes, body byte length (u64 BE), exact body bytes.

No YAML reserialization, newline conversion, whitespace trimming, or Unicode
normalization. Values, catalog classification, and URL are excluded. Inline
bundles include **all** supplied templates, even unused entries. Disk bundles
include unique `resources[].template` names, including conditional resources;
paths must resolve under `templates_dir` without symlinks. Unreferenced disk files
are excluded. Disk recipes/templates are snapshotted once; verification and
rendering use the same bytes. Apps store that inline snapshot, so later updates
never silently follow disk edits. Rust callers can use
`catalog::verification::bundle_sha256` to compute the digest.

This verifies integrity against the caller's expected digest, **not** publisher
identity: official/community are caller-supplied claims. The dashboard must
obtain the expected digest through a trusted catalog channel. `url` is audit
metadata, not a fetching instruction or signature.

### Rendered image policy

Every `Image=` in container/image/image-backed-volume units must end in
`@sha256:<64 hex>`. Repeated directives and systemd continuations are checked.
`.image` is also available as recipe resource type `image`. `ImageTag=` aliases
are not image pulls; consumers must still use a digest. References such as
`Image=foo.image` or `foo.build` are refused; use registry digests directly.
Container/image units must have an Image directive.

Kube units require `Yaml=` naming a companion `file` resource by its absolute
path in the app's bundle directory, spelled plainly (no `..`, `%` specifiers or
quotes): declare a `bundle_dir` parameter and write
`Yaml={{ bundle_dir }}/kube/pod.yaml`. Quadlet resolves a relative `Yaml=`
against the unit's own directory (the Quadlet scan directory, see
[`quadlet.go`](https://github.com/containers/podman/blob/v5.6.0/pkg/systemd/quadlet/quadlet.go)),
not the bundle, so a relative path would name a file that was never checked.
`apps.create`/`update` check against the real bundle directory (a
caller-supplied `bundle_dir` elsewhere fails); `recipes.render`/`render_inline`
against the `bundle_dir` the recipe renders with, and refuse pinned kube units
without one. All YAML documents are parsed and every `image` key is checked,
matched case-insensitively as Podman's decoder does (`Image:` counts), including
containers, initContainers, and ephemeralContainers. External YAML paths/URLs
are refused. Raw `PodmanArgs`/`GlobalArgs`, image mounts, `Exec*=` commands in
a unit's `[Service]` section (`ExecStartPre=podman pull ...` runs anything),
build units, and pod units (implicit infra-image pulls) are unsupported by the
pinned policy and require the explicit custom-only opt-out. This is an image policy, not a sandbox
for arbitrary host configuration in administrator-supplied recipes.
See [Quadlet documentation](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html).

Bundled nginx:alpine, mariadb:11, nextcloud:latest, and redis:7-alpine use
multi-platform index digests retrieved using `skopeo inspect --raw` on
2026-10-23. Tags are retained for humans; Podman accepts `tag@digest` and pulls
the digest (verified with `podman pull` for bundled nginx). Refresh these pins
deliberately when updating templates; installation never resolves tags.

`AppManifest.source` stores verified provenance with the computed lowercase
digest; `allow_unpinned_images` records the policy. Old manifests load with no
source and pinning enabled. On update, omitted fields retain existing provenance
and policy when reusing the recipe. A replacement recipe without source becomes
custom and resets the opt-out to false unless explicitly requested. Every update
rechecks the stored/replacement bundle and newly rendered images.

## Packaging notes

- Keep template paths relative so the same recipe works with `--templates-dir`
  in development and in production deployments.
- Use `file` resources for companion content (nginx configs, static HTML) and
  install them via the `quadlets.install.files` agent action.
- Bind-mount companion *subdirectories* of the bundle, never the bundle itself:
  `apps` keeps `app.json` (the app's values, secrets included) at the bundle
  root. The shipped `nginx-site` recipe puts content in `site/` and its nginx
  config in `conf/`, and mounts `Volume={{ bundle_dir }}/site:/usr/share/nginx/html:ro,z`.
  Use `,z` (shared `container_file_t`), not `,Z`: the bundle belongs to the
  apps account, so rootless Podman may relabel it, but Tetra rewrites its
  files on every update and `,Z`'s per-container MCS categories would be
  relabeled recursively on every start without isolating anything (all apps
  share the account, and the content is public anyway).
- In apps scope (rootless), `apps.create`/`update` refuse a `PublishPort=`
  whose host port is below the host's `net.ipv4.ip_unprivileged_port_start`
  (1024 by default), whatever the parameter's `min`; system scope binds any
  port. Keep `min: 1` for recipes meant for both scopes.
- `requires` is metadata for the dashboard/catalog; the renderer itself does
  not verify that Podman or Quadlets are installed.
