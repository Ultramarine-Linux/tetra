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
| `secret` | `String` | Masked input; value is not logged. |
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
- `generate` — Auto-generation strategy when no value and no default exist. Only `random_32` is supported today (useful for passwords/keys).
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
Image=docker.io/library/nextcloud:latest
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
agent `recipes.render_inline` and `recipes.context_inline` actions accept:

- `recipe` — the full recipe YAML as a string.
- `templates` — a map of template name → template body.
- `values` — the parameter value map.

This lets a remote catalog publish new recipes without updating Tetra, as long
as the recipe schema is one the agent understands.

## Packaging notes

- Keep template paths relative so the same recipe works with `--templates-dir`
  in development and in production deployments.
- Use `file` resources for companion content (nginx configs, static HTML) and
  install them via the `quadlets.install.files` agent action.
- `requires` is metadata for the dashboard/catalog; the renderer itself does
  not verify that Podman or Quadlets are installed.
