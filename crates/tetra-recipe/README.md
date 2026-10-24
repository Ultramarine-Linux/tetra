# tetra-recipe

The recipe model behind [Tetra](../../README.md): the recipe schema, parameter
validation and Tera rendering, the template bundle digest (`bundle_sha256`)
and the rendered image policy (`verify_images`). Tetra re-exports it as
`tetra::catalog`.

The recipes repository tooling (`Ultramarine-Server/recipes`) depends on this
crate so catalogs are checked by exactly the code that installs them, without
pulling in Tetra's host-agent dependencies. It is the single source of truth
for recipe schema, validation, digest and image policy: change those here, not
in a copy.

See [`docs/recipes.md`](../../docs/recipes.md) for the recipe format.
