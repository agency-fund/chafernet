# Contributing

Thank you for considering contributing to chafernet.

We do not accept PRs without advance discussion. If you'd like to report a bug or implement a feature, please create an
issue.

The repository is a Cargo workspace with two crates, `chafernet` (the library) and `python` (the extension module,
built with [maturin](https://www.maturin.rs/)), and the Python package in `python/chafernet`.

## Day-to-day development

Your environment will need:

* [Task](https://taskfile.dev): Our Taskfile defines development and CI scripts.
* [uv](https://docs.astral.sh/uv/)
* Rust toolchain per `rust-toolchain.toml` pins
* [changie](https://changie.dev)
* [wasmtime](https://wasmtime.dev/)

| Task                 | What it does                                                                           |
|----------------------|----------------------------------------------------------------------------------------|
| `task setup`         | Creates `.venv` with the development tools; `PYTHON=3.15t` picks another interpreter   |
| `task build`         | Builds the extension into `.venv` in release mode                                      |
| `task build:debug`   | The same, with debug assertions                                                        |
| `task test`          | Runs every test: Rust, natively and on WebAssembly, then Python on a fresh debug build |
| `task coverage`      | Measures coverage into `coverage/`; run `task build` afterwards                        |
| `task lint`          | Runs everything CI's `lint` job runs                                                   |
| `task fmt`           | Formats the Rust, Python, and Markdown files                                           |
| `task msrv`          | Checks the build with the minimum supported Rust version                               |
| `task readme`        | Regenerates the READMEs and the crate docs from `gendocs/`                             |
| `task stubs`         | Regenerates the type stub `python/chafernet/_chafernet.pyi` from the Rust source       |
| `task changelog:new` | Adds a changelog fragment under `.changes/unreleased/`                                 |

External contributors should follow the
[standard forking workflow](https://docs.github.com/en/get-started/exploring-projects-on-github/contributing-to-a-project).
Include a changelog entry (via `task changelog:new`) if your change would result in user-visible changes. See
[good changelog entries](https://docs.gitlab.com/ee/development/changelog.html#writing-good-changelog-entries) for
writing tips.

## Documentation

* The READMEs, `chafernet/src/crate-docs.md`, and the type stub are generated: edit the templates in `gendocs/` or the
  Rust source, then run `task readme` or `task stubs`. `tools/gen_readmes.py` documents what a template can use.
* Use the conditional templating to ensure your edits are readable and beautiful in both rustdoc and GitHub Markdown.
* Every change a user would notice should add a changelog fragment.

## Releasing

The version of the crate and the Python package is defined in `Cargo.toml`.

There are four steps to a release:

1. **By hand**, on your machine, you prepare the release:
    1. bump the version and assemble the changelog with `changelog:batch`. run `task changelog:batch -- X.Y.Z`, where
       X.Y.Z is the
       number of the new version being released, or `patch`, `minor`, or `major`, or `auto` if you are brave. The
       first release needs the number.
    1. review the generated `.changes/X.Y.Z.md` file and make changes as necessary. This becomes the release notes
       visible on the GitHub release. If you make changes, run `changelog:merge`.
    1. Run `release:tag` to update the version numbers in the configs, create the tag, runs some lints, and commits. If
       this fails, you can undo it with `git tag -d vX.Y.Z && git reset --soft HEAD~1`.
    1. Run the `git push` command that `release:tag` prints. Only a repository admin can push a `v*` tag, and a pushed
       tag can't be moved or deleted, so this is the last point at which the release can be undone.
2. GitHub Actions creates a draft release: the tag triggers `.github/workflows/ci.yml` to run tests, build and test the
   wheels, run some sanity check, attest and hash the release artifacts and create a draft GitHub release.
3. **By hand**, you vet the draft release on GitHub and then publish it. A published release is immutable: its files
   and its tag can't change.
4. GitHub Actions (`.github/workflows/publish.yml`) is triggered by publishing the release, checks that CI built the
   files from the tag, and uploads them to PyPI and crates.io. While the repository is public, each upload first waits
   for one of the approvers named in `.github/tf/gh.tf` to approve it on the run's page.

| Task                            | What it does                                                                       |
|---------------------------------|------------------------------------------------------------------------------------|
| `task changelog:batch -- X.Y.Z` | Rolls the fragments into `.changes/X.Y.Z.md`, for the new version X.Y.Z            |
| `task changelog:merge`          | Regenerates `CHANGELOG.md` after editing a file in `.changes/`                     |
| `task release:tag`              | Sets the batched version, runs `task lint test`, then commits and tags the release |

The tasks `release:preflight`, `release:draft`, and `ci:publish:crate` are the workflows' steps; they are not run by
hand.

### When something goes wrong

* If the tag's run fails for a reason outside the code, such as a runner or a network fault, re-run it
  (`gh run rerun --failed`); the draft is made once every job has passed.
* If the fix needs a commit, that version is spent, because its tag can't be moved. Delete the draft release if there
  is one (`gh release delete vX.Y.Z`), fix the cause, and release the next patch version:
    1. Run `task changelog:batch -- patch`.
    1. Move the notes from the failed version's `.changes/X.Y.Z.md` into the new version's file, delete the old file,
       and run `task changelog:merge`.
    1. Continue with `release:tag` as usual.
* If publishing fails partway, re-run the failed job (`gh run rerun --failed`): each step skips what the registry
  already has.

## Adding or removing platform targets

| Task                     | What it does                                                                             |
|--------------------------|------------------------------------------------------------------------------------------|
| `task sdist`             | Builds the source distribution into `dist/`                                              |
| `task release:test`      | Installs from `dist/` into a fresh venv for each Python in `PYTHONS` and runs the tests  |
| `task release:test:musl` | Runs the tests on the musllinux wheel in `dist/` inside Alpine; needs Docker             |
| `task test:wasm`         | Builds for `wasm32-unknown-unknown` and runs the Rust tests on `wasm32-wasip2`           |
| `task msrv`              | Checks the build with the minimum supported Rust version                                 |

The supported platforms are defined in several places and all must agree:

* **Wheel platforms:** the `wheels` matrix in `.github/workflows/ci.yml`.
* **Python versions:** the `project.classifiers` list and `requires-python` in `pyproject.toml` (the READMEs take the
  versions from there); the `test` matrix and the `wheels` job in `ci.yml`, which names the versions in several steps;
  and the default `PYTHONS` of `release:test:musl` in `Taskfile.yml`. `PYTHON` in `Taskfile.yml` is the oldest supported
  version, which the type stub is generated with.
* **WebAssembly targets:** the `test:wasm` task and the `wasm` job in `ci.yml`.
* **Rust versions:** `rust-toolchain.toml` for the pinned version, which CI installs from that file, and `rust-version`
  in `Cargo.toml` for the minimum one, which `task msrv` reads.

A push to main builds the wheels only when a file that builds them changes. Pull requests, tags, and manual runs
(`gh workflow run ci.yml`) build and test every target, so use one of those to check a change to the targets.

## Supply chain

We use `cargo audit` and `cargo vet` for supply chain security (`cargo install cargo-audit cargo-vet --locked`).

`.github/workflows/supply-chain.yml` runs both on every change and weekly.

The repository only runs GitHub's own actions and the ones listed in `.github/tf/gh.tf`, each pinned to a full commit
SHA. To use a new action in a workflow, add it to `patterns_allowed` there and run `task gh:apply`.

```sh
cargo audit                     # fix by bumping (cargo update -p <crate>) or dropping the crate
cargo vet                       # lists the crates that need attention
cargo vet suggest               # what to review, and the smallest diff that covers it
cargo vet certify <crate> <ver> # after reading it; or `cargo vet add-exemption` to defer
```

* `supply-chain/config.toml` imports the audits from reputable sources (e.g. Google, Mozilla, etc).
* `supply-chain/audits.toml` trusts the publishers of the RustCrypto crates. Renew publisher trust with
  `cargo vet trust --all <publisher> --allow-multiple-publishers` renews them.
