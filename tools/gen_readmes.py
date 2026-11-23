#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.14"
# dependencies = [
#     "minijinja==3.1.0",
#     # The same version as the rumdl-pre-commit hook in prek.toml, so that both format the READMEs alike.
#     "rumdl==0.3.2",
#     "typer>=0.20",
# ]
# ///
"""Generates the READMEs and the crate docs from the MiniJinja templates in gendocs/.

Run `task readme` (or this script) after editing a template; `--check` only reports the outputs that are out of date.
Each output is formatted with rumdl and the repository's .rumdl.toml, so that the rumdl prek hooks leave it as generated.

OUTPUTS names the template and the target of each generated file. The templates include gendocs/frontmatter.md and
gendocs/footer.md, and can use:

* `target`: "github" for the READMEs or "rustdoc" for the crate docs, so `{% if target == "rustdoc" %}` marks text for
  one of them.
* `{{ api("PATH") }}` or `{{ api("PATH", "TEXT") }}`: a code span in the READMEs and an intra-doc link in the crate docs.
* `{{ repo_link("TEXT", "PATH") }}`: a relative link in the root README, where it resolves, and plain text in the
  others, which crates.io, PyPI, and docs.rs show outside the repository.
* `rust_version`, `repository`, and `license`, from Cargo.toml, and `python_versions`, from pyproject.toml's version
  classifiers, which must start at requires-python.

GitHub alerts (`> [!TIP]`) become rustdoc-friendly blocks in the crate docs.
"""

import re
import subprocess
import sysconfig
import tomllib
from pathlib import Path
from typing import Annotated

import minijinja
import typer

ROOT = Path(__file__).resolve().parent.parent

OUTPUTS = {
    "README.md": ("readme.tpl.md", "github"),
    "chafernet/README.md": ("rust.tpl.md", "github"),
    "python/README.md": ("python.tpl.md", "github"),
    "chafernet/src/crate-docs.md": ("rust.tpl.md", "rustdoc"),
}

RUMDL = Path(sysconfig.get_path("scripts")) / "rumdl"

ALERT = re.compile(r"^> \[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\n((?:>.*\n?)+)", re.MULTILINE)


def config() -> dict[str, str]:
    """The facts the templates share with Cargo.toml and pyproject.toml, so that they are stated once."""
    package = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    # The supported Pythons are the versions the classifiers name, the first of which requires-python must require.
    versions = [
        m.group(1)
        for c in project["classifiers"]
        if (m := re.fullmatch(r"Programming Language :: Python :: (3\.\d+)", c))
    ]
    if not versions or project["requires-python"] != f">={versions[0]}":
        raise SystemExit(f"pyproject.toml: requires-python is not >= the first Python classifier ({versions})")
    return {
        "rust_version": package["rust-version"],
        "repository": package["repository"],
        "license": package["license"],
        "python_versions": " and ".join([", ".join(versions[:-1]), versions[-1]] if len(versions) > 1 else versions),
    }


def render(template: str, target: str, output: str) -> str:
    """The template rendered for target, in which api() is a code span ("github") or an intra-doc link ("rustdoc"),
    and repo_link() is a relative link only in the root README: the others are also shown outside the repository, by
    crates.io, PyPI, and docs.rs, where a path in it does not resolve."""

    def repo_link(text: str, path: str) -> str:
        return f"[{text}]({path})" if output == "README.md" else text

    def api(path: str, text: str | None = None) -> str:
        text = text or path
        if target == "github":
            return f"`{text}`"
        return f"[`{text}`]" if text == path else f"[`{text}`]({path.removesuffix('()')})"

    env = minijinja.Environment(
        loader=minijinja.load_from_path(ROOT / "gendocs"),
        globals={"target": target, "api": api, "repo_link": repo_link, **config()},
        undefined_behavior="strict",
        trim_blocks=True,
        lstrip_blocks=True,
        # An included fragment keeps its last newline, which separates it from what follows.
        keep_trailing_newline=True,
    )
    return env.render_template(template)


def rustdoc_alerts(text: str) -> str:
    """GitHub alerts, which rustdoc shows as quotes beginning with the marker, as a quote with a bold label, or for the
    serious kinds, rustdoc's warning block."""

    def alert(match: re.Match[str]) -> str:
        kind, body = match.group(1), re.sub(r"^> ?", "", match.group(2).rstrip("\n"), flags=re.MULTILINE)
        labelled = f"**{kind.capitalize()}:** {body}"
        if kind in ("IMPORTANT", "WARNING", "CAUTION"):
            return f'<div class="warning">\n\n{labelled}\n\n</div>\n'
        return re.sub(r"^", "> ", labelled, flags=re.MULTILINE) + "\n"

    return ALERT.sub(alert, text)


def rumdl_fmt(text: str, path: str) -> str:
    """The Markdown text formatted by rumdl as the file at path (relative to the root) would be. normalize rewraps every
    paragraph, so that the output's lines don't depend on where the template's, with their placeholders, break."""
    config = ["--config", ROOT / ".rumdl.toml", "--config", 'MD013.reflow-mode = "normalize"']
    command = [RUMDL, "fmt", "--silent", *config, "--stdin-filename", path, "-"]
    try:
        return subprocess.run(command, input=text, capture_output=True, text=True, check=True, cwd=ROOT).stdout
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"{path}: rumdl fmt failed:\n{error.stderr}") from None


def generate() -> dict[str, str]:
    """The contents of every generated file, by path."""
    outputs = {}
    for output, (template, target) in OUTPUTS.items():
        try:
            body = render(template, target, output)
        except minijinja.TemplateError as error:
            raise SystemExit(f"gendocs/{template}: {error}") from None
        if target == "rustdoc":
            body = rustdoc_alerts(body)
        header = f"<!-- Generated from gendocs/{template} by tools/gen_readmes.py; edit the template and run `task readme`. -->\n"
        outputs[output] = rumdl_fmt(header + body.strip("\n") + "\n", output)
    return outputs


def main(
    check: Annotated[bool, typer.Option("--check", help="Write nothing; exit 1 if a README is out of date.")] = False,
) -> None:
    stale = []
    for output, text in generate().items():
        path = ROOT / output
        if path.exists() and path.read_text() == text:
            continue
        stale.append(output)
        if not check:
            path.write_text(text)
    for output in stale:
        typer.echo(f"{output} is out of date; run `task readme`" if check else f"wrote {output}", err=check)
    if check and stale:
        raise typer.Exit(1)


if __name__ == "__main__":
    typer.run(main)
