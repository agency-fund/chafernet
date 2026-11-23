# The GitHub repository's settings, among them those that protect the release pipeline (see "Releasing" in
# CONTRIBUTING.md), for OpenTofu. The repository must already exist. `task gh:plan` shows what would change and
# `task gh:apply` changes it.
#
# The state and the variables live outside the repository, in the directory the Taskfile calls TF_DIR, which is
# tf/chafernet beside the checkout unless TF_DIR says otherwise: the state in terraform.tfstate there, and the three
# variables below in terraform.tfvars there. `task gh:init` records where the state is.
#
# The provider signs in with GITHUB_TOKEN, or with the `gh` CLI's login when that is unset; the account must be a
# repository admin.
#
# What these settings can't cover, because it is outside GitHub:
# * PyPI: a pending trusted publisher for publish.yml and the pypi environment; no API tokens.
# * crates.io: after the first release, a trusted publisher for publish.yml and the crates-io environment, "require
#   trusted publishing" turned on, and the bootstrap token and the CRATES_IO_BOOTSTRAP_TOKEN secret deleted.
# * GitHub, PyPI, and crates.io: two-factor authentication with a hardware key. With these settings, a GitHub account
#   that can tag and publish releases is what remains to protect.

terraform {
  required_version = ">= 1.8"
  # `task gh:init` supplies the state file's path.
  backend "local" {}
  required_providers {
    github = {
      source  = "integrations/github"
      version = "~> 6.13"
    }
  }
}

variable "owner" {
  description = "The GitHub organization or user that owns the repository"
  type        = string
}

variable "repository" {
  description = "The repository's name, without the owner"
  type        = string
}

variable "approvers" {
  description = "The GitHub usernames of the people who may approve a publish job; any one of them is enough"
  type        = list(string)
  validation {
    condition     = length(var.approvers) >= 1 && length(var.approvers) <= 6
    error_message = "Name between one and six approvers: GitHub allows an environment at most six reviewers."
  }
}

provider "github" {
  owner = var.owner
}

# The repository itself, which already exists: the first apply imports it and makes its settings these. Its
# visibility, topics and default branch stay as they are. `task gh:destroy` refuses while this resource is in the
# state, because destroying it would delete the repository; `tofu state rm github_repository.this` lets go of it first.
import {
  to = github_repository.this
  id = var.repository
}

resource "github_repository" "this" {
  name = var.repository
  # The crate's description, so that it is written once.
  description            = regex("description = \"([^\"]+)\"", file("${path.module}/../../chafernet/Cargo.toml"))[0]
  has_issues             = true
  has_discussions        = false
  has_projects           = false
  has_wiki               = false
  allow_merge_commit     = true
  allow_squash_merge     = true
  allow_rebase_merge     = true
  delete_branch_on_merge = true
  lifecycle {
    prevent_destroy = true
  }
}

data "github_user" "approvers" {
  for_each = toset(var.approvers)
  username = each.key
}

locals {
  release_tags = "v*"
  # The built-in repository admin role, as a ruleset bypass actor.
  admin_role_id = 5
  # GitHub offers required reviewers on an environment only to public repositories (and to GitHub Enterprise).
  require_approval = github_repository.this.visibility == "public"
}

# Release tags: only a repository admin can create one, and nobody, admins included, can move or delete one, so a tag
# always names the commit CI checked.
#
# With these, a failed release can't be fixed by moving its tag: delete the draft release, bump the patch version, and
# tag again, as "When something goes wrong" in CONTRIBUTING.md describes.
resource "github_repository_ruleset" "release_tag_creation" {
  repository  = github_repository.this.name
  name        = "Only admins create release tags"
  target      = "tag"
  enforcement = "active"
  conditions {
    ref_name {
      include = ["refs/tags/${local.release_tags}"]
      exclude = []
    }
  }
  rules {
    creation = true
  }
  bypass_actors {
    actor_id    = local.admin_role_id
    actor_type  = "RepositoryRole"
    bypass_mode = "always"
  }
}

resource "github_repository_ruleset" "release_tag_immutable" {
  repository  = github_repository.this.name
  name        = "Release tags are immutable"
  target      = "tag"
  enforcement = "active"
  conditions {
    ref_name {
      include = ["refs/tags/${local.release_tags}"]
      exclude = []
    }
  }
  rules {
    update           = true
    deletion         = true
    non_fast_forward = true
  }
}

# The default branch: no force pushes or deletion. (The `changes` job in ci.yml also fails after a force push to it.)
# If every commit is signed, add `required_signatures = true`, so that a stolen GitHub token can't push without the
# signing key as well.
resource "github_repository_ruleset" "default_branch" {
  repository  = github_repository.this.name
  name        = "main"
  target      = "branch"
  enforcement = "active"
  conditions {
    ref_name {
      include = ["~DEFAULT_BRANCH"]
      exclude = []
    }
  }
  rules {
    deletion         = true
    non_fast_forward = true
  }
}

# Immutable releases: once a release is published, its files and its tag can't change, and GitHub attests to it
# (`gh release verify TAG`). Drafts stay editable, so the draft that ci.yml makes freezes when it is published.
#
# The provider has no resource for this (integrations/terraform-provider-github#2746), so `gh` sets it, and OpenTofu
# does not notice if it is later turned off by hand.
resource "terraform_data" "immutable_releases" {
  input = github_repository.this.full_name
  provisioner "local-exec" {
    command = "gh api -X PUT repos/${self.input}/immutable-releases"
  }
  provisioner "local-exec" {
    when    = destroy
    command = "gh api -X DELETE repos/${self.input}/immutable-releases"
  }
}

# Publishing environments. A trusted publisher trusts the repository, the workflow file name, and the environment, but
# not the ref: without a policy, a workflow named publish.yml pushed to any branch could use these environments and
# publish. Only release tags may deploy to them; with the tag rulesets, only an admin can make such a tag. Where GitHub
# allows it, one of the approvers must also approve each publish job; an approver needs access to the repository.
#
# An environment that already exists is taken over as it is. `task gh:destroy` deletes the environments, and their
# secrets with them.
resource "github_repository_environment" "publish" {
  for_each            = toset(["pypi", "crates-io"])
  repository          = github_repository.this.name
  environment         = each.key
  prevent_self_review = false
  deployment_branch_policy {
    protected_branches     = false
    custom_branch_policies = true
  }
  dynamic "reviewers" {
    for_each = local.require_approval ? [1] : []
    content {
      users = [for user in data.github_user.approvers : user.id]
    }
  }
}

resource "github_repository_environment_deployment_policy" "release_tags" {
  for_each    = github_repository_environment.publish
  repository  = github_repository.this.name
  environment = each.value.environment
  tag_pattern = local.release_tags
}

# Actions: only GitHub's own actions and the ones listed, each pinned to a full commit SHA. When a workflow starts
# using a new action, add it here.
resource "github_actions_repository_permissions" "this" {
  repository           = github_repository.this.name
  enabled              = true
  allowed_actions      = "selected"
  sha_pinning_required = true
  allowed_actions_config {
    github_owned_allowed = true
    verified_allowed     = false
    patterns_allowed = [
      "astral-sh/setup-uv@*",
      "dorny/paths-filter@*",
      "go-task/setup-task@*",
      "PyO3/maturin-action@*",
      "pypa/gh-action-pypi-publish@*",
      "rust-lang/crates-io-auth-action@*",
      "taiki-e/install-action@*",
    ]
  }
}

# Dependabot alerts: GitHub reports a dependency in Cargo.lock, uv.lock or the workflows that has a published advisory.
# supply-chain.yml checks the Rust crates with cargo audit; nothing else checks the Python packages and the actions.
resource "github_repository_vulnerability_alerts" "this" {
  repository = github_repository.this.name
  enabled    = true
}

# The token a workflow gets by default is read-only and can't approve pull requests.
resource "github_workflow_repository_permissions" "this" {
  repository                       = github_repository.this.name
  default_workflow_permissions     = "read"
  can_approve_pull_request_reviews = false
}
