#!/usr/bin/env bash
# Create or update Kist's secret CI/CD variables in one go with the GitLab CLI (glab).
#
#   ./set-variables.sh production payments staging
#
# - KIST_DATABASE_URL is read from the prompt (never echoed, never in shell history).
# - KIST_PASSWORD_<PROFILE> is read from ~/.kist/pwd_<profile> when it exists,
#   otherwise from the prompt.
# - Every variable is Masked, Protected and raw (Expand variable reference OFF).
#   Set HIDDEN=1 to create them "Masked and hidden" (only possible on creation).
# - Run inside the project's clone, or pass the project with GLAB_REPO=group/project.
set -euo pipefail

command -v glab >/dev/null || { echo "glab not found: https://docs.gitlab.com/cli/" >&2; exit 1; }
[ "$#" -gt 0 ] || { echo "usage: $0 <profile> [profile...]" >&2; exit 2; }

repo_args=()
[ -n "${GLAB_REPO:-}" ] && repo_args=(-R "$GLAB_REPO")
flags=(--masked --protected --raw)
[ "${HIDDEN:-0}" = "1" ] && flags+=(--hidden)

put() {  # put NAME  (value on stdin)
  local name=$1 value
  value=$(cat)
  if [ "${#value}" -lt 8 ] || [[ "$value" =~ [[:space:]] ]]; then
    echo "$name: GitLab can only mask single-line values of 8+ characters without spaces" >&2
    return 1
  fi
  if printf '%s' "$value" | glab variable set "$name" "${flags[@]}" "${repo_args[@]}" >/dev/null 2>&1; then
    echo "created $name"
  else
    printf '%s' "$value" | glab variable update "$name" --masked --protected --raw "${repo_args[@]}" >/dev/null
    echo "updated $name"
  fi
}

prompt() {  # prompt NAME
  local value
  read -rsp "$1: " value; echo >&2
  printf '%s' "$value"
}

for profile in "$@"; do
  if ! [[ "KIST_PASSWORD_${profile^^}" =~ ^[A-Z0-9_]+$ ]]; then
    echo "KIST_PASSWORD_${profile^^}: GitLab variable names allow only letters, digits and _; rename profile '$profile'" >&2
    exit 1
  fi
done

prompt KIST_DATABASE_URL | put KIST_DATABASE_URL

kist_dir=${KIST_DIR:-$HOME/.kist}
for profile in "$@"; do
  name="KIST_PASSWORD_${profile^^}"          # Kist looks up exactly this name
  if [ -r "$kist_dir/pwd_$profile" ]; then
    tr -d '\n' < "$kist_dir/pwd_$profile" | put "$name"
  else
    prompt "$name" | put "$name"
  fi
done
