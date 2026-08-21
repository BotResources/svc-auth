#!/usr/bin/env bash

set -euo pipefail

usage() {
    echo "usage: registry-docs.sh <service> <version> [--print-only]" >&2
    exit 2
}

[[ $# -ge 2 ]] || usage
SERVICE="$1"
VERSION="$2"
shift 2
PRINT_ONLY=0
while [[ $# -gt 0 ]]; do case "$1" in
    --print-only) PRINT_ONLY=1; shift ;;
    -h | --help) usage ;;
    *)
        echo "error: unknown argument '$1'" >&2
        usage
        ;;
esac done

if [[ ! "${VERSION}" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
    echo "::error::registry docs: version '${VERSION}' is not a plain M.m.p semver — cannot map it to a registry PatchVersion." >&2
    exit 1
fi
MAJOR="${BASH_REMATCH[1]}"
MINOR="${BASH_REMATCH[2]}"
PATCH="${BASH_REMATCH[3]}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"

# shellcheck source=scripts/service-meta.sh
source scripts/service-meta.sh

registry_ids "${SERVICE}" "${VERSION}"

BR_REGISTRY_URL="${BR_REGISTRY_URL:-https://botresources.ai/graphql}"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

SDL_DOC="${WORK}/patch.sdl"
DB_DOC="${WORK}/patch.db.sql"
: >"${SDL_DOC}"
: >"${DB_DOC}"

if [[ "${SVC_META_GRAPHQL}" != "no" ]]; then
    echo "::error::registry docs: scripts/service-meta.sh declares a GraphQL surface for ${SERVICE}, but this script carries no SDL extraction path — svc-auth serves no GraphQL. Port the binary \`schema\` extraction from be-botresources.ai's registry-docs.sh before flipping SVC_META_GRAPHQL." >&2
    exit 1
fi
echo "sdl: ${SERVICE} declares no GraphQL surface — posing the empty document."

if [[ -n "${SVC_META_DB_NAME}" ]]; then
    echo "::error::registry docs: scripts/service-meta.sh declares the database '${SVC_META_DB_NAME}' for ${SERVICE}, but this script carries no schema-recompose path — svc-auth owns no database. Port the ephemeral-Postgres recompose from be-botresources.ai's registry-docs.sh before setting SVC_META_DB_NAME." >&2
    exit 1
fi
echo "db: ${SERVICE} owns no schema — posing the empty document."

if [[ "${PRINT_ONLY}" == 1 ]]; then
    echo "===== SDL (${SERVICE} ${VERSION}) ====="
    cat "${SDL_DOC}"
    echo "===== DB SCHEMA (${SERVICE} ${VERSION}) ====="
    cat "${DB_DOC}"
    exit 0
fi

if [[ -z "${BR_REGISTRY_KEY:-}" ]]; then
    echo "::error::registry docs: BR_REGISTRY_KEY is not set — the procedural SDL and DB schema for ${SERVICE} ${VERSION} cannot be posed. Failing rather than skipping: without these two documents the patch never flips to implemented, so a silent skip ships an image the registry does not know about. Use --print-only to exercise this script without a key."
    exit 1
fi

gql() {
    python3 -c 'import json,sys; json.dump({"query": sys.argv[1], "variables": json.load(open(sys.argv[2]))}, open(sys.argv[3], "w"))' \
        "$1" "$2" "${WORK}/payload.json"
    curl -sS --fail-with-body -X POST "${BR_REGISTRY_URL}" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${BR_REGISTRY_KEY}" \
        -d "@${WORK}/payload.json"
}

classify() {
    python3 -c '
import json, sys
d = json.loads(sys.argv[1])
if not d.get("errors"):
    print("OK")
    sys.exit(0)
e = d["errors"][0]
ext = e.get("extensions") or {}
reason = ext.get("reason") or ""
if reason == "patch_already_implemented":
    print("ALREADY")
    sys.exit(0)
print("REFUSED %s (%s)" % (reason or e.get("message"), ext.get("code")))
' "$1"
}

FROZEN=0

pose() {
    python3 -c 'import json,sys; json.dump({"sid": sys.argv[1], "maj": int(sys.argv[2]), "min": int(sys.argv[3]), "pat": int(sys.argv[4]), "doc": open(sys.argv[5]).read()}, open(sys.argv[6], "w"))' \
        "${SVC_REG_SERVICE_ID}" "${MAJOR}" "${MINOR}" "${PATCH}" "$2" "${WORK}/doc-vars.json"
    local resp verdict
    resp=$(gql "$3" "${WORK}/doc-vars.json")
    verdict=$(classify "${resp}")
    case "${verdict}" in
    OK)
        echo "posed procedural $1 ($(wc -l <"$2" | tr -d ' ') lines)"
        ;;
    ALREADY)
        FROZEN=1
        echo "::warning::registry docs: ${SERVICE} ${VERSION} is already implemented in the registry, so its documents are frozen — the $1 was NOT re-posed. Reached only when a version recorded in the registry has to be rebuilt because its image is missing from GHCR; the document already on the patch was posed from this same commit, so it is already the right one. If you believe it is wrong, that needs a new patch version — a published version is immutable."
        ;;
    *)
        echo "::error::registry docs: set procedural $1 refused — ${verdict#REFUSED }"
        exit 1
        ;;
    esac
}

pose "SDL" "${SDL_DOC}" \
    'mutation($sid: UUID!, $maj: Int!, $min: Int!, $pat: Int!, $doc: String!) { servicesSetPatchSdl(serviceId: $sid, major: $maj, minor: $min, patch: $pat, sdl: $doc, procedural: true) { ok } }'
pose "DB schema" "${DB_DOC}" \
    'mutation($sid: UUID!, $maj: Int!, $min: Int!, $pat: Int!, $doc: String!) { servicesSetPatchDbSchema(serviceId: $sid, major: $maj, minor: $min, patch: $pat, dbSchema: $doc, procedural: true) { ok } }'

if [[ "${FROZEN}" == 1 ]]; then
    echo "OK   ${SERVICE} ${VERSION}: already implemented — the documents on the patch were posed by the run that shipped this version and were left untouched."
else
    echo "OK   ${SERVICE} ${VERSION}: both procedural documents posed on ${SERVICE} ${MAJOR}.${MINOR}.${PATCH} (service ${SVC_REG_SERVICE_ID})."
fi
