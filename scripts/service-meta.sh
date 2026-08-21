#!/usr/bin/env bash

# shellcheck disable=SC2034  # SVC_META_* are read by registry-docs.sh across the source boundary
service_meta() {
    SVC_META_GRAPHQL=""
    SVC_META_REGISTRY_ID=""
    SVC_META_DB_NAME=""

    case "$1" in
    svc-auth)
        SVC_META_GRAPHQL="no"
        SVC_META_REGISTRY_ID="019f5764-1b96-7c66-8c57-04b70e25afda"
        SVC_META_DB_NAME=""
        ;;
    *)
        echo "::error::service-meta: no metadata declared for '$1' in scripts/service-meta.sh." >&2
        return 1
        ;;
    esac
}

registry_ids() {
    local crate="$1" want_version="${2:-}" file="registry.toml"
    local uuid_re='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

    service_meta "${crate}" || return 1

    [[ -f "${file}" ]] || {
        echo "::error::registry ids: ${file} not found at the repo root — it commits this service's registry coordinate." >&2
        return 1
    }

    if [[ -n "${want_version}" ]]; then
        local declared
        declared=$(awk '
            /^\[package\]/           { in_pkg = 1; next }
            /^\[/ && !/^\[package\]/  { in_pkg = 0 }
            in_pkg && /^version *=/   { gsub(/[" ]/, "", $3); print $3; exit }
        ' "Cargo.toml")
        [[ "${declared}" == "${want_version}" ]] || {
            echo "::error::registry ids: asked to act on ${crate} ${want_version}, but this checkout declares ${declared} in Cargo.toml. The release documents describe THIS tree, so proceeding would describe ${declared} inside ${want_version}'s registry patch. Publish from a checkout of the commit that released ${want_version} (its tag), or bump to ${want_version} properly." >&2
            return 1
        }
    fi

    SVC_REG_SERVICE_ID=$(sed -n 's/^[[:space:]]*service-id[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${file}" | head -1)

    [[ "${SVC_REG_SERVICE_ID}" =~ ${uuid_re} ]] || {
        echo "::error::registry ids: ${file} has no well-formed service-id (got '${SVC_REG_SERVICE_ID}')." >&2
        return 1
    }
    [[ "${SVC_REG_SERVICE_ID}" == "${SVC_META_REGISTRY_ID}" ]] || {
        echo "::error::registry ids: ${file} declares service-id ${SVC_REG_SERVICE_ID}, but scripts/service-meta.sh has ${SVC_META_REGISTRY_ID} for ${crate}. One of the two is wrong — refusing to touch the registry until they agree." >&2
        return 1
    }
}
