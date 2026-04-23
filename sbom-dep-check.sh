#!/bin/bash
# sbom-dep-check.sh — Check CycloneDX SBOM attestations for specific impacted package versions
# Usage: ./sbom-dep-check.sh <registry-base-url> <deps-file>
# Example: ./sbom-dep-check.sh registry.suse.com/ai deps.txt

set -uo pipefail

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
if [ $# -lt 2 ]; then
    echo "Usage: $0 <registry-base-url> <deps-file>"
    echo "Example: $0 registry.suse.com/ai deps.txt"
    echo ""
    echo "deps-file format (one entry per line, # for comments):"
    echo "  pgserve 1.1.11"
    echo "  @scope/package 4.1.0"
    exit 1
fi

REGISTRY_URL="$1"
DEPS_FILE="$2"

if [ ! -f "$DEPS_FILE" ]; then
    echo "Error: deps file '$DEPS_FILE' not found."
    exit 1
fi

REGISTRY_HOST="${REGISTRY_URL%%/*}"
REGISTRY_PATH="${REGISTRY_URL#*/}"
COSIGN_KEY="https://documentation.suse.com/suse-ai/files/sr-pubkey.pem"

# ---------------------------------------------------------------------------
# Load deps: parallel arrays PKG_NAMES[] and PKG_VERSIONS[]
# ---------------------------------------------------------------------------
PKG_NAMES=()
PKG_VERSIONS=()

while IFS= read -r line; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"   # ltrim
    line="${line%"${line##*[![:space:]]}"}"   # rtrim
    [ -z "$line" ] && continue

    pkg=$(echo "$line" | awk '{print $1}')
    ver=$(echo "$line" | awk '{print $2}')
    [ -z "$pkg" ] || [ -z "$ver" ] && continue

    PKG_NAMES+=("$pkg")
    PKG_VERSIONS+=("$ver")
done < "$DEPS_FILE"

if [ ${#PKG_NAMES[@]} -eq 0 ]; then
    echo "Error: no valid entries found in '$DEPS_FILE'."
    exit 1
fi

# ---------------------------------------------------------------------------
# Match helper — returns "found" or "not_found"
# cosign --output json emits one JSON object per attestation, so saved files
# may have multiple top-level documents; -s slurps them into an array first.
# ---------------------------------------------------------------------------
match_pkg() {
    local file="$1" pkg="$2" ver="$3"
    local ver_bare="${ver#v}"
    local result
    result=$(jq -se --arg n "$pkg" --arg v "$ver_bare" \
      '[.[].components[]? | select(.name == $n and ((.version | ltrimstr("v")) == $v))] | length > 0' \
      "$file" 2>/dev/null) || true
    [ "$result" = "true" ] && echo "found" || echo "not_found"
}

# ---------------------------------------------------------------------------
# Per-image/platform SBOM fetch + check
# ---------------------------------------------------------------------------
IMPACT_LINES=()
SBOM_COUNT=0

check_sbom() {
    local repo="$1" image_name="$2" digest="$3" platform_str="$4" tag="$5"
    local output_file="${image_name}-${tag}-${platform_str}-sbom.json"

    echo "  Fetching SBOM for ${image_name} @ ${platform_str} (${digest})..."

    cosign verify-attestation \
        --key "${COSIGN_KEY}" \
        --type cyclonedx \
        --output json \
        "${REGISTRY_HOST}/${repo}@${digest}" \
        2>/dev/null \
        | jq '.payload | @base64d | fromjson | .predicate' \
        > "${output_file}" || true

    if [ ! -s "${output_file}" ] || [ "$(cat "${output_file}")" = "null" ]; then
        echo "  [WARN] No CycloneDX SBOM attestation found for ${image_name} (${platform_str}), skipping."
        rm -f "${output_file}"
        return
    fi

    echo "  SBOM saved to ${output_file}"
    ((SBOM_COUNT++)) || true

    local any_impact=0
    for i in "${!PKG_NAMES[@]}"; do
        local pkg="${PKG_NAMES[$i]}" ver="${PKG_VERSIONS[$i]}"
        local result
        result=$(match_pkg "${output_file}" "$pkg" "$ver")
        if [ "$result" = "found" ]; then
            echo "  [IMPACTED] ${pkg}@${ver} found in ${image_name} (${platform_str})"
            IMPACT_LINES+=("${pkg} ${ver} — ${image_name}:${tag} (${platform_str})")
            any_impact=1
        fi
    done

    if [ "$any_impact" -eq 0 ]; then
        echo "  [CLEAR] No impacted packages found in ${image_name} (${platform_str})"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo "Registry  : ${REGISTRY_HOST}/${REGISTRY_PATH}"
echo "Deps file : ${DEPS_FILE}"
echo "Checking  :"
for i in "${!PKG_NAMES[@]}"; do
    echo "  ${PKG_NAMES[$i]}@${PKG_VERSIONS[$i]}"
done
echo ""

echo "Fetching container catalog from ${REGISTRY_HOST}..."
CONTAINERS=$(crane catalog "${REGISTRY_HOST}" 2>/dev/null | grep -E "^${REGISTRY_PATH}/containers") || true

if [ -z "$CONTAINERS" ]; then
    echo "No containers found matching ^${REGISTRY_PATH}/containers"
    exit 0
fi

echo "Found containers:"
echo "$CONTAINERS" | sed 's/^/  /'
echo ""

while IFS= read -r repo; do
    IMAGE_NAME=$(basename "$repo")
    echo "=== ${repo} ==="

    TAGS=$(crane ls "${REGISTRY_HOST}/${repo}" 2>/dev/null | grep -Ev '\.(att|sig)$') || true

    if [ -z "$TAGS" ]; then
        echo "  [WARN] No usable tags found for ${repo}, skipping."
        echo ""
        continue
    fi

    while IFS= read -r tag; do
        echo "  Tag: ${tag}"

        MANIFEST=$(crane manifest "${REGISTRY_HOST}/${repo}:${tag}" 2>/dev/null) || {
            echo "  [WARN] Could not fetch manifest for ${repo}:${tag}, skipping."
            continue
        }

        if echo "$MANIFEST" | jq -e '.manifests' > /dev/null 2>&1; then
            while IFS= read -r entry; do
                DIGEST=$(echo "$entry"  | jq -r '.digest')
                OS=$(echo "$entry"      | jq -r '.platform.os // "unknown"')
                ARCH=$(echo "$entry"    | jq -r '.platform.architecture // "unknown"')
                VARIANT=$(echo "$entry" | jq -r '.platform.variant // ""')
                if [ -n "$VARIANT" ]; then
                    PLATFORM_STR="${OS}-${ARCH}-${VARIANT}"
                else
                    PLATFORM_STR="${OS}-${ARCH}"
                fi
                check_sbom "$repo" "$IMAGE_NAME" "$DIGEST" "$PLATFORM_STR" "$tag"
            done < <(echo "$MANIFEST" | jq -c '.manifests[]')
        else
            DIGEST=$(crane digest "${REGISTRY_HOST}/${repo}:${tag}" 2>/dev/null) || {
                echo "  [WARN] Could not get digest for ${repo}:${tag}, skipping."
                continue
            }
            check_sbom "$repo" "$IMAGE_NAME" "$DIGEST" "single" "$tag"
        fi
    done <<< "$TAGS"

    echo ""
done <<< "$CONTAINERS"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=============================="
echo "Summary"
echo "=============================="
echo "SBOMs scanned : ${SBOM_COUNT}"
echo ""

if [ ${#IMPACT_LINES[@]} -eq 0 ]; then
    echo "No impacted package versions found in any SBOM."
else
    echo "Impacted packages found:"
    for line in "${IMPACT_LINES[@]}"; do
        echo "  [IMPACTED] ${line}"
    done
fi

echo ""
echo "Done."
