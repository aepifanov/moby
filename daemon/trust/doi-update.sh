#!/usr/bin/env bash

# This script is used to update the list of Docker Official Image root keys
# baked into ee-engine. The list of keys is printed to stdout, one per line.
# The output may include comment lines, which are signified by a '#' in the
# first column.

# From @cyli on Docker Community Slack:
# > so what I did to get that was iterate over every DOI here https://github.com/docker-library/official-images/tree/master/library and run notary -s https://notary.docker.io -d ~/.docker/trust info docker.io/library/$image_name using Notary CLI I built with these mods: https://github.com/cyli/notary/commit/7c26fee5bd135e30d0c3a909c7a8797b67455bf0 :sweat_smile:
# > express-gateway is the only DOI without keys
# > I guess make sure he knows to use the canonical ID, could probably just filter that output to remove it

set -euo pipefail

# Print the canonical root key for the given official image.
function _root_key() {
	local retries=5
	local key
	while [[ $retries -gt 0 ]]; do
		if key="$(go run github.com/cyli/notary/cmd/notary@canonical-info \
			-s https://notary.docker.io \
			info "docker.io/library/${1}" 2> /dev/null)"; then
			awk '$1 == "(canonical)" { print $3 }' <<< "${key}"
			return
		fi

		[[ -n "${key}" ]] && printf >&2 '%s\n' "${key}"
		[[ $key == *"does not have trust data"* ]] && return

		((retries--))
		if [[ $retries -gt 0 ]]; then
			printf >&2 'Error fetching root key for %s; retrying...\n' "${1}"
			sleep 1
		fi
	done
	printf >&2 'FATAL: could not fetch root key for %s.\n' "${1}"
	return 1
}

# Pre-populate the list of images with deprecated images which are signed with
# keys that have historically been included in the ee-engine list, but for which
# none of the images signed with those keys are enumerated in the
# official-images repository.
images=(rapidoid)

# Fill the list of images with the names of all maintained official images from
# the canonical source: the official-images GitHub repository.
for image in $(gh api repos/docker-library/official-images/contents/library -q '.[].name'); do
	images+=("${image}")
done

declare -A keys
for i in "${!images[@]}"; do
	image="${images[$i]}"
	printf >&2 '[%d/%d] %s\n' "$((i + 1))" "${#images[@]}" "${image}"
	key="$(_root_key "${image}")"
	if [[ -n "${key}" ]]; then
		keys["${key}"]+=" ${image}"
	fi
done

for key in $(printf '%s\n' "${!keys[@]}" | sort); do
	for image in $(printf '%s\n' "${keys[$key]}" | sort); do
		printf '# %s\n' "${image}"
	done
	printf '%s\n' "${key}"
done
