#!/bin/bash

set -eu

VERSIONS=(
  "v0.1.1"
)
FLAVOURS=(
  "bls_tests_json"
  # "bls_tests_yaml"
)

# signal handler (we only care about the Ctrl+C generated SIGINT)
REL_PATH="$(dirname "${BASH_SOURCE[0]}")"
ABS_PATH="$(cd "${REL_PATH}"; pwd)"
cleanup() {
	echo -e "\nCtrl+C pressed. Cleaning up."
	cd "$ABS_PATH"
	rm -rf tarballs tests-*
	exit 1
}
trap cleanup SIGINT

dl_version() {
	[[ -z "$1" ]] && { echo "usage: dl_version() vX.Y.Z"; exit 1; }
	version="$1"

	mkdir -p "tarballs/ef-bls12381-vectors-${version}"
	pushd "tarballs/ef-bls12381-vectors-${version}" >/dev/null
	for flavour in "${FLAVOURS[@]}"; do
		if [[ ! -e "${flavour}.tar.gz" ]]; then
			echo "Downloading: ef-bls12381-vectors-${version}/${flavour}.tar.gz"
			curl --location --remote-name --silent --show-error \
				"https://github.com/ethereum/bls12-381-tests/releases/download/${version}/${flavour}.tar.gz" \
				|| {
					echo "Curl failed. Aborting"
					rm -f "${flavour}.tar.gz"
					exit 1
				}
		fi
	done
	popd >/dev/null
}

unpack_version() {
	[[ -z "$1" ]] && { echo "usage: unpack_version() vX.Y.Z"; exit 1; }
	version="$1"

	dl_version "$version"

	# suppress warnings when unpacking with GNU tar an archive created with BSD tar (probably on macOS)
	EXTRA_TAR_PARAMS=""
	tar --version | grep -qi 'gnu' && EXTRA_TAR_PARAMS="--warning=no-unknown-keyword --ignore-zeros"

	if [[ ! -d "ef-bls12381-vectors-${version}" ]]; then
		for flavour in "${FLAVOURS[@]}"; do
			echo "Unpacking: ef-bls12381-vectors-${version}/${flavour}.tar.gz"
			mkdir -p "ef-bls12381-vectors-${version}"
			tar -C "ef-bls12381-vectors-${version}" --strip-components 1 ${EXTRA_TAR_PARAMS} --exclude=phase1 -xzf \
				"tarballs/ef-bls12381-vectors-${version}/${flavour}.tar.gz" \
				|| {
					echo "Tar failed. Aborting."
					rm -rf "ef-bls12381-vectors-${version}"
					exit 1
				}
		done
	fi
}

# download and unpack
for version in "${VERSIONS[@]}"; do
	unpack_version "$version"
done

# delete tarballs and unpacked data from old versions
for tpath in tarballs/*; do
	tdir="$(basename "$tpath")"
	if [[ ! " ${VERSIONS[@]} " =~ " $tdir " ]]; then
		rm -rf "$tpath"
	fi
done
for tpath in ef-bls12381-vectors-*; do
	tver="$(echo "$tpath" | sed -e's/^ef-bls12381-vectors-//')"
	if [[ ! " ${VERSIONS[@]} " =~ " $tver " ]]; then
		rm -rf "$tpath"
	fi
done
