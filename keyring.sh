#!/usr/bin/env bash
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

GNUPGHOME="$(mktemp -d --tmpdir archlinux-keyring-XXXXXXXXX)"
export GNUPGHOME
trap 'rm -rf $GNUPGHOME' EXIT INT TERM QUIT

now=$(date +%s)
# 90 days in seconds
expiration_limit=7776000
raw_key_colons=""

import_key_from_keyserver() {
	# import a public key from a keyserver into the keyring
	local key_id="$1"
	printf "Import key ID %s from key server.\n" "$key_id"
	gpg --recv "${key_id}"
}

import_key_from_file() {
	# import a public key from file into the keyring
	local key_id="$1"
	gpg --import "${key_id}"
}

import_keys_from_directory() {
	# import keys from *.asc files in a directory
	local directory="$1"
	for key_file in "${directory}/"*.asc; do
		import_key_from_file "$key_file"
	done
}

import_ownertrust_from_file() {
	# import ownertrust from a file
	local _file="$1"
	gpg --import-ownertrust < "${_file}" 2>/dev/null
}

import_keys_from_list() {
	# import keys from a keyserver using a list of PGP key IDs from a file
	local list="$1"
	while read -r key; do
		printf "Key ID: %s\n" "$key"
		import_key_from_keyserver "$(awk '{print $1}' - <<<"$key")"
	done < "$list"
}

print_key_info() {
	# print the long format of a PGP key ID
	local key_id="$1"
	gpg --keyid-format long --list-key "$key_id" 2>/dev/null
}

print_hokey_lint_info() {
	# print the output of hokey lint for a PGP key ID
	local key_id="$1"
	printf "hokey lint for %s\n" "$key_id"
	gpg --export "$key_id" | hokey lint
}

print_sequoia_lint_info() {
	# print the output of sq-keyring-linter if it exits with a non-zero exit code
	local key_id="$1"
	set +e
	if ! sq-keyring-linter -q <(gpg --export "$key_id" 2>/dev/null); then
		sq-keyring-linter <(gpg --export "$key_id" 2>/dev/null)
		print_hokey_lint_info "$key_id"
	fi
	set -e
}

get_valid_raw_key_colons() {
	# assign list of public keys in colon representation
	# see /usr/share/doc/gnupg/DETAILS for details on the format
	raw_key_colons="$(
		gpg --list-key --with-colons 2>/dev/null \
		| awk -F':' \
		'function key_type(x) {
			if (x ~ /(pub|sub)/)
				return 1
			else
				return ""
		}
		function key_validity(x) {
			if (x !~ /(e|r)/)
				return 1
			else
				return ""
		}
		function key_capability(x) {
			if (x ~ /s/)
				return 1
			else
				return ""
		}
		{
			if (key_type($1) && key_validity($2) && key_capability($12))
				print $0
		}'
	)"
}

list_expiring_keys() {
	# list public keys, that will expire in less than 90 days
	local expiring_keys=""
	expiring_keys="$(awk -F':' -v now="$now" -v expiration_limit=$expiration_limit \
	'function key_expiry(x) {
		if (!(x))
			return ""
		if ((x - now) < expiration_limit)
			return 1
		else
			return ""
	}
	{
		if (key_expiry($7))
			print $5
	}' <<< "$1")"
	if [[ -n "$expiring_keys" ]]; then
		printf "WARNING: Keys expiring in less than 90 days detected:\n"
		while read -r key_id; do
			print_key_info "$key_id"
		done <<< "$expiring_keys"
	fi
}

list_unsafe_keys() {
	# list public keys, that are potentially unsafe or use weak algorithms
	local unsafe_keys=""
	unsafe_keys="$(awk -F':' \
	'function key_length(x) {
		if (x >= 2048)
			return 1
		else
			return ""
	}
	function key_public_key_algorithm(x) {
	# check that RSA (1) or ECC
	# see https://tools.ietf.org/html/rfc4880#page-62 for further details
		if (x ~ /(1|3|22)/)
			return 1
		else
			return ""
	}
	function key_curve_name(x) {
		if (x ~ /ed25519/)
			return 1
		else
			return ""
	}
	{
		if (! key_public_key_algorithm($4))
			print $5
		if(! key_length($3) && (!key_curve_name($17)))
			print $5
	}' <<< "$1")"
	if [[ -n "$unsafe_keys" ]]; then
		printf "WARNING: Weak or unsafe keys detected:\n"
		while read -r key_id; do
			print_key_info "$key_id"
		done <<< "$unsafe_keys"
	fi
}

list_keyring_lint() {
	local keys=""
	keys="$(awk -F':' '{print $5}' <<< "$1")"
	printf "all keys: %s\n" "$keys"
	while read -r key_id; do
		printf "hokey lint output for %s\n" "$key_id"
		print_hokey_lint_info "$key_id"
	done <<< "$keys"
	while read -r key_id; do
		print_sequoia_lint_info "$key_id"
	done <<< "$keys"
}

# WIP
# import_keys_from_directory 'master'
# import_key_from_file 'keyring.gpg'
# import_ownertrust_from_file 'archlinux-trusted'
# import_keys_from_directory 'master-revoked'
# import_keys_from_directory 'packager'
# import_keys_from_directory 'packager-revoked'
# import_keys_from_list 'packager-keyids'
# import_keys_from_list 'master-keyids'

get_valid_raw_key_colons
printf "%s\n" "$raw_key_colons"
list_expiring_keys "$raw_key_colons"
list_unsafe_keys "$raw_key_colons"
# list_keyring_lint "$raw_key_colons"

