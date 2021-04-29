#!/usr/bin/env bash
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -eu

# TODO: use a keyring that is assembled from the existing public keys
homedir="/etc/pacman.d/gnupg"
now=$(date +%s)
# 90 days in seconds
expiration_limit=7776000

raw_key_colons=""


print_key_info() {
	local key_id="$1"
	gpg --homedir "$homedir" --keyid-format long --list-key "$key_id" 2>/dev/null
}

get_valid_raw_key_colons() {
# assign list of public keys in colon representation
# see /usr/share/doc/gnupg/DETAILS for details on the format
	raw_key_colons="$(
	gpg --homedir "$homedir" --list-key --with-colons 2>/dev/null \
		| awk -F':' \
		'function key_type(x) {
			if (x ~ /(pub|sub)/)
				return 1
			else
				return ""
		}
		function key_validity(x) {
			if (x ~ /f/)
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

get_valid_raw_key_colons
list_expiring_keys "$raw_key_colons"
list_unsafe_keys "$raw_key_colons"
