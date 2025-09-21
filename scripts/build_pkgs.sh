#!/bin/bash

# run the following from gluon folder
# make TOPDIR="../../openwrt" -C "./package/gluon-ebtables" clean
# make TOPDIR="../../openwrt" -C "./package/gluon-ebtables" compile

set -e

update_feeds=0
target="x86-64"
topdir="$(realpath "$(dirname "${0}")/../openwrt")"

print_help() {
	echo "$0 [OPTIONS] PACKAGE_DIR [PACKAGE_DIR] ..."
	echo ""
	echo " -h          print this help"
	echo " -t          target to build packages for"
	echo " -u          clean and update feeds"
	echo ""
	echo ' To change gluon variables, run e.g. "make config GLUON_MINIFY=0"'
	echo ' because then the gluon logic will be triggered, and openwrt/.config'
	echo ' will be regenerated. The variables from openwrt/.config are already'
	echo ' automatically used for this script.'
	echo
}

while getopts "ut:h" opt
do
	case $opt in
		u) update_feeds=1;;
		h) print_help; exit 0;;
		t) target="${OPTARG}";;
		*) ;;
	esac
done
shift $(( OPTIND - 1 ))

if [ $# -lt 1 ]; then
	echo ERROR: Please specify a FEED_DIR. For example:
	echo
	echo " \$ $0 community"
	exit 1
fi

if [ -z "${GLUON_RELEASE}" ]; then
	export GLUON_RELEASE="1.0"
fi

if [ -z "${GLUON_SITEDIR}" ]; then
	export GLUON_SITEDIR="contrib/ci/minimal-site"
fi

if [ "$update_feeds" -eq 1  ]; then
	# build new config, to set the correct target in openwrt/.config  
	make GLUON_TARGET="${target}" config
	pushd "${topdir}"
	# recreate feeds file as install allows to set a new default
	./scripts/feeds clean
	./scripts/feeds update -f -a
	# enable all packages from this feed by using the default
	./scripts/feeds install -a -d m
	popd
fi

while [ $# -gt 0 ]; do
	feed_name="$1"; shift
	echo "Feed: ${feed_name}"

	package_dirs=$(find "./packages/${feed_name}" -maxdepth 3 -type f -name "Makefile" -exec dirname {} \; | sort -u)

	for pkgdir in $package_dirs; do
		echo "building ${pkgdir}"
		if ! [ -f "${pkgdir}/Makefile" ]; then
			echo "ERROR: ${pkgdir} does not contain a Makefile"
			continue
		fi

		if ! grep -q BuildPackage "${pkgdir}/Makefile"; then
			echo "ERROR: ${pkgdir}/Makefile does not contain a BuildPackage command"
			continue
		fi
		make TOPDIR="${topdir}" -C "${pkgdir}" clean || true
		make TOPDIR="${topdir}" -C "${pkgdir}" compile || true
	done
done
