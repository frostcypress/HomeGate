#!/bin/sh
set -eu

VERSION=21.02.7
TARGET=sunxi
SUBTARGET=cortexa53
SDK_FILE="openwrt-sdk-${VERSION}-${TARGET}-${SUBTARGET}_gcc-8.4.0_musl.Linux-x86_64.tar.xz"
SDK_SHA256="0618244a291989b01c660ec6065eeb868ba7a984957415c0aec2ff69a3aa165b"
BASE_URL="https://downloads.openwrt.org/releases/${VERSION}/targets/${TARGET}/${SUBTARGET}"
DEST=${1:-"$PWD/.sdk"}

mkdir -p "$DEST"
cd "$DEST"

if [ ! -f "$SDK_FILE" ]; then
	if command -v curl >/dev/null 2>&1; then
		curl -fL --retry 3 -O "$BASE_URL/$SDK_FILE"
	elif command -v wget >/dev/null 2>&1; then
		wget "$BASE_URL/$SDK_FILE"
	else
		echo "curl or wget is required" >&2
		exit 1
	fi
fi

echo "$SDK_SHA256  $SDK_FILE" | sha256sum -c -

DIR=${SDK_FILE%.tar.xz}
if [ ! -d "$DIR" ]; then
	tar -xJf "$SDK_FILE"
fi

printf '%s\n' "$DEST/$DIR"
