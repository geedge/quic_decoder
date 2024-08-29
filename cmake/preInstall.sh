#!/bin/sh
DST=${RPM_INSTALL_PREFIX}/sapp/

mkdir -p ${DST}/stellar_plugin
touch ${DST}/stellar_plugin/spec.toml

if ! grep -q '^\./stellar_plugin/quic_decoder.so' "${DST}/stellar_plugin/spec.toml"; then
    echo -e "\n" >> "${DST}/stellar_plugin/spec.toml"
    echo -e "[[plugin]]" >> "${DST}/stellar_plugin/spec.toml"
    echo -e "path = \"./stellar_plugin/quic_decoder.so\"" >> "${DST}/stellar_plugin/spec.toml"
    echo -e "init = \"QUIC_ONLOAD\"" >> "${DST}/stellar_plugin/spec.toml"
    echo -e "exit = \"QUIC_UNLOAD\"" >> "${DST}/stellar_plugin/spec.toml"
    echo -e "\n" >> "${DST}/stellar_plugin/spec.toml"
fi
