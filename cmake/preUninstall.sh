if [ $1 == 0 ]; then
	DST=${RPM_INSTALL_PREFIX}/sapp/stellar_plugin
	sed -i -n '$!N;/quic_decoder.so/!P;D' ${DST}/spec.toml
	sed -i '/QUIC_ONLOAD/d' ${DST}/spec.toml
	sed -i '/QUIC_UNLOAD/d' ${DST}/spec.toml
fi
