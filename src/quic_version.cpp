#include <stdio.h>
#include "quic_process.h"
 
int quic_version_int2string(unsigned int version, char *buff, int buff_len)
{
	if(version>=GQUIC_VERSION_Q001 && version<=GQUIC_VERSION_Q099)
	{
		snprintf(buff, buff_len, "Google QUIC %02d", (((version>>8)&0x0000000F)*10) + (version&0x0000000F));
		return 1;
	}

	if(version>=GQUIC_VERSION_T048 && version<=GQUIC_VERSION_T099)
	{
		snprintf(buff, buff_len, "Google QUIC with TLS %02d", (((version>>8)&0x0000000F)*10) + (version&0x0000000F));
		return 1;
	}

		
	if(version==IQUIC_VERSION_RFC9000)
	{
		snprintf(buff, buff_len, "IETF QUIC RFC9000");
		return 1;
	}

	if(version>=IQUIC_VERSION_I001 && version<=IQUIC_VERSION_I032)
	{
		snprintf(buff, buff_len, "IETF QUIC %02d", (((version>>16)&0x000000FF)*10) + (((version>>8)&0x000000FF)*10) + (version&0x000000FF));
		return 1;
	}

	if(version>=QUANT_VERSION_00 && version<=QUANT_VERSION_FF)
	{
		snprintf(buff, buff_len, "NetApp QUANT %02d",  (version&0x000000FF));
		return 1;
	}

	if(version==PICOQUIC_VERSION_30)
	{
		snprintf(buff, buff_len, "Private Octopus");
		return 1;
	}

	if(version==PQUIC_VERSION_PROX)
	{
		snprintf(buff, buff_len, "Proxied QUIC");
		return 1;
	}

	if(version>=QUIC_GO_VERSION_00 && version<=QUIC_GO_VERSION_FF)
	{
		snprintf(buff, buff_len, "quic-go QGO %02d",  (version&0x000000FF));
		return 1;
	}

	if(version>=QUIC_GO_VERSION_00 && version<=QUIC_GO_VERSION_FF)
	{
		snprintf(buff, buff_len, "quicly qicly0 %02d",  (version&0x000000FF));
		return 1;
	}
	
	if(version>=MSQUIC_VERSION_00 && version<=MSQUIC_VERSION_0F)
	{
		snprintf(buff, buff_len, "Microsoft MsQuic %02d",  (version&0x0000000F));
		return 1;
	}

	if(version>=MOZQUIC_VERSION_00 && version<=MOZQUIC_VERSION_0F)
	{
		snprintf(buff, buff_len, "Mozilla MozQuic %02d",  (version&0x0000000F));
		return 1;
	}

	if(version>=MVFST_VERSION_00&& version<=MVFST_VERSION_0F)
	{
		snprintf(buff, buff_len, "Facebook mvfst %02d",  (version&0x0000000F));
		return 1;
	}

	return 0;
}
 