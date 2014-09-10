// Select_Cert.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <windows.h>

#include <wincrypt.h>

#include <Cryptuiapi.h>

int main(int argc, char* argv[])
{
	HCERTSTORE hstore = NULL;
	PCCERT_CONTEXT hcert = NULL;
	BYTE pvData[24];
	DWORD pcbData = 24, tmpcnt = 0;
	char tmpstr[64];
	int ret = 1;

	hstore = CertOpenSystemStore(NULL, "MY");
	if (!hstore) return 1;
	hcert = CryptUIDlgSelectCertificateFromStore(hstore, NULL, NULL, NULL, CRYPTUI_SELECT_LOCATION_COLUMN, 0, NULL);
	if (!hcert) goto failed;
	if (CertGetCertificateContextProperty(hcert, CERT_SHA1_HASH_PROP_ID, pvData, &pcbData))
	{
		for (DWORD datacnt = 0; datacnt < pcbData; datacnt++)
		{
			BYTE ch = (pvData[datacnt]>>4) & 15;
			tmpstr[tmpcnt++] = ch + (ch < 10)?'0':'7';
			ch = pvData[datacnt] & 15;
			tmpstr[tmpcnt++] = ch + (ch < 10)?'0':'7';
			tmpstr[tmpcnt++] = ' ';
		}
		tmpstr[tmpcnt - 1] = 0;
		printf(" --cryptoapicert \"THUMB:%s\"", tmpstr);
		ret = 0;
	}
	CertFreeCertificateContext(hcert);
failed:
	CertCloseStore(hstore, 0);
	return ret;
}

