/*
  CompressCrypt.cpp

  from CryptCompress.c (T:\iZ\age-c466\backup_e\ADTX\prj\util\CryptCompress)
  or Encrypt.c / Decrypt.c (T:\iZ\age-c466\backup_e\ADTX\prj\util\vcencrypt)

  cl CompressCrypt.cpp AES256_KeyBLOB.cpp kernel32.lib user32.lib gdi32.lib \
    advapi32.lib crypt32.lib (-DDEBUG) -DUNICODE -EHsc
*/

#include "AES256_KeyBLOB.h"
#include <cstring>

#if _WIN32_WINNT >= 0x0600
#define ENCRYPT_CSP PROV_RSA_AES
#define ENCRYPT_ALGORITHM CALG_AES_256 // CALG_AES_256: 16xN bytes
#define ENCRYPT_KEYLEN (256 * 0x10000)
#else
#define ENCRYPT_CSP PROV_RSA_FULL
#define ENCRYPT_ALGORITHM CALG_RC2 // CALG_RC2: 16xN bytes, CALG_RC4: same size
#define ENCRYPT_KEYLEN 0
#endif

void test_encryptdata(void)
{
  HCRYPTPROV prov = NULL;
  HCRYPTHASH hash = NULL;
  HCRYPTKEY key = NULL;
  BYTE hashdata[HASH_MD5_LEN * 4] = {0}; // x 2 over when SHA...
  DWORD hashlen = 0; // must get with HP_HASHVAL (not use HP_HASHSIZE)
  WCHAR hashstr[sizeof(hashdata) * 3 + 3] = {0}; // (2HEX+SP)x16 + CR + LF + 1
  DWORD hashstrlen = sizeof(hashstr) / sizeof(hashstr[0]);
  BYTE *password = (BYTE *)"HogeHoge";
  BYTE buf[100] = "first Compress second Crypt (38 bytes)";
  DWORD len = strlen((char *)buf);

  EVERIFY(CryptAcquireContext(&prov, NULL, NULL, ENCRYPT_CSP,
    CRYPT_VERIFYCONTEXT | CRYPT_SILENT));
  EVERIFY(CryptCreateHash(prov, CALG_MD5, 0, 0, &hash));
  EVERIFY(CryptHashData(hash, password, strlen((char *)password), 0));
  EVERIFY(CryptDeriveKey(prov, ENCRYPT_ALGORITHM, hash, ENCRYPT_KEYLEN, &key));

  EVERIFY(CryptGetHashParam(hash, HP_HASHVAL, NULL, &hashlen, 0));
  EVERIFY(hashlen <= sizeof(hashdata));
  EVERIFY(CryptGetHashParam(hash, HP_HASHVAL, hashdata, &hashlen, 0));
  fprintf(stdout, "hash: %d bytes ", hashlen);
  EVERIFY(CryptBinaryToString(hashdata, hashlen, CRYPT_STRING_HEX,
    hashstr, &hashstrlen)); // CryptBinaryToString is in crypt32.lib
  hashstr[hashstrlen - 2] = L'\0'; // trim CR and LF
  fwprintf(stdout, L"(%d WCHARs) [%s]\n", hashstrlen, hashstr);
  dmpbuf(hashdata, hashlen, TRUE);

  fprintf(stdout, "plain: %d bytes [%s]\n", len, buf);
  dmpbuf(buf, len, TRUE);

  EVERIFY(CryptEncrypt(key, 0, TRUE, 0, buf, &len, sizeof(buf)));
  fprintf(stdout, "crypt: %d bytes\n", len);
  dmpbuf(buf, len, TRUE);

  EVERIFY(CryptDecrypt(key, 0, TRUE, 0, buf, &len));
  buf[len] = '\0';
  fprintf(stdout, "decrypt: %d bytes [%s]\n", len, buf);
  dmpbuf(buf, len, TRUE);

done:
  if(key) VERIFY(CryptDestroyKey(key));
  if(hash) VERIFY(CryptDestroyHash(hash));
  if(prov) VERIFY(CryptReleaseContext(prov, 0));
}

int main(int ac, char **av)
{
  test_encryptdata();
  return 0;
}
