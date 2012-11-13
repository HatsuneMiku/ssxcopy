/*
  AES256_KeyBLOB.cpp

  compiled with CompressCrypt.cpp or AES256_Encrypt.cpp or AES256_Decrypt.cpp
*/

#include "AES256_KeyBLOB.h"

BOOL chkerr(BOOL b, char *m, int n, char *f, char *e)
{
  if(b) return b;
  WCHAR *buf;
  FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER
    | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
    (LPTSTR)&buf, 0, NULL);
  fprintf(stderr, "ASSERT in module %s(%d) @%s: %s\n", m, n, f, e);
  MessageBoxW(NULL, buf, L"error", MB_OK);
  LocalFree(buf);
  return b;
}

BOOL dmpbuf(unsigned char *buf, int len, BOOL crlf)
{
  for(int i = 0; i < len; i++) fprintf(stdout, "%02x", buf[i]);
  if(crlf) fprintf(stdout, "\n");
  return TRUE;
}

BOOL Create_AES256_KeyBLOB(
  HCRYPTPROV    prov,               // CSP
  unsigned char *pbPassword,        // input (Password for Key and IV)
  DWORD         cbPassword,         // input (length)
  unsigned char *pbSalt,            // input (Salt for Key and IV)
  DWORD         cbSalt,             // input (length 8 or 16)
  AES_256_KEY_BLOB  *blob,          // output
  unsigned char pbIV[16]            // output (length fixed 16)
)
{
  BOOL bStatus = FALSE;
  DWORD dwError = 0;
  HCRYPTHASH hash = NULL;
  BYTE hashwork[HASH_MD5_LEN * 64] = {0};
  DWORD hashlen = 0; // must get with HP_HASHVAL (not use HP_HASHSIZE)
  EVERIFY(prov && pbPassword && pbSalt && blob && pbIV);
  EVERIFY(HASH_MD5_LEN + cbPassword + cbSalt <= sizeof(hashwork));

  EVERIFY(CryptCreateHash(prov, CALG_MD5, 0, 0, &hash));
  CopyMemory(hashwork, pbPassword, cbPassword);
  CopyMemory(hashwork + cbPassword, pbSalt, cbSalt);
  EVERIFY(CryptHashData(hash, hashwork, cbPassword + cbSalt, 0));
  BYTE hashdata0[HASH_MD5_LEN] = {0};
  EVERIFY(CryptGetHashParam(hash, HP_HASHVAL, NULL, &hashlen, 0));
  EVERIFY(hashlen <= sizeof(hashdata0));
  EVERIFY(CryptGetHashParam(hash, HP_HASHVAL, hashdata0, &hashlen, 0));
  if(hash){ EVERIFY(CryptDestroyHash(hash)); hash = NULL; }

  EVERIFY(CryptCreateHash(prov, CALG_MD5, 0, 0, &hash));
  CopyMemory(hashwork, hashdata0, hashlen);
  CopyMemory(hashwork + hashlen, pbPassword, cbPassword);
  CopyMemory(hashwork + hashlen + cbPassword, pbSalt, cbSalt);
  EVERIFY(CryptHashData(hash, hashwork, hashlen + cbPassword + cbSalt, 0));
  BYTE hashdata1[HASH_MD5_LEN] = {0};
  EVERIFY(CryptGetHashParam(hash, HP_HASHVAL, NULL, &hashlen, 0));
  EVERIFY(hashlen <= sizeof(hashdata1));
  EVERIFY(CryptGetHashParam(hash, HP_HASHVAL, hashdata1, &hashlen, 0));
  if(hash){ EVERIFY(CryptDestroyHash(hash)); hash = NULL; }

  EVERIFY(CryptCreateHash(prov, CALG_MD5, 0, 0, &hash));
  CopyMemory(hashwork, hashdata1, hashlen);
  CopyMemory(hashwork + hashlen, pbPassword, cbPassword);
  CopyMemory(hashwork + hashlen + cbPassword, pbSalt, cbSalt);
  EVERIFY(CryptHashData(hash, hashwork, hashlen + cbPassword + cbSalt, 0));
  BYTE hashdata2[HASH_MD5_LEN] = {0};
  EVERIFY(CryptGetHashParam(hash, HP_HASHVAL, NULL, &hashlen, 0));
  EVERIFY(hashlen <= sizeof(hashdata2));
  EVERIFY(CryptGetHashParam(hash, HP_HASHVAL, hashdata2, &hashlen, 0));
  if(hash){ EVERIFY(CryptDestroyHash(hash)); hash = NULL; }

  blob->hdr.bType = PLAINTEXTKEYBLOB;
  blob->hdr.bVersion = CUR_BLOB_VERSION;
  blob->hdr.reserved = 0;
  blob->hdr.aiKeyAlg = CALG_AES_256;
  blob->cbKeySize = 32; // sizeof(blob->pbDerivedKey) is the size of pointer
  CopyMemory(blob->pbDerivedKey, hashdata0, hashlen);
  CopyMemory(blob->pbDerivedKey + hashlen, hashdata1, hashlen);
  CopyMemory(pbIV, hashdata2, hashlen);
  bStatus = TRUE;

done:
  if(hash) VERIFY(CryptDestroyHash(hash));
  return bStatus;
}
