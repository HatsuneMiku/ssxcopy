/*
  AES256_KeyBLOB.h

  included from CompressCrypt.cpp or AES256_Encrypt.cpp or AES256_Decrypt.cpp
*/

#ifndef __AES256_KEYBLOB_H__
#define __AES256_KEYBLOB_H__

#ifndef _WIN32_WINNT
// 0x0400 : NT, 0x0500 : 2000 / XP, 0x0600 : Vista / 7 / 8
// #define _WIN32_WINNT 0x0501
#define _WIN32_WINNT 0x0600
#endif
#ifndef UNICODE
#define UNICODE
#endif
#include <windows.h>
#include <wincrypt.h>
#include <cstdio>

#if defined(_DEBUG) || defined(DEBUG)
#define ASSERT(x) chkerr((BOOL)(x), __FILE__, __LINE__, __FUNCTION__, #x)
#define VERIFY(x) ASSERT(x)
#else // RELEASE
#define ASSERT(x)
#define VERIFY(x) (x)
#endif
extern BOOL chkerr(BOOL b, char *m, int n, char *f, char *e);
#define EVERIFY(x) if(!VERIFY(x)){ goto done; }

extern BOOL dmpbuf(unsigned char *buf, int len, BOOL crlf);

#define HASH_MD5_LEN 16

typedef struct _AES_256_kEY_BLOB {
  BLOBHEADER    hdr;
  DWORD         cbKeySize;          // 32
  unsigned char pbDerivedKey[32];   // 32 bytes = 256 bits
} AES_256_KEY_BLOB;

extern BOOL Create_AES256_KeyBLOB(
  HCRYPTPROV    prov,               // CSP
  unsigned char *pbPassword,        // input (Password for Key and IV)
  DWORD         cbPassword,         // input (length)
  unsigned char *pbSalt,            // input (Salt for Key and IV)
  DWORD         cbSalt,             // input (length 8 or 16)
  AES_256_KEY_BLOB  *blob,          // output
  unsigned char pbIV[16]            // output (length fixed 16)
);

#endif // __AES256_KEYBLOB_H__
