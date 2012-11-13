/*
  AES256_Encrypt_Decrypt.inc

  included from AES256_Encrypt.cpp or AES256_Decrypt.cpp
*/

#if defined(AES256_ENCRYPT_IMPLEMENT__) || defined(AES256_DECRYPT_IMPLEMENT__)

#if defined(AES256_ENCRYPT_IMPLEMENT__)
BOOL aes256_encrypt(char *src, char *dst, char *pwd)
#endif
#if defined(AES256_DECRYPT_IMPLEMENT__)
BOOL aes256_decrypt(char *src, char *dst, char *pwd)
#endif
{
  BOOL status = FALSE;
  HCRYPTPROV prov = NULL;
  HCRYPTKEY key = NULL;
  FILE *ifp = NULL;
  FILE *ofp = NULL;

  EVERIFY(CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES,
    CRYPT_VERIFYCONTEXT | CRYPT_SILENT));
  EVERIFY(ifp = fopen(src, "rb"));
  EVERIFY(ofp = fopen(dst, "wb"));
  BYTE buf[32 * 32]; // (32 bytes = 256 bits) x N
  BYTE Salted[8] = {'S', 'a', 'l', 't', 'e', 'd', '_', '_'};
  BYTE *piv = &buf[sizeof(Salted)];
  int liv = 8;
#if defined(AES256_ENCRYPT_IMPLEMENT__)
  CopyMemory(buf, Salted, sizeof(Salted));
  EVERIFY(CryptGenRandom(prov, liv, piv));
  fwrite(buf, 1, sizeof(Salted) + liv, ofp); // Salted__????????
  EVERIFY(!ferror(ofp));
#endif
#if defined(AES256_DECRYPT_IMPLEMENT__)
  fread(buf, 1, sizeof(Salted) + liv, ifp); // Salted__????????
  EVERIFY(!ferror(ifp));
#endif
  AES_256_KEY_BLOB blob;
  BYTE pbIV[16];
  EVERIFY(Create_AES256_KeyBLOB(prov, (BYTE *)pwd, strlen(pwd), piv, liv,
    &blob, pbIV));
#if 1
  fprintf(stdout, "salt="); dmpbuf(piv, liv, TRUE);
  fprintf(stdout, "key="); dmpbuf(blob.pbDerivedKey, 32, TRUE);
  fprintf(stdout, "iv ="); dmpbuf(pbIV, 16, TRUE);
#endif
  EVERIFY(CryptImportKey(prov, (BYTE *)&blob, sizeof(blob),
    NULL, CRYPT_EXPORTABLE, &key));
  DWORD padding = PKCS5_PADDING; // default
  EVERIFY(CryptSetKeyParam(key, KP_PADDING, (BYTE *)&padding, 0));
  DWORD mode = CRYPT_MODE_CBC; // default
  EVERIFY(CryptSetKeyParam(key, KP_MODE, (BYTE *)&mode, 0));
  EVERIFY(CryptSetKeyParam(key, KP_IV, pbIV, 0)); // Initial Vector
  do{
    DWORD count = fread(buf, 1, sizeof(buf), ifp);
    EVERIFY(!ferror(ifp));
    // fprintf(stdout, "count in: %d\n", count);
#if defined(AES256_ENCRYPT_IMPLEMENT__)
    EVERIFY(CryptEncrypt(key, 0, feof(ifp), 0, buf, &count, sizeof(buf)));
#endif
#if defined(AES256_DECRYPT_IMPLEMENT__)
    EVERIFY(CryptDecrypt(key, 0, feof(ifp), 0, buf, &count));
#endif
    // fprintf(stdout, "count out: %d\n", count);
    fwrite(buf, 1, count, ofp);
    EVERIFY(!ferror(ofp));
  }while(!feof(ifp));
  status = TRUE;
  fprintf(stdout, "OK\n");

done:
  if(ofp) fclose(ofp);
  if(ifp) fclose(ifp);
  if(key) VERIFY(CryptDestroyKey(key));
  if(prov) VERIFY(CryptReleaseContext(prov, 0));
  return status;
}

#endif
