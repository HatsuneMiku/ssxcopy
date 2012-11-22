/*
  CompressCrypt.cpp

  from CryptCompress.c (...\prj\util\CryptCompress)
  or Encrypt.c / Decrypt.c (...\prj\util\vcencrypt)

  cl CompressCrypt.cpp AES256_KeyBLOB.cpp kernel32.lib user32.lib gdi32.lib \
    advapi32.lib crypt32.lib libbz2.lib -DUNICODE -EHsc (-DDEBUG)
*/

#include "AES256_KeyBLOB.h"
#include <cstring>

#include "bzlib.h"
#include <iomanip>
#include <ostream>
#include <sstream>
#include <string>

#if _WIN32_WINNT >= 0x0600
#define ENCRYPT_CSP PROV_RSA_AES
#define ENCRYPT_ALGORITHM CALG_AES_256 // CALG_AES_256: 16xN bytes
#define ENCRYPT_KEYLEN (256 * 0x10000)
#else
#define ENCRYPT_CSP PROV_RSA_FULL
#define ENCRYPT_ALGORITHM CALG_RC2 // CALG_RC2: 16xN bytes, CALG_RC4: same size
#define ENCRYPT_KEYLEN 0
#endif

#define ERR_RETURN(s, f) do{ \
    int r = (f); \
    if(r != BZ_OK){ \
      std::ostringstream oss; \
      oss << s << r; \
      return oss.str(); \
    } \
  }while(0)
#define BUF_LEN (64 * 1024) // 8192 // or malloc (8192 * 1024) to high speed

using namespace std;

string compress_stream_to_stream(FILE *ofp, FILE *ifp)
{
  char buf[BUF_LEN];
  bz_stream bz = {0}; bz.bzalloc = NULL; bz.bzfree = NULL; bz.opaque = NULL;
  bz.next_in = NULL; bz.avail_in = 0;
  ERR_RETURN("bzCompressInit: ", BZ2_bzCompressInit(&bz, 9, 0, 0));
  int stream_status = BZ_OK; bz.next_out = buf; bz.avail_out = sizeof(buf);
  while(stream_status != BZ_STREAM_END){
    char inbuf[BUF_LEN];
    fprintf(stdout, ".");
    if(!bz.avail_in){
      bz.next_in = inbuf;
      bz.avail_in = fread(inbuf, 1, sizeof(inbuf), ifp);
    }
    int action = bz.avail_in ? BZ_RUN : BZ_FINISH;
    if((stream_status = BZ2_bzCompress(&bz, action)) == BZ_STREAM_END) break;
    if((stream_status != BZ_OK)
    && (stream_status != BZ_RUN_OK)
    && (stream_status != BZ_FLUSH_OK)
    && (stream_status != BZ_FINISH_OK)){
      ostringstream oss;
      oss << "bzCompress: " << stream_status;
      return oss.str();
    }
    if(!bz.avail_out){
      fwrite(buf, 1, sizeof(buf), ofp);
      bz.next_out = buf; bz.avail_out = sizeof(buf);
    }
  }
  if(size_t remain = sizeof(buf) - bz.avail_out){
    fwrite(buf, 1, remain, ofp);
  }
  ERR_RETURN("bzCompressEnd: ", BZ2_bzCompressEnd(&bz));
  return string("");
}

string decompress_stream_to_stream(FILE *ofp, FILE *ifp)
{
  char buf[BUF_LEN];
  bz_stream bz = {0}; bz.bzalloc = NULL; bz.bzfree = NULL; bz.opaque = NULL;
  bz.next_in = NULL; bz.avail_in = 0;
  ERR_RETURN("bzDecompressInit: ", BZ2_bzDecompressInit(&bz, 0, 0));
  int stream_status = BZ_OK; bz.next_out = buf; bz.avail_out = sizeof(buf);
  while(stream_status != BZ_STREAM_END){
    char inbuf[BUF_LEN];
    fprintf(stdout, ".");
    if(!bz.avail_in){
      bz.next_in = inbuf;
      bz.avail_in = fread(inbuf, 1, sizeof(inbuf), ifp);
    }
    if((stream_status = BZ2_bzDecompress(&bz)) == BZ_STREAM_END) break;
    ERR_RETURN("bzDecompress: ", stream_status);
    if(!bz.avail_out){
      fwrite(buf, 1, sizeof(buf), ofp);
      bz.next_out = buf; bz.avail_out = sizeof(buf);
    }
  }
  if(size_t remain = sizeof(buf) - bz.avail_out){
    fwrite(buf, 1, remain, ofp);
  }
  ERR_RETURN("bzDecompressEnd: ", BZ2_bzDecompressEnd(&bz));
  return string("");
}

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
  {
    fprintf(stdout, "bzCompress test ");
    // FILE *ifp = fopen("..\\privatedata\\ssxcopy-master.tar", "rb");
    // FILE *ofp = fopen("..\\privatedata\\ssxcopy-master.tar.bz2", "wb");
    FILE *ifp = fopen("..\\privatedata\\test.mp3", "rb");
    FILE *ofp = fopen("..\\privatedata\\test.mp3.bz2", "wb");
    if(!ifp || !ofp){
      fprintf(stderr, "file is not found\n");
    }else{
      string s(compress_stream_to_stream(ofp, ifp));
      if(s.length()) fprintf(stderr, "error: %s\n", s.c_str());
    }
    if(ofp) fclose(ofp);
    if(ifp) fclose(ifp);
    fprintf(stdout, "\n");
  }
  {
    fprintf(stdout, "bzDecompress test ");
    // FILE *ifp = fopen("..\\privatedata\\ssxcopy-master.tar.bz2", "rb");
    // FILE *ofp = fopen("..\\privatedata\\ssxcopy-master.tar.bz2.x", "wb");
    FILE *ifp = fopen("..\\privatedata\\test.mp3.bz2", "rb");
    FILE *ofp = fopen("..\\privatedata\\test.mp3.bz2.x", "wb");
    if(!ifp || !ofp){
      fprintf(stderr, "file is not found\n");
    }else{
      string s(decompress_stream_to_stream(ofp, ifp));
      if(s.length()) fprintf(stderr, "error: %s\n", s.c_str());
    }
    if(ofp) fclose(ofp);
    if(ifp) fclose(ifp);
    fprintf(stdout, "\n");
  }
  return 0;
}
