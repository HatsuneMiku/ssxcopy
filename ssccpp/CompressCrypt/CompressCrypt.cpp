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
#include <sys/types.h>
#include <sys/stat.h>

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
#define BUF_LEN (32 * 1024) // or malloc (8192 * 1024) to high speed

using namespace std;

fpos_t get_file_size_from_filename(char *filename)
{
  struct _stati64 st;
  if(_stati64(filename, &st)) return 0;
  return st.st_size;
}

fpos_t get_file_size_from_fp(FILE *fp)
{
  _fseeki64(fp, 0, SEEK_END);
  fpos_t sz;
  int result = fgetpos(fp, &sz);
  _fseeki64(fp, 0, SEEK_SET);
  return result ? 0 : sz;
}

string compress_stream_to_stream(FILE *ofp, FILE *ifp, fpos_t ifsz)
{
  fpos_t pos = 0;
  char buf[BUF_LEN];
  bz_stream bz = {0}; bz.bzalloc = NULL; bz.bzfree = NULL; bz.opaque = NULL;
  bz.next_in = NULL; bz.avail_in = 0;
  ERR_RETURN("bzCompressInit: ", BZ2_bzCompressInit(&bz, 9, 0, 0));
  int stream_status = BZ_OK; bz.next_out = buf; bz.avail_out = sizeof(buf);
  while(stream_status != BZ_STREAM_END){
    char inbuf[BUF_LEN];
    if(!bz.avail_in){
      bz.next_in = inbuf;
      bz.avail_in = fread(inbuf, 1, sizeof(inbuf), ifp);
      fprintf(stdout, "\x0d%3d", 100 * (pos += bz.avail_in) / ifsz);
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

string decompress_stream_to_stream(FILE *ofp, FILE *ifp, fpos_t ifsz)
{
  fpos_t pos = 0;
  char buf[BUF_LEN];
  bz_stream bz = {0}; bz.bzalloc = NULL; bz.bzfree = NULL; bz.opaque = NULL;
  bz.next_in = NULL; bz.avail_in = 0;
  ERR_RETURN("bzDecompressInit: ", BZ2_bzDecompressInit(&bz, 0, 0));
  int stream_status = BZ_OK; bz.next_out = buf; bz.avail_out = sizeof(buf);
  while(stream_status != BZ_STREAM_END){
    char inbuf[BUF_LEN];
    if(!bz.avail_in){
      bz.next_in = inbuf;
      bz.avail_in = fread(inbuf, 1, sizeof(inbuf), ifp);
      fprintf(stdout, "\x0d%3d", 100 * (pos += bz.avail_in) / ifsz);
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
    // char *infile = "..\\privatedata\\ssxcopy-master.tar";
    // char *outfile = "..\\privatedata\\ssxcopy-master.tar.bz2";
    char *infile = "..\\privatedata\\test.mp3";
    char *outfile = "..\\privatedata\\test.mp3.bz2";
    fprintf(stdout, "  0%% bzCompress %s ", infile);
    FILE *ifp = fopen(infile, "rb");
    FILE *ofp = fopen(outfile, "wb");
    if(!ifp || !ofp){
      fprintf(stderr, "file is not found\n");
    }else{
      fpos_t ifsz = get_file_size_from_fp(ifp);
      fprintf(stdout, "%lld", ifsz);
      string s(compress_stream_to_stream(ofp, ifp, ifsz));
      if(s.length()) fprintf(stderr, "error: %s\n", s.c_str());
    }
    if(ofp) fclose(ofp);
    if(ifp) fclose(ifp);
    fprintf(stdout, "\n");
    fprintf(stdout, "output: %s %lld\n",
      outfile, get_file_size_from_filename(outfile));
  }
  {
    // char *infile = "..\\privatedata\\ssxcopy-master.tar.bz2";
    // char *outfile = "..\\privatedata\\ssxcopy-master.tar.bz2.x";
    char *infile = "..\\privatedata\\test.mp3.bz2";
    char *outfile = "..\\privatedata\\test.mp3.bz2.x";
    fprintf(stdout, "  0%% bzDecompress %s ", infile);
    FILE *ifp = fopen(infile, "rb");
    FILE *ofp = fopen(outfile, "wb");
    if(!ifp || !ofp){
      fprintf(stderr, "file is not found\n");
    }else{
      fpos_t ifsz = get_file_size_from_fp(ifp);
      fprintf(stdout, "%lld", ifsz);
      string s(decompress_stream_to_stream(ofp, ifp, ifsz));
      if(s.length()) fprintf(stderr, "error: %s\n", s.c_str());
    }
    if(ofp) fclose(ofp);
    if(ifp) fclose(ifp);
    fprintf(stdout, "\n");
    fprintf(stdout, "output: %s %lld\n",
      outfile, get_file_size_from_filename(outfile));
  }
  return 0;
}
