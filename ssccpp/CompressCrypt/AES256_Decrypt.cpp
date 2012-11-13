/*
  AES256_Decrypt.cpp

  cl AES256_Decrypt.cpp AES256_KeyBLOB.cpp kernel32.lib user32.lib gdi32.lib \
    advapi32.lib -DUNICODE -EHsc (-DDEBUG)
*/

#include "AES256_KeyBLOB.h"
#include <cstring>

#define AES256_DECRYPT_IMPLEMENT__
#include "AES256_Encrypt_Decrypt.inc"

int main(int ac, char **av)
{
  if(ac < 4) fprintf(stderr, "Usage: %s <src> <dst> <pwd>\n", av[0]);
  else aes256_decrypt(av[1], av[2], av[3]);
  return 0;
}
