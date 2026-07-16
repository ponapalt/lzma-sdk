/* Xz.c - Xz
2024-03-01 : Igor Pavlov : Public domain */

#include "Precomp.h"

/* SSP: SHA-256 for the xz integrity check is provided by OpenSSL (see XzSha256_*
   below). Keeping the OpenSSL include in this .c file confines it to the C SDK,
   out of Xz.h and any C++ TU. */
#include <openssl/evp.h>

#include "7zCrc.h"
#include "CpuArch.h"
#include "Xz.h"
#include "XzCrc64.h"

/* SSP: thin wrappers over OpenSSL EVP for the xz SHA-256 integrity check. The
   context (EVP_MD_CTX*) is stored as an opaque void* in the caller's struct and
   is lazily allocated on the first Init, reused across Init/Update/Final cycles,
   and released by XzSha256_Free. SHA-256 does not fail in practice, so return
   values are ignored to keep the original void signatures. */
void XzSha256_Init(void **pp)
{
  EVP_MD_CTX *ctx = (EVP_MD_CTX *)*pp;
  if (ctx == NULL)
  {
    ctx = EVP_MD_CTX_new();
    *pp = ctx;
  }
  EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
}

void XzSha256_Update(void **pp, const void *data, size_t size)
{
  EVP_DigestUpdate((EVP_MD_CTX *)*pp, data, size);
}

void XzSha256_Final(void **pp, Byte *digest)
{
  unsigned int outLen = 0;
  EVP_DigestFinal_ex((EVP_MD_CTX *)*pp, digest, &outLen);
}

void XzSha256_Free(void **pp)
{
  if (*pp)
  {
    EVP_MD_CTX_free((EVP_MD_CTX *)*pp);
    *pp = NULL;
  }
}

const Byte XZ_SIG[XZ_SIG_SIZE] = { 0xFD, '7', 'z', 'X', 'Z', 0 };
/* const Byte XZ_FOOTER_SIG[XZ_FOOTER_SIG_SIZE] = { 'Y', 'Z' }; */

unsigned Xz_WriteVarInt(Byte *buf, UInt64 v)
{
  unsigned i = 0;
  do
  {
    buf[i++] = (Byte)((v & 0x7F) | 0x80);
    v >>= 7;
  }
  while (v != 0);
  buf[(size_t)i - 1] &= 0x7F;
  return i;
}

void Xz_Construct(CXzStream *p)
{
  p->numBlocks = 0;
  p->blocks = NULL;
  p->flags = 0;
}

void Xz_Free(CXzStream *p, ISzAllocPtr alloc)
{
  ISzAlloc_Free(alloc, p->blocks);
  p->numBlocks = 0;
  p->blocks = NULL;
}

unsigned XzFlags_GetCheckSize(CXzStreamFlags f)
{
  unsigned t = XzFlags_GetCheckType(f);
  return (t == 0) ? 0 : ((unsigned)4 << ((t - 1) / 3));
}

void XzCheck_Init(CXzCheck *p, unsigned mode)
{
  p->mode = mode;
  switch (mode)
  {
    case XZ_CHECK_CRC32: p->crc = CRC_INIT_VAL; break;
    case XZ_CHECK_CRC64: p->crc64 = CRC64_INIT_VAL; break;
    case XZ_CHECK_SHA256: XzSha256_Init(&p->sha); break;
    default: break;
  }
}

void XzCheck_Update(CXzCheck *p, const void *data, size_t size)
{
  switch (p->mode)
  {
    case XZ_CHECK_CRC32: p->crc = CrcUpdate(p->crc, data, size); break;
    case XZ_CHECK_CRC64: p->crc64 = Crc64Update(p->crc64, data, size); break;
    case XZ_CHECK_SHA256: XzSha256_Update(&p->sha, (const Byte *)data, size); break;
    default: break;
  }
}

int XzCheck_Final(CXzCheck *p, Byte *digest)
{
  switch (p->mode)
  {
    case XZ_CHECK_CRC32:
      SetUi32(digest, CRC_GET_DIGEST(p->crc))
      break;
    case XZ_CHECK_CRC64:
    {
      int i;
      UInt64 v = CRC64_GET_DIGEST(p->crc64);
      for (i = 0; i < 8; i++, v >>= 8)
        digest[i] = (Byte)(v & 0xFF);
      break;
    }
    case XZ_CHECK_SHA256:
      XzSha256_Final(&p->sha, digest);
      break;
    default:
      return 0;
  }
  return 1;
}
