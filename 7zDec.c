/* 7zDec.c -- Decoding from 7z folder
: Igor Pavlov : Public domain */

#include "Precomp.h"

#include <string.h>

/* SSP: enable PPMd decoding (requires Ppmd7.c / Ppmd7Dec.c to be linked) */
#define Z7_PPMD_SUPPORT

#include "7z.h"
#include "7zCrc.h"

#include "Bcj2.h"
#include "Bra.h"
#include "CpuArch.h"
#include "Delta.h"
#include "LzmaDec.h"
#include "Lzma2Dec.h"

/* SSP: AES-256-CBC / SHA-256 for 7zAES are provided by OpenSSL (see Sz7zAes_* below) */
#include <openssl/evp.h>
#include <openssl/rand.h>
#ifdef Z7_PPMD_SUPPORT
#include "Ppmd7.h"
#endif

#define k_Copy 0
#ifndef Z7_NO_METHOD_LZMA2
#define k_LZMA2 0x21
#endif
#define k_LZMA  0x30101
#define k_BCJ2  0x303011B

#if !defined(Z7_NO_METHODS_FILTERS)
#define Z7_USE_BRANCH_FILTER
#endif

#if !defined(Z7_NO_METHODS_FILTERS) || \
     defined(Z7_USE_NATIVE_BRANCH_FILTER) && defined(MY_CPU_ARM64)
#define Z7_USE_FILTER_ARM64
#ifndef Z7_USE_BRANCH_FILTER
#define Z7_USE_BRANCH_FILTER
#endif
#define k_ARM64 0xa
#endif

#if !defined(Z7_NO_METHODS_FILTERS) || \
     defined(Z7_USE_NATIVE_BRANCH_FILTER) && defined(MY_CPU_ARMT)
#define Z7_USE_FILTER_ARMT
#ifndef Z7_USE_BRANCH_FILTER
#define Z7_USE_BRANCH_FILTER
#endif
#define k_ARMT  0x3030701
#endif

#ifndef Z7_NO_METHODS_FILTERS
#define k_Delta 3
#define k_RISCV 0xb
#define k_BCJ   0x3030103
#define k_PPC   0x3030205
#define k_IA64  0x3030401
#define k_ARM   0x3030501
#define k_SPARC 0x3030805
#endif

#ifdef Z7_PPMD_SUPPORT

#define k_PPMD 0x30401

typedef struct
{
  IByteIn vt;
  const Byte *cur;
  const Byte *end;
  const Byte *begin;
  UInt64 processed;
  BoolInt extra;
  SRes res;
  ILookInStreamPtr inStream;
} CByteInToLook;

static Byte ReadByte(IByteInPtr pp)
{
  Z7_CONTAINER_FROM_VTBL_TO_DECL_VAR_pp_vt_p(CByteInToLook)
  if (p->cur != p->end)
    return *p->cur++;
  if (p->res == SZ_OK)
  {
    size_t size = (size_t)(p->cur - p->begin);
    p->processed += size;
    p->res = ILookInStream_Skip(p->inStream, size);
    size = (1 << 25);
    p->res = ILookInStream_Look(p->inStream, (const void **)&p->begin, &size);
    p->cur = p->begin;
    p->end = p->begin + size;
    if (size != 0)
      return *p->cur++;
  }
  p->extra = True;
  return 0;
}

static SRes SzDecodePpmd(const Byte *props, unsigned propsSize, UInt64 inSize, ILookInStreamPtr inStream,
    Byte *outBuffer, SizeT outSize, ISzAllocPtr allocMain)
{
  CPpmd7 ppmd;
  CByteInToLook s;
  SRes res = SZ_OK;

  s.vt.Read = ReadByte;
  s.inStream = inStream;
  s.begin = s.end = s.cur = NULL;
  s.extra = False;
  s.res = SZ_OK;
  s.processed = 0;

  if (propsSize != 5)
    return SZ_ERROR_UNSUPPORTED;

  {
    unsigned order = props[0];
    UInt32 memSize = GetUi32(props + 1);
    if (order < PPMD7_MIN_ORDER ||
        order > PPMD7_MAX_ORDER ||
        memSize < PPMD7_MIN_MEM_SIZE ||
        memSize > PPMD7_MAX_MEM_SIZE)
      return SZ_ERROR_UNSUPPORTED;
    Ppmd7_Construct(&ppmd);
    if (!Ppmd7_Alloc(&ppmd, memSize, allocMain))
      return SZ_ERROR_MEM;
    Ppmd7_Init(&ppmd, order);
  }
  {
    ppmd.rc.dec.Stream = &s.vt;
    if (!Ppmd7z_RangeDec_Init(&ppmd.rc.dec))
      res = SZ_ERROR_DATA;
    else if (!s.extra)
    {
      Byte *buf = outBuffer;
      const Byte *lim = buf + outSize;
      for (; buf != lim; buf++)
      {
        int sym = Ppmd7z_DecodeSymbol(&ppmd);
        if (s.extra || sym < 0)
          break;
        *buf = (Byte)sym;
      }
      if (buf != lim)
        res = SZ_ERROR_DATA;
      else if (!Ppmd7z_RangeDec_IsFinishedOK(&ppmd.rc.dec))
      {
        /* if (Ppmd7z_DecodeSymbol(&ppmd) != PPMD7_SYM_END || !Ppmd7z_RangeDec_IsFinishedOK(&ppmd.rc.dec)) */
        res = SZ_ERROR_DATA;
      }
    }
    if (s.extra)
      res = (s.res != SZ_OK ? s.res : SZ_ERROR_DATA);
    else if (s.processed + (size_t)(s.cur - s.begin) != inSize)
      res = SZ_ERROR_DATA;
  }
  Ppmd7_Free(&ppmd, allocMain);
  return res;
}

#endif


static SRes SzDecodeLzma(const Byte *props, unsigned propsSize, UInt64 inSize, ILookInStreamPtr inStream,
    Byte *outBuffer, SizeT outSize, ISzAllocPtr allocMain)
{
  CLzmaDec state;
  SRes res = SZ_OK;

  LzmaDec_CONSTRUCT(&state)
  RINOK(LzmaDec_AllocateProbs(&state, props, propsSize, allocMain))
  state.dic = outBuffer;
  state.dicBufSize = outSize;
  LzmaDec_Init(&state);

  for (;;)
  {
    const void *inBuf = NULL;
    size_t lookahead = (1 << 18);
    if (lookahead > inSize)
      lookahead = (size_t)inSize;
    res = ILookInStream_Look(inStream, &inBuf, &lookahead);
    if (res != SZ_OK)
      break;

    {
      SizeT inProcessed = (SizeT)lookahead, dicPos = state.dicPos;
      ELzmaStatus status;
      res = LzmaDec_DecodeToDic(&state, outSize, (const Byte *)inBuf, &inProcessed, LZMA_FINISH_END, &status);
      lookahead -= inProcessed;
      inSize -= inProcessed;
      if (res != SZ_OK)
        break;

      if (status == LZMA_STATUS_FINISHED_WITH_MARK)
      {
        if (outSize != state.dicPos || inSize != 0)
          res = SZ_ERROR_DATA;
        break;
      }

      if (outSize == state.dicPos && inSize == 0 && status == LZMA_STATUS_MAYBE_FINISHED_WITHOUT_MARK)
        break;

      if (inProcessed == 0 && dicPos == state.dicPos)
      {
        res = SZ_ERROR_DATA;
        break;
      }

      res = ILookInStream_Skip(inStream, inProcessed);
      if (res != SZ_OK)
        break;
    }
  }

  LzmaDec_FreeProbs(&state, allocMain);
  return res;
}


#ifndef Z7_NO_METHOD_LZMA2

static SRes SzDecodeLzma2(const Byte *props, unsigned propsSize, UInt64 inSize, ILookInStreamPtr inStream,
    Byte *outBuffer, SizeT outSize, ISzAllocPtr allocMain)
{
  CLzma2Dec state;
  SRes res = SZ_OK;

  Lzma2Dec_CONSTRUCT(&state)
  if (propsSize != 1)
    return SZ_ERROR_DATA;
  RINOK(Lzma2Dec_AllocateProbs(&state, props[0], allocMain))
  state.decoder.dic = outBuffer;
  state.decoder.dicBufSize = outSize;
  Lzma2Dec_Init(&state);

  for (;;)
  {
    const void *inBuf = NULL;
    size_t lookahead = (1 << 18);
    if (lookahead > inSize)
      lookahead = (size_t)inSize;
    res = ILookInStream_Look(inStream, &inBuf, &lookahead);
    if (res != SZ_OK)
      break;

    {
      SizeT inProcessed = (SizeT)lookahead, dicPos = state.decoder.dicPos;
      ELzmaStatus status;
      res = Lzma2Dec_DecodeToDic(&state, outSize, (const Byte *)inBuf, &inProcessed, LZMA_FINISH_END, &status);
      lookahead -= inProcessed;
      inSize -= inProcessed;
      if (res != SZ_OK)
        break;

      if (status == LZMA_STATUS_FINISHED_WITH_MARK)
      {
        if (outSize != state.decoder.dicPos || inSize != 0)
          res = SZ_ERROR_DATA;
        break;
      }

      if (inProcessed == 0 && dicPos == state.decoder.dicPos)
      {
        res = SZ_ERROR_DATA;
        break;
      }

      res = ILookInStream_Skip(inStream, inProcessed);
      if (res != SZ_OK)
        break;
    }
  }

  Lzma2Dec_FreeProbs(&state, allocMain);
  return res;
}

#endif


static SRes SzDecodeCopy(UInt64 inSize, ILookInStreamPtr inStream, Byte *outBuffer)
{
  while (inSize > 0)
  {
    const void *inBuf;
    size_t curSize = (1 << 18);
    if (curSize > inSize)
      curSize = (size_t)inSize;
    RINOK(ILookInStream_Look(inStream, &inBuf, &curSize))
    if (curSize == 0)
      return SZ_ERROR_INPUT_EOF;
    memcpy(outBuffer, inBuf, curSize);
    outBuffer += curSize;
    inSize -= curSize;
    RINOK(ILookInStream_Skip(inStream, curSize))
  }
  return SZ_OK;
}

static BoolInt IS_MAIN_METHOD(UInt32 m)
{
  switch (m)
  {
    case k_Copy:
    case k_LZMA:
  #ifndef Z7_NO_METHOD_LZMA2
    case k_LZMA2:
  #endif
  #ifdef Z7_PPMD_SUPPORT
    case k_PPMD:
  #endif
      return True;
    default:
      return False;
  }
}

static BoolInt IS_SUPPORTED_CODER(const CSzCoderInfo *c)
{
  return
      c->NumStreams == 1
      /* && c->MethodID <= (UInt32)0xFFFFFFFF */
      && IS_MAIN_METHOD((UInt32)c->MethodID);
}

#define IS_BCJ2(c) ((c)->MethodID == k_BCJ2 && (c)->NumStreams == 4)

static SRes CheckSupportedFolder(const CSzFolder *f)
{
  if (f->NumCoders < 1 || f->NumCoders > 4)
    return SZ_ERROR_UNSUPPORTED;
  if (!IS_SUPPORTED_CODER(&f->Coders[0]))
    return SZ_ERROR_UNSUPPORTED;
  if (f->NumCoders == 1)
  {
    if (f->NumPackStreams != 1 || f->PackStreams[0] != 0 || f->NumBonds != 0)
      return SZ_ERROR_UNSUPPORTED;
    return SZ_OK;
  }
  
  
  #if defined(Z7_USE_BRANCH_FILTER)

  if (f->NumCoders == 2)
  {
    const CSzCoderInfo *c = &f->Coders[1];
    if (
        /* c->MethodID > (UInt32)0xFFFFFFFF || */
        c->NumStreams != 1
        || f->NumPackStreams != 1
        || f->PackStreams[0] != 0
        || f->NumBonds != 1
        || f->Bonds[0].InIndex != 1
        || f->Bonds[0].OutIndex != 0)
      return SZ_ERROR_UNSUPPORTED;
    switch ((UInt32)c->MethodID)
    {
    #if !defined(Z7_NO_METHODS_FILTERS)
      case k_Delta:
      case k_BCJ:
      case k_PPC:
      case k_IA64:
      case k_SPARC:
      case k_ARM:
      case k_RISCV:
    #endif
    #ifdef Z7_USE_FILTER_ARM64
      case k_ARM64:
    #endif
    #ifdef Z7_USE_FILTER_ARMT
      case k_ARMT:
    #endif
        break;
      default:
        return SZ_ERROR_UNSUPPORTED;
    }
    return SZ_OK;
  }

  #endif

  
  if (f->NumCoders == 4)
  {
    if (!IS_SUPPORTED_CODER(&f->Coders[1])
        || !IS_SUPPORTED_CODER(&f->Coders[2])
        || !IS_BCJ2(&f->Coders[3]))
      return SZ_ERROR_UNSUPPORTED;
    if (f->NumPackStreams != 4
        || f->PackStreams[0] != 2
        || f->PackStreams[1] != 6
        || f->PackStreams[2] != 1
        || f->PackStreams[3] != 0
        || f->NumBonds != 3
        || f->Bonds[0].InIndex != 5 || f->Bonds[0].OutIndex != 0
        || f->Bonds[1].InIndex != 4 || f->Bonds[1].OutIndex != 1
        || f->Bonds[2].InIndex != 3 || f->Bonds[2].OutIndex != 2)
      return SZ_ERROR_UNSUPPORTED;
    return SZ_OK;
  }
  
  return SZ_ERROR_UNSUPPORTED;
}






static SRes SzFolder_Decode2(const CSzFolder *folder,
    const Byte *propsData,
    const UInt64 *unpackSizes,
    const UInt64 *packPositions,
    ILookInStreamPtr inStream, UInt64 startPos,
    Byte *outBuffer, SizeT outSize, ISzAllocPtr allocMain,
    Byte *tempBuf[])
{
  UInt32 ci;
  SizeT tempSizes[3] = { 0, 0, 0};
  SizeT tempSize3 = 0;
  Byte *tempBuf3 = 0;

  RINOK(CheckSupportedFolder(folder))

  for (ci = 0; ci < folder->NumCoders; ci++)
  {
    const CSzCoderInfo *coder = &folder->Coders[ci];

    if (IS_MAIN_METHOD((UInt32)coder->MethodID))
    {
      UInt32 si = 0;
      UInt64 offset;
      UInt64 inSize;
      Byte *outBufCur = outBuffer;
      SizeT outSizeCur = outSize;
      if (folder->NumCoders == 4)
      {
        const UInt32 indices[] = { 3, 2, 0 };
        const UInt64 unpackSize = unpackSizes[ci];
        si = indices[ci];
        if (ci < 2)
        {
          Byte *temp;
          outSizeCur = (SizeT)unpackSize;
          if (outSizeCur != unpackSize)
            return SZ_ERROR_MEM;
          temp = (Byte *)ISzAlloc_Alloc(allocMain, outSizeCur);
          if (!temp && outSizeCur != 0)
            return SZ_ERROR_MEM;
          outBufCur = tempBuf[1 - ci] = temp;
          tempSizes[1 - ci] = outSizeCur;
        }
        else if (ci == 2)
        {
          if (unpackSize > outSize) /* check it */
            return SZ_ERROR_PARAM;
          tempBuf3 = outBufCur = outBuffer + (outSize - (size_t)unpackSize);
          tempSize3 = outSizeCur = (SizeT)unpackSize;
        }
        else
          return SZ_ERROR_UNSUPPORTED;
      }
      offset = packPositions[si];
      inSize = packPositions[(size_t)si + 1] - offset;
      RINOK(LookInStream_SeekTo(inStream, startPos + offset))

      if (coder->MethodID == k_Copy)
      {
        if (inSize != outSizeCur) /* check it */
          return SZ_ERROR_DATA;
        RINOK(SzDecodeCopy(inSize, inStream, outBufCur))
      }
      else if (coder->MethodID == k_LZMA)
      {
        RINOK(SzDecodeLzma(propsData + coder->PropsOffset, coder->PropsSize, inSize, inStream, outBufCur, outSizeCur, allocMain))
      }
    #ifndef Z7_NO_METHOD_LZMA2
      else if (coder->MethodID == k_LZMA2)
      {
        RINOK(SzDecodeLzma2(propsData + coder->PropsOffset, coder->PropsSize, inSize, inStream, outBufCur, outSizeCur, allocMain))
      }
    #endif
    #ifdef Z7_PPMD_SUPPORT
      else if (coder->MethodID == k_PPMD)
      {
        RINOK(SzDecodePpmd(propsData + coder->PropsOffset, coder->PropsSize, inSize, inStream, outBufCur, outSizeCur, allocMain))
      }
    #endif
      else
        return SZ_ERROR_UNSUPPORTED;
    }
    else if (coder->MethodID == k_BCJ2)
    {
      const UInt64 offset = packPositions[1];
      const UInt64 s3Size = packPositions[2] - offset;
      
      if (ci != 3)
        return SZ_ERROR_UNSUPPORTED;
      
      tempSizes[2] = (SizeT)s3Size;
      if (tempSizes[2] != s3Size)
        return SZ_ERROR_MEM;
      tempBuf[2] = (Byte *)ISzAlloc_Alloc(allocMain, tempSizes[2]);
      if (!tempBuf[2] && tempSizes[2] != 0)
        return SZ_ERROR_MEM;
      
      RINOK(LookInStream_SeekTo(inStream, startPos + offset))
      RINOK(SzDecodeCopy(s3Size, inStream, tempBuf[2]))

      if ((tempSizes[0] & 3) != 0 ||
          (tempSizes[1] & 3) != 0 ||
          tempSize3 + tempSizes[0] + tempSizes[1] != outSize)
        return SZ_ERROR_DATA;

      {
        CBcj2Dec p;
        
        p.bufs[0] = tempBuf3;   p.lims[0] = tempBuf3 + tempSize3;
        p.bufs[1] = tempBuf[0]; p.lims[1] = tempBuf[0] + tempSizes[0];
        p.bufs[2] = tempBuf[1]; p.lims[2] = tempBuf[1] + tempSizes[1];
        p.bufs[3] = tempBuf[2]; p.lims[3] = tempBuf[2] + tempSizes[2];
        
        p.dest = outBuffer;
        p.destLim = outBuffer + outSize;
        
        Bcj2Dec_Init(&p);
        RINOK(Bcj2Dec_Decode(&p))

        {
          unsigned i;
          for (i = 0; i < 4; i++)
            if (p.bufs[i] != p.lims[i])
              return SZ_ERROR_DATA;
          if (p.dest != p.destLim || !Bcj2Dec_IsMaybeFinished(&p))
            return SZ_ERROR_DATA;
        }
      }
    }
#if defined(Z7_USE_BRANCH_FILTER)
    else if (ci == 1)
    {
#if !defined(Z7_NO_METHODS_FILTERS)
      if (coder->MethodID == k_Delta)
      {
        if (coder->PropsSize != 1)
          return SZ_ERROR_UNSUPPORTED;
        {
          Byte state[DELTA_STATE_SIZE];
          Delta_Init(state);
          Delta_Decode(state, (unsigned)(propsData[coder->PropsOffset]) + 1, outBuffer, outSize);
        }
        continue;
      }
#endif
     
#ifdef Z7_USE_FILTER_ARM64
      if (coder->MethodID == k_ARM64)
      {
        UInt32 pc = 0;
        if (coder->PropsSize == 4)
        {
          pc = GetUi32(propsData + coder->PropsOffset);
          if (pc & 3)
            return SZ_ERROR_UNSUPPORTED;
        }
        else if (coder->PropsSize != 0)
          return SZ_ERROR_UNSUPPORTED;
        z7_BranchConv_ARM64_Dec(outBuffer, outSize, pc);
        continue;
      }
#endif

#if !defined(Z7_NO_METHODS_FILTERS)
      if (coder->MethodID == k_RISCV)
      {
        UInt32 pc = 0;
        if (coder->PropsSize == 4)
        {
          pc = GetUi32(propsData + coder->PropsOffset);
          if (pc & 1)
            return SZ_ERROR_UNSUPPORTED;
        }
        else if (coder->PropsSize != 0)
          return SZ_ERROR_UNSUPPORTED;
        z7_BranchConv_RISCV_Dec(outBuffer, outSize, pc);
        continue;
      }
#endif
      
#if !defined(Z7_NO_METHODS_FILTERS) || defined(Z7_USE_FILTER_ARMT)
      {
        if (coder->PropsSize != 0)
          return SZ_ERROR_UNSUPPORTED;
       #define CASE_BRA_CONV(isa) case k_ ## isa: Z7_BRANCH_CONV_DEC(isa)(outBuffer, outSize, 0); break; // pc = 0;
        switch (coder->MethodID)
        {
         #if !defined(Z7_NO_METHODS_FILTERS)
          case k_BCJ:
          {
            UInt32 state = Z7_BRANCH_CONV_ST_X86_STATE_INIT_VAL;
            z7_BranchConvSt_X86_Dec(outBuffer, outSize, 0, &state); // pc = 0
            break;
          }
          case k_PPC: Z7_BRANCH_CONV_DEC_2(BranchConv_PPC)(outBuffer, outSize, 0); break; // pc = 0;
          // CASE_BRA_CONV(PPC)
          CASE_BRA_CONV(IA64)
          CASE_BRA_CONV(SPARC)
          CASE_BRA_CONV(ARM)
         #endif
         #if !defined(Z7_NO_METHODS_FILTERS) || defined(Z7_USE_FILTER_ARMT)
          CASE_BRA_CONV(ARMT)
         #endif
          default:
            return SZ_ERROR_UNSUPPORTED;
        }
        continue;
      }
#endif
    } // (c == 1)
#endif // Z7_USE_BRANCH_FILTER
    else
      return SZ_ERROR_UNSUPPORTED;
  }

  return SZ_OK;
}


/* ---------------------------------------------------------------------------
   SSP patch: 7z AES-256 (MethodID 0x06F10701) decode support.

   The public C SDK cannot decode AES-encrypted 7z folders. This block adds a
   password-driven AES-CBC decryptor. The approach is: bulk-decrypt the single
   encrypted pack stream into a temp buffer, rewrite the folder definition with
   the AES coder removed, and re-run the decrypted data through the existing
   SzFolder_Decode2. This keeps all coder/BCJ/Delta/CRC validation intact and
   touches only one branch in SzAr_DecodeFolder (below). The encrypted-header
   case (kEncodedHeader) also flows through SzAr_DecodeFolder, so it is handled
   automatically. Wrong passwords surface as SZ_ERROR_CRC / SZ_ERROR_DATA via
   the existing folder-CRC check.
--------------------------------------------------------------------------- */

#define k_AES 0x6F10701

#define SZ7ZAES_MAX_PASSWORD_BYTES 2048

static Byte   g_7zAesPassword[SZ7ZAES_MAX_PASSWORD_BYTES];
static size_t g_7zAesPasswordSize = 0;
static int    g_7zAesUsed = 0;

void Sz7zAes_SetPassword(const Byte *utf16lePassword, size_t sizeInBytes)
{
  if (!utf16lePassword || sizeInBytes == 0)
  {
    g_7zAesPasswordSize = 0;
    return;
  }
  if (sizeInBytes > SZ7ZAES_MAX_PASSWORD_BYTES)
    sizeInBytes = SZ7ZAES_MAX_PASSWORD_BYTES;
  memcpy(g_7zAesPassword, utf16lePassword, sizeInBytes);
  g_7zAesPasswordSize = sizeInBytes;
}

int  Sz7zAes_WasUsed(void)  { return g_7zAesUsed; }
void Sz7zAes_ResetUsed(void) { g_7zAesUsed = 0; }

static int Sz7zAes_FindAesCoder(const CSzFolder *f)
{
  unsigned i;
  for (i = 0; i < f->NumCoders; i++)
    if (f->Coders[i].MethodID == k_AES && f->Coders[i].NumStreams == 1)
      return (int)i;
  return -1;
}

/* SHA-256 based 7zAES key derivation (the numCyclesPower != 0x3F path, shared by
   both decrypt and encrypt). key = final digest of 2^numCyclesPower rounds of
   SHA256(salt || password || counterLE8); password is the UTF-16LE bytes set by
   Sz7zAes_SetPassword. */
static SRes Sz7zAes_DeriveKey(const Byte *salt, unsigned saltSize, unsigned numCyclesPower, Byte key[32])
{
  EVP_MD_CTX *sha = EVP_MD_CTX_new();
  Byte ctr[8];
  UInt64 numRounds = (UInt64)1 << numCyclesPower;
  unsigned int outLen = 0;
  if (!sha)
    return SZ_ERROR_MEM;
  memset(ctr, 0, 8);
  EVP_DigestInit_ex(sha, EVP_sha256(), NULL);
  do
  {
    unsigned i;
    EVP_DigestUpdate(sha, salt, saltSize);
    EVP_DigestUpdate(sha, g_7zAesPassword, g_7zAesPasswordSize);
    EVP_DigestUpdate(sha, ctr, 8);
    for (i = 0; i < 8; i++)
      if (++ctr[i] != 0)
        break;
  }
  while (--numRounds != 0);
  EVP_DigestFinal_ex(sha, key, &outLen);
  EVP_MD_CTX_free(sha);
  return SZ_OK;
}

/* Derive the AES-256 key and IV from 7zAES coder properties + current password
   (password is the UTF-16LE byte sequence set by Sz7zAes_SetPassword). */
static SRes Sz7zAes_CalcKeyIv(const Byte *props, unsigned propsSize, Byte key[32], Byte iv[16])
{
  unsigned numCyclesPower;
  unsigned saltSize, ivSize;
  const Byte *salt;
  const Byte *ivData;
  Byte firstByte;

  if (propsSize < 1)
    return SZ_ERROR_UNSUPPORTED;
  firstByte = props[0];
  numCyclesPower = (unsigned)(firstByte & 0x3F);

  if ((firstByte & 0xC0) == 0)
  {
    saltSize = 0;
    ivSize = 0;
    salt = props + 1;
    ivData = props + 1;
  }
  else
  {
    if (propsSize < 2)
      return SZ_ERROR_UNSUPPORTED;
    saltSize = (unsigned)((firstByte >> 7) & 1) + (unsigned)(props[1] >> 4);
    ivSize   = (unsigned)((firstByte >> 6) & 1) + (unsigned)(props[1] & 0x0F);
    if ((size_t)2 + saltSize + ivSize > propsSize)
      return SZ_ERROR_UNSUPPORTED;
    salt = props + 2;
    ivData = props + 2 + saltSize;
  }

  if (ivSize > 16)
    return SZ_ERROR_UNSUPPORTED;

  memset(iv, 0, 16);
  memcpy(iv, ivData, ivSize);

  if (numCyclesPower == 0x3F)
  {
    /* special: key = salt || password, zero padded to 32 bytes */
    unsigned pos = 0;
    unsigned i;
    memset(key, 0, 32);
    for (i = 0; i < saltSize && pos < 32; i++)
      key[pos++] = salt[i];
    for (i = 0; (size_t)i < g_7zAesPasswordSize && pos < 32; i++)
      key[pos++] = g_7zAesPassword[i];
  }
  else
  {
    SRes res = Sz7zAes_DeriveKey(salt, saltSize, numCyclesPower, key);
    if (res != SZ_OK)
      return res;
  }
  return SZ_OK;
}

/* AES-256-CBC in-place decrypt of a 16-byte-multiple buffer.
   Failure leaves garbage in the buffer, which the existing folder-CRC
   check downstream reports as SZ_ERROR_CRC. */
static void Sz7zAes_Decrypt(const Byte key[32], const Byte iv[16], Byte *data, size_t size)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int outLen = 0;
  if (!ctx)
    return;
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
  {
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    EVP_DecryptUpdate(ctx, data, &outLen, data, (int)size);
  }
  EVP_CIPHER_CTX_free(ctx);
}

/* 7zAES encryption (SSP): the OpenSSL counterpart of Sz7zAes_Decrypt, used by the
   compressor (C7zipper). Generates a random 16-byte IV, derives the AES-256 key
   from the password set via Sz7zAes_SetPassword (numCyclesPower=19, no salt --
   matching 7-Zip defaults), and AES-256-CBC encrypts `size` bytes (must be a
   16-byte multiple; the caller zero-pads) in place. Emits the 7zAES coder
   properties (18 bytes: numCyclesPower flag byte, size nibble byte, 16-byte IV)
   into props. Keeping this here confines OpenSSL to the C SDK, out of the C++ TU. */
SRes Sz7zAes_Encode(Byte *data, size_t size, Byte *props, unsigned *pPropsSize)
{
  const unsigned numCyclesPower = 19;
  Byte key[32];
  Byte iv[16];
  EVP_CIPHER_CTX *ctx;
  int outLen = 0;
  SRes res;

  if (g_7zAesPasswordSize == 0)
    return SZ_ERROR_PARAM;
  if ((size & 15) != 0)
    return SZ_ERROR_PARAM;
  if (RAND_bytes(iv, 16) != 1)
    return SZ_ERROR_FAIL;

  /* coder props: numCyclesPower | 0x40 (iv-size high bit) + props[1]=0x0F
     -> saltSize = 0, ivSize = 1 + 15 = 16. Mirrors Sz7zAes_CalcKeyIv parsing. */
  props[0] = (Byte)(numCyclesPower | 0x40);
  props[1] = 0x0F;
  memcpy(props + 2, iv, 16);
  *pPropsSize = 18;

  res = Sz7zAes_DeriveKey(NULL, 0, numCyclesPower, key);
  if (res != SZ_OK)
    return res;

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return SZ_ERROR_MEM;
  res = SZ_OK;
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
  {
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (size != 0 && !EVP_EncryptUpdate(ctx, data, &outLen, data, (int)size))
      res = SZ_ERROR_FAIL;
  }
  else
    res = SZ_ERROR_FAIL;
  EVP_CIPHER_CTX_free(ctx);
  return res;
}

/* memory-backed ILookInStream over the decrypted buffer */
typedef struct
{
  ILookInStream vt;
  const Byte *data;
  size_t size;
  size_t pos;
} CSz7zMemInStream;

static SRes Sz7zMem_Look(ILookInStreamPtr pp, const void **buf, size_t *size)
{
  Z7_CONTAINER_FROM_VTBL_TO_DECL_VAR_pp_vt_p(CSz7zMemInStream)
  size_t rem = p->size - p->pos;
  if (*size > rem)
    *size = rem;
  *buf = p->data + p->pos;
  return SZ_OK;
}

static SRes Sz7zMem_Skip(ILookInStreamPtr pp, size_t offset)
{
  Z7_CONTAINER_FROM_VTBL_TO_DECL_VAR_pp_vt_p(CSz7zMemInStream)
  if (offset > p->size - p->pos)
    return SZ_ERROR_INPUT_EOF;
  p->pos += offset;
  return SZ_OK;
}

static SRes Sz7zMem_Read(ILookInStreamPtr pp, void *buf, size_t *size)
{
  Z7_CONTAINER_FROM_VTBL_TO_DECL_VAR_pp_vt_p(CSz7zMemInStream)
  size_t rem = p->size - p->pos;
  if (*size > rem)
    *size = rem;
  if (*size != 0)
    memcpy(buf, p->data + p->pos, *size);
  p->pos += *size;
  return SZ_OK;
}

static SRes Sz7zMem_Seek(ILookInStreamPtr pp, Int64 *pos, ESzSeek origin)
{
  Z7_CONTAINER_FROM_VTBL_TO_DECL_VAR_pp_vt_p(CSz7zMemInStream)
  Int64 np;
  switch (origin)
  {
    case SZ_SEEK_SET: np = *pos; break;
    case SZ_SEEK_CUR: np = (Int64)p->pos + *pos; break;
    case SZ_SEEK_END: np = (Int64)p->size + *pos; break;
    default: return SZ_ERROR_PARAM;
  }
  if (np < 0 || (UInt64)np > (UInt64)p->size)
    return SZ_ERROR_PARAM;
  p->pos = (size_t)np;
  *pos = np;
  return SZ_OK;
}

static SRes Sz7zAes_DecodeFolder2(const CSzFolder *folder,
    const Byte *propsData,
    const UInt64 *unpackSizes,
    const UInt64 *packPositions,
    ILookInStreamPtr inStream, UInt64 startPos,
    Byte *outBuffer, SizeT outSize, ISzAllocPtr allocMain,
    Byte *tempBuf[])
{
  int aesCiInt = Sz7zAes_FindAesCoder(folder);
  unsigned aesCi;
  unsigned i;
  const CSzCoderInfo *aesCoder;
  UInt64 encOffset, encSizeU, decSizeU;
  size_t encSize, decSize;
  Byte *buf;
  SRes res;
  CSzFolder folder2;
  UInt64 packPositions2[2];
  CSz7zMemInStream ms;
  Byte key[32];
  Byte iv[16];

  g_7zAesUsed = 1;

  if (aesCiInt < 0)
    return SZ_ERROR_UNSUPPORTED;
  aesCi = (unsigned)aesCiInt;

  if (g_7zAesPasswordSize == 0)
    return SZ_ERROR_UNSUPPORTED;

  /* Linear single-stream chains only: every coder has exactly one in/out
     stream, so stream index == coder index. The folder's single pack stream
     must feed the AES coder. 7-Zip writes the AES coder FIRST in the folder
     (e.g. [AES], [AES,LZMA2], [AES,LZMA2,BCJ] with UnpackStream at the end);
     the removal below remaps indices, so any AES position is accepted. */
  if (folder->NumPackStreams != 1)
    return SZ_ERROR_UNSUPPORTED;
  for (i = 0; i < folder->NumCoders; i++)
    if (folder->Coders[i].NumStreams != 1)
      return SZ_ERROR_UNSUPPORTED;
  if (folder->PackStreams[0] != aesCi)
    return SZ_ERROR_UNSUPPORTED;

  aesCoder = &folder->Coders[aesCi];

  encOffset = packPositions[0];
  encSizeU = packPositions[1] - encOffset;
  decSizeU = unpackSizes[aesCi];

  encSize = (size_t)encSizeU;
  decSize = (size_t)decSizeU;
  if ((UInt64)encSize != encSizeU || (UInt64)decSize != decSizeU)
    return SZ_ERROR_MEM;
  if (encSize == 0 || (encSize & 15) != 0 || decSize > encSize)
    return SZ_ERROR_DATA;

  buf = (Byte *)ISzAlloc_Alloc(allocMain, encSize);
  if (!buf)
    return SZ_ERROR_MEM;

  res = LookInStream_SeekTo(inStream, startPos + encOffset);
  if (res == SZ_OK)
    res = LookInStream_Read2(inStream, buf, encSize, SZ_ERROR_INPUT_EOF);
  if (res == SZ_OK)
    res = Sz7zAes_CalcKeyIv(propsData + aesCoder->PropsOffset, aesCoder->PropsSize, key, iv);
  if (res != SZ_OK)
  {
    ISzAlloc_Free(allocMain, buf);
    return res;
  }

  Sz7zAes_Decrypt(key, iv, buf, encSize);

  /* rewrite the folder with the AES coder removed; the result is validated
     against the standard supported shapes by SzFolder_Decode2 itself */
  folder2 = *folder;
  if (folder->NumCoders == 1)
  {
    /* AES alone -> a single Copy coder over the decrypted bytes */
    if (decSize != (size_t)outSize)
    {
      ISzAlloc_Free(allocMain, buf);
      return SZ_ERROR_DATA;
    }
    folder2.Coders[0].MethodID = k_Copy;
    folder2.Coders[0].NumStreams = 1;
    folder2.Coders[0].PropsOffset = 0;
    folder2.Coders[0].PropsSize = 0;
    folder2.NumCoders = 1;
    folder2.NumBonds = 0;
    folder2.NumPackStreams = 1;
    folder2.PackStreams[0] = 0;
    folder2.UnpackStream = 0;
  }
  else
  {
    /* drop coder aesCi and remap the remaining coder/stream indices
       (each coder has exactly one in/out stream: stream index == coder index) */
    #define SZ7ZAES_MAP(x) ((UInt32)((unsigned)(x) > aesCi ? (x) - 1 : (x)))
    unsigned n = 0;
    int packSet = 0;
    for (i = 0; i < folder->NumCoders; i++)
      if (i != aesCi)
        folder2.Coders[n++] = folder->Coders[i];
    folder2.NumCoders = n;
    n = 0;
    for (i = 0; i < folder->NumBonds; i++)
    {
      const CSzBond *b = &folder->Bonds[i];
      if (b->OutIndex == aesCi)
      {
        /* the coder that consumed AES output now reads the decrypted pack stream */
        folder2.PackStreams[0] = SZ7ZAES_MAP(b->InIndex);
        packSet = 1;
      }
      else
      {
        folder2.Bonds[n].InIndex = SZ7ZAES_MAP(b->InIndex);
        folder2.Bonds[n].OutIndex = SZ7ZAES_MAP(b->OutIndex);
        n++;
      }
    }
    folder2.NumBonds = n;
    folder2.NumPackStreams = 1;
    if (!packSet || folder->UnpackStream == aesCi)
    {
      ISzAlloc_Free(allocMain, buf);
      return SZ_ERROR_UNSUPPORTED;
    }
    folder2.UnpackStream = SZ7ZAES_MAP(folder->UnpackStream);
    #undef SZ7ZAES_MAP
  }

  packPositions2[0] = 0;
  packPositions2[1] = decSize;

  ms.vt.Look = Sz7zMem_Look;
  ms.vt.Skip = Sz7zMem_Skip;
  ms.vt.Read = Sz7zMem_Read;
  ms.vt.Seek = Sz7zMem_Seek;
  ms.data = buf;
  ms.size = decSize;
  ms.pos = 0;

  res = SzFolder_Decode2(&folder2, propsData, unpackSizes, packPositions2,
      &ms.vt, 0, outBuffer, outSize, allocMain, tempBuf);

  ISzAlloc_Free(allocMain, buf);
  return res;
}

/* ------------------------- end SSP 7z AES patch ------------------------- */


/* ---------------------------------------------------------------------------
   SSP patch: resumable streaming folder decode (SzAr_FolderStream_*). See 7z.h.

   The decoders below are the streaming counterparts of SzDecodeCopy /
   SzDecodeLzma / SzDecodeLzma2 / SzDecodePpmd, driven by the caller (pull):
   instead of filling a folder sized output buffer they produce one staging
   chunk at a time, so the memory they hold is bounded by the coder's own
   window and not by the size of the folder or of the file being extracted.

   Being resumable is what makes a solid folder usable: the caller stops at a
   file boundary, hands those bytes out, and resumes the same decoder for the
   next file instead of decoding the folder again from its start.

   The accepted folder shape is a linear one-pack-stream chain

     pack -> [AES] -> main -> [filter] -> out

   with main = Copy / LZMA / LZMA2 / PPMd, AES = 7zAES (CBC, decrypted on the
   fly) and filter = Delta / BCJ / PPC / IA64 / ARM / ARMT / ARM64 / SPARC /
   RISCV. BCJ2 (four pack streams) and any other graph are rejected with
   SZ_ERROR_UNSUPPORTED; the caller falls back to SzArEx_Extract for those.
--------------------------------------------------------------------------- */

/* staging buffer size; a multiple of the 16-byte AES block */
#define SZ7Z_STREAM_BUF_SIZE (1 << 18)

/* ---- packed input: raw pass-through, or AES-256-CBC decrypted on the fly --- */

typedef struct
{
  ILookInStreamPtr inStream;
  UInt64 packRemain;      /* packed bytes not yet consumed from inStream */
  /* AES only (aes == NULL: raw pass-through) */
  EVP_CIPHER_CTX *aes;
  UInt64 plainRemain;     /* decrypted bytes not yet delivered */
  Byte *buf;              /* decryption staging buffer */
  size_t bufPos;
  size_t bufEnd;
  ISzAllocPtr alloc;
} CSz7zPackIn;

static void Sz7zPackIn_Construct(CSz7zPackIn *p, ILookInStreamPtr inStream, UInt64 packSize)
{
  p->inStream = inStream;
  p->packRemain = packSize;
  p->aes = NULL;
  p->plainRemain = 0;
  p->buf = NULL;
  p->bufPos = 0;
  p->bufEnd = 0;
  p->alloc = NULL;
}

static void Sz7zPackIn_Free(CSz7zPackIn *p)
{
  if (p->aes)
  {
    EVP_CIPHER_CTX_free(p->aes);
    p->aes = NULL;
  }
  if (p->buf)
  {
    ISzAlloc_Free(p->alloc, p->buf);
    p->buf = NULL;
  }
}

static SRes Sz7zPackIn_SetAes(CSz7zPackIn *p, const Byte *props, unsigned propsSize,
    UInt64 plainSize, ISzAllocPtr alloc)
{
  Byte key[32];
  Byte iv[16];
  RINOK(Sz7zAes_CalcKeyIv(props, propsSize, key, iv))
  p->alloc = alloc;
  p->buf = (Byte *)ISzAlloc_Alloc(alloc, SZ7Z_STREAM_BUF_SIZE);
  if (!p->buf)
    return SZ_ERROR_MEM;
  p->aes = EVP_CIPHER_CTX_new();
  if (!p->aes)
    return SZ_ERROR_MEM;
  if (!EVP_DecryptInit_ex(p->aes, EVP_aes_256_cbc(), NULL, key, iv))
    return SZ_ERROR_FAIL;
  EVP_CIPHER_CTX_set_padding(p->aes, 0);
  p->plainRemain = plainSize;
  return SZ_OK;
}

/* Hands out the next run of input bytes without consuming them. A returned
   size of 0 means the stream is exhausted. */
static SRes Sz7zPackIn_Peek(CSz7zPackIn *p, const Byte **data, size_t *size)
{
  size_t want;

  *data = NULL;
  *size = 0;

  if (!p->aes)
  {
    const void *buf = NULL;
    want = SZ7Z_STREAM_BUF_SIZE;
    if ((UInt64)want > p->packRemain)
      want = (size_t)p->packRemain;
    if (want == 0)
      return SZ_OK;
    RINOK(ILookInStream_Look(p->inStream, &buf, &want))
    *data = (const Byte *)buf;
    *size = want;
    return SZ_OK;
  }

  if (p->bufPos == p->bufEnd)
  {
    int outLen = 0;
    p->bufPos = 0;
    p->bufEnd = 0;
    want = SZ7Z_STREAM_BUF_SIZE;
    if ((UInt64)want > p->packRemain)
      want = (size_t)p->packRemain;
    if (want == 0 || p->plainRemain == 0)
      return SZ_OK;
    /* the packed size of an AES stream is a multiple of the block size, and so
       is SZ7Z_STREAM_BUF_SIZE, so 'want' never splits a block */
    RINOK(LookInStream_Read2(p->inStream, p->buf, want, SZ_ERROR_INPUT_EOF))
    p->packRemain -= want;
    if (!EVP_DecryptUpdate(p->aes, p->buf, &outLen, p->buf, (int)want))
      return SZ_ERROR_DATA;
    p->bufEnd = (size_t)outLen;
    if ((UInt64)p->bufEnd > p->plainRemain)
      p->bufEnd = (size_t)p->plainRemain;  /* drop the encryption padding */
    p->plainRemain -= p->bufEnd;
  }
  *data = p->buf + p->bufPos;
  *size = p->bufEnd - p->bufPos;
  return SZ_OK;
}

static SRes Sz7zPackIn_Consume(CSz7zPackIn *p, size_t size)
{
  if (size == 0)
    return SZ_OK;
  if (!p->aes)
  {
    RINOK(ILookInStream_Skip(p->inStream, size))
    p->packRemain -= size;
    return SZ_OK;
  }
  p->bufPos += size;
  return SZ_OK;
}

/* ---- output filter: Delta and the branch converters -----------------------

   A branch converter only converts whole instructions, so a chunk boundary can
   leave a few bytes at the end unconverted. Those stay in the staging buffer
   and are converted together with the next chunk (the tail-carry XzDec.c's
   CXzBcFilterState does). Delta converts everything it is handed. */

typedef struct
{
  UInt32 methodId;    /* 0 = no filter */
  UInt32 delta;
  UInt32 ip;
  UInt32 x86State;
  Byte deltaState[DELTA_STATE_SIZE];
} CSz7zFilter;

static BoolInt Sz7zFilter_IsFilterMethod(UInt32 id)
{
  switch (id)
  {
  #if !defined(Z7_NO_METHODS_FILTERS)
    case k_Delta:
    case k_BCJ:
    case k_PPC:
    case k_IA64:
    case k_SPARC:
    case k_ARM:
    case k_RISCV:
  #endif
  #ifdef Z7_USE_FILTER_ARM64
    case k_ARM64:
  #endif
  #ifdef Z7_USE_FILTER_ARMT
    case k_ARMT:
  #endif
      return True;
    default:
      return False;
  }
}

/* the props are read exactly as SzFolder_Decode2 reads them for the same method */
static SRes Sz7zFilter_Init(CSz7zFilter *p, UInt32 methodId, const Byte *props, unsigned propsSize)
{
  p->methodId = methodId;
  p->delta = 0;
  p->ip = 0;
  p->x86State = Z7_BRANCH_CONV_ST_X86_STATE_INIT_VAL;

  switch (methodId)
  {
  #if !defined(Z7_NO_METHODS_FILTERS)
    case k_Delta:
      if (propsSize != 1)
        return SZ_ERROR_UNSUPPORTED;
      p->delta = (UInt32)props[0] + 1;
      Delta_Init(p->deltaState);
      return SZ_OK;
    case k_RISCV:
      if (propsSize == 4)
      {
        p->ip = GetUi32(props);
        if (p->ip & 1)
          return SZ_ERROR_UNSUPPORTED;
      }
      else if (propsSize != 0)
        return SZ_ERROR_UNSUPPORTED;
      return SZ_OK;
  #endif
  #ifdef Z7_USE_FILTER_ARM64
    case k_ARM64:
      if (propsSize == 4)
      {
        p->ip = GetUi32(props);
        if (p->ip & 3)
          return SZ_ERROR_UNSUPPORTED;
      }
      else if (propsSize != 0)
        return SZ_ERROR_UNSUPPORTED;
      return SZ_OK;
  #endif
    default:
      /* BCJ / PPC / IA64 / ARM / ARMT: no props, pc = 0 */
      return (propsSize == 0) ? SZ_OK : SZ_ERROR_UNSUPPORTED;
  }
}

/* Converts in place and returns how much was converted; the rest is the tail
   the caller has to hand back at the start of the next call. */
static size_t Sz7zFilter_Apply(CSz7zFilter *p, Byte *data, size_t size)
{
  switch (p->methodId)
  {
  #if !defined(Z7_NO_METHODS_FILTERS)
    case k_Delta:
      Delta_Decode(p->deltaState, (unsigned)p->delta, data, (SizeT)size);
      break;
    case k_BCJ:
      size = (size_t)(z7_BranchConvSt_X86_Dec(data, (SizeT)size, p->ip, &p->x86State) - data);
      break;
    case k_PPC:   size = (size_t)(Z7_BRANCH_CONV_DEC(PPC)  (data, (SizeT)size, p->ip) - data); break;
    case k_IA64:  size = (size_t)(Z7_BRANCH_CONV_DEC(IA64) (data, (SizeT)size, p->ip) - data); break;
    case k_SPARC: size = (size_t)(Z7_BRANCH_CONV_DEC(SPARC)(data, (SizeT)size, p->ip) - data); break;
    case k_ARM:   size = (size_t)(Z7_BRANCH_CONV_DEC(ARM)  (data, (SizeT)size, p->ip) - data); break;
    case k_RISCV: size = (size_t)(Z7_BRANCH_CONV_DEC(RISCV)(data, (SizeT)size, p->ip) - data); break;
  #endif
  #ifdef Z7_USE_FILTER_ARM64
    case k_ARM64: size = (size_t)(Z7_BRANCH_CONV_DEC(ARM64)(data, (SizeT)size, p->ip) - data); break;
  #endif
  #ifdef Z7_USE_FILTER_ARMT
    case k_ARMT:  size = (size_t)(Z7_BRANCH_CONV_DEC(ARMT) (data, (SizeT)size, p->ip) - data); break;
  #endif
    default:
      break;
  }
  p->ip += (UInt32)size;
  return size;
}

/* ---- PPMd input adapter (reads the packed stream through CSz7zPackIn) ---- */

#ifdef Z7_PPMD_SUPPORT

typedef struct
{
  IByteIn vt;
  CSz7zPackIn *in;
  const Byte *cur;
  const Byte *end;
  size_t peeked;
  BoolInt extra;
  SRes res;
} CSz7zPpmdIn;

static Byte Sz7zPpmd_ReadByte(IByteInPtr pp)
{
  Z7_CONTAINER_FROM_VTBL_TO_DECL_VAR_pp_vt_p(CSz7zPpmdIn)
  if (p->cur != p->end)
    return *p->cur++;
  if (p->res == SZ_OK)
  {
    const Byte *data = NULL;
    size_t size = 0;
    p->res = Sz7zPackIn_Consume(p->in, p->peeked);
    p->peeked = 0;
    if (p->res == SZ_OK)
      p->res = Sz7zPackIn_Peek(p->in, &data, &size);
    if (p->res == SZ_OK && size != 0)
    {
      p->peeked = size;
      p->cur = data;
      p->end = data + size;
      return *p->cur++;
    }
  }
  p->extra = True;
  return 0;
}

#endif

/* ---- the resumable folder stream ---- */

#define SZ7Z_MAIN_COPY  0
#define SZ7Z_MAIN_LZMA  1
#define SZ7Z_MAIN_LZMA2 2
#define SZ7Z_MAIN_PPMD  3

struct CSzFolderStream
{
  ISzAllocPtr alloc;
  const CSzAr *ar;
  UInt32 folderIndex;

  CSz7zPackIn in;

  int mainKind;
  BoolInt lzmaInit;
  BoolInt lzma2Init;
  CLzmaDec lzma;
  CLzma2Dec lzma2;
 #ifdef Z7_PPMD_SUPPORT
  BoolInt ppmdInit;
  CPpmd7 ppmd;
  CSz7zPpmdIn ppmdIn;
 #endif

  BoolInt hasFilter;
  CSz7zFilter filter;

  /* staging buffer; NULL when the packed bytes are the folder output as-is
     (Copy without a filter), which is then handed out without a copy */
  Byte *buf;
  size_t bufPos;    /* handed out of buf so far */
  size_t bufConv;   /* converted (= publishable) end */
  size_t bufTotal;  /* produced end; [bufConv, bufTotal) is the filter tail */

  UInt64 outSize;    /* the folder's whole unpacked size */
  UInt64 outRemain;  /* not produced yet */
  UInt64 consumed;   /* taken by the caller */

  const Byte *peekData;  /* what the last Peek handed out */
  size_t peekSize;
  BoolInt peekFromBuf;

  UInt32 crc;   /* over the consumed bytes, i.e. the folder CRC once at the end */
  SRes res;     /* sticky: once set, every call fails with it */
};

/* Copies straight from the packed (or just decrypted) stream. Only reached
   with a filter in the chain; without one the bytes go out without a copy. */
static SRes Sz7zFolderStream_ProduceCopy(CSzFolderStream *s, Byte *dest, size_t destCap, size_t *produced)
{
  const Byte *src = NULL;
  size_t avail = 0;
  RINOK(Sz7zPackIn_Peek(&s->in, &src, &avail))
  if (avail == 0)
    return SZ_ERROR_INPUT_EOF;
  if (avail > destCap)
    avail = destCap;
  memcpy(dest, src, avail);
  RINOK(Sz7zPackIn_Consume(&s->in, avail))
  *produced = avail;
  return SZ_OK;
}

/* An LZMA window larger than the stream it decodes is dead weight: a match can
   never reach further back than the number of bytes produced so far. */
static void Sz7zStream_CapLzmaDicSize(Byte *props, UInt64 unpackSize)
{
  const UInt32 dicSize = (UInt32)props[1] | ((UInt32)props[2] << 8)
      | ((UInt32)props[3] << 16) | ((UInt32)props[4] << 24);
  UInt32 need;
  if ((UInt64)dicSize <= unpackSize)
    return;
  /* dicSize > unpackSize, so unpackSize fits in 32 bits here */
  need = (unpackSize < (UInt64)(1 << 12)) ? (UInt32)1 << 12 : (UInt32)unpackSize;
  props[1] = (Byte)need;
  props[2] = (Byte)(need >> 8);
  props[3] = (Byte)(need >> 16);
  props[4] = (Byte)(need >> 24);
}

static SRes Sz7zFolderStream_ProduceLzma(CSzFolderStream *s, Byte *dest, size_t destCap, size_t *produced)
{
  for (;;)
  {
    const Byte *src = NULL;
    size_t avail = 0;
    SizeT srcLen, destLen;
    ELzmaStatus status;

    RINOK(Sz7zPackIn_Peek(&s->in, &src, &avail))

    srcLen = (SizeT)avail;
    destLen = (SizeT)destCap;
    RINOK(LzmaDec_DecodeToBuf(&s->lzma, dest, &destLen, src, &srcLen, LZMA_FINISH_ANY, &status))
    RINOK(Sz7zPackIn_Consume(&s->in, (size_t)srcLen))

    if (destLen != 0)
    {
      *produced = (size_t)destLen;
      return SZ_OK;
    }
    if (srcLen == 0)
      return (status == LZMA_STATUS_NEEDS_MORE_INPUT) ? SZ_ERROR_INPUT_EOF : SZ_ERROR_DATA;
  }
}


#ifndef Z7_NO_METHOD_LZMA2

/* the LZMA2 property byte encodes the window size; pick the smallest one that
   still covers the stream (see LZMA2_DIC_SIZE_FROM_PROP in Lzma2Dec.c) */
static Byte Sz7zStream_CapLzma2Prop(Byte prop, UInt64 unpackSize)
{
  Byte i;
  if (prop > 40)
    return prop;  /* invalid; Lzma2Dec_Allocate rejects it */
  for (i = 0; i < prop; i++)
  {
    const UInt32 dicSize = ((UInt32)2 | (i & 1)) << (i / 2 + 11);
    if ((UInt64)dicSize >= unpackSize)
      return i;
  }
  return prop;
}

static SRes Sz7zFolderStream_ProduceLzma2(CSzFolderStream *s, Byte *dest, size_t destCap, size_t *produced)
{
  for (;;)
  {
    const Byte *src = NULL;
    size_t avail = 0;
    SizeT srcLen, destLen;
    ELzmaStatus status;

    RINOK(Sz7zPackIn_Peek(&s->in, &src, &avail))

    srcLen = (SizeT)avail;
    destLen = (SizeT)destCap;
    RINOK(Lzma2Dec_DecodeToBuf(&s->lzma2, dest, &destLen, src, &srcLen, LZMA_FINISH_ANY, &status))
    RINOK(Sz7zPackIn_Consume(&s->in, (size_t)srcLen))

    if (destLen != 0)
    {
      *produced = (size_t)destLen;
      return SZ_OK;
    }
    if (srcLen == 0)
      return (status == LZMA_STATUS_NEEDS_MORE_INPUT) ? SZ_ERROR_INPUT_EOF : SZ_ERROR_DATA;
  }
}

#endif


#ifdef Z7_PPMD_SUPPORT

static SRes Sz7zFolderStream_ProducePpmd(CSzFolderStream *s, Byte *dest, size_t destCap, size_t *produced)
{
  size_t i;
  for (i = 0; i < destCap; i++)
  {
    const int sym = Ppmd7z_DecodeSymbol(&s->ppmd);
    if (s->ppmdIn.extra || sym < 0)
      break;
    dest[i] = (Byte)sym;
  }
  if (i == 0)
    return (s->ppmdIn.res != SZ_OK) ? s->ppmdIn.res : SZ_ERROR_DATA;
  *produced = i;
  return SZ_OK;
}

#endif


/* Produces at least one byte into dest, or fails. destCap must not be 0. */
static SRes Sz7zFolderStream_Produce(CSzFolderStream *s, Byte *dest, size_t destCap, size_t *produced)
{
  *produced = 0;
  if ((UInt64)destCap > s->outRemain)
    destCap = (size_t)s->outRemain;

  switch (s->mainKind)
  {
    case SZ7Z_MAIN_LZMA:
      return Sz7zFolderStream_ProduceLzma(s, dest, destCap, produced);
  #ifndef Z7_NO_METHOD_LZMA2
    case SZ7Z_MAIN_LZMA2:
      return Sz7zFolderStream_ProduceLzma2(s, dest, destCap, produced);
  #endif
  #ifdef Z7_PPMD_SUPPORT
    case SZ7Z_MAIN_PPMD:
      return Sz7zFolderStream_ProducePpmd(s, dest, destCap, produced);
  #endif
    default:
      return Sz7zFolderStream_ProduceCopy(s, dest, destCap, produced);
  }
}

/* Accepts the linear chain pack -> [AES] -> main -> [filter] -> out and reports
   which coder is which (-1 = not in the chain). Every coder here has exactly
   one input and one output stream, so a coder's stream index equals its coder
   index -- for the bonds and for PackStreams / UnpackStream alike. */
static SRes Sz7zStream_ParseFolder(const CSzFolder *f, int *mainCi, int *aesCi, int *fltCi)
{
  int feeder[3];   /* feeder[i] = the coder feeding coder i, -1 = the pack stream */
  unsigned i;
  int cur, len;

  *mainCi = -1;
  *aesCi = -1;
  *fltCi = -1;

  if (f->NumPackStreams != 1 || f->NumCoders < 1 || f->NumCoders > 3)
    return SZ_ERROR_UNSUPPORTED;
  if (f->NumBonds != f->NumCoders - 1 || f->UnpackStream >= f->NumCoders)
    return SZ_ERROR_UNSUPPORTED;

  for (i = 0; i < f->NumCoders; i++)
  {
    const CSzCoderInfo *c = &f->Coders[i];
    if (c->NumStreams != 1)
      return SZ_ERROR_UNSUPPORTED;
    feeder[i] = -1;
    if (c->MethodID == k_AES)
    {
      if (*aesCi >= 0)
        return SZ_ERROR_UNSUPPORTED;
      *aesCi = (int)i;
    }
    else if (IS_MAIN_METHOD(c->MethodID))
    {
      if (*mainCi >= 0)
        return SZ_ERROR_UNSUPPORTED;
      *mainCi = (int)i;
    }
    else if (Sz7zFilter_IsFilterMethod(c->MethodID))
    {
      if (*fltCi >= 0)
        return SZ_ERROR_UNSUPPORTED;
      *fltCi = (int)i;
    }
    else
      return SZ_ERROR_UNSUPPORTED;  /* BCJ2 (4 streams) and anything else: not here */
  }

  for (i = 0; i < f->NumBonds; i++)
  {
    const UInt32 inIndex = f->Bonds[i].InIndex;
    const UInt32 outIndex = f->Bonds[i].OutIndex;
    if (inIndex >= f->NumCoders || outIndex >= f->NumCoders || feeder[inIndex] != -1)
      return SZ_ERROR_UNSUPPORTED;
    feeder[inIndex] = (int)outIndex;
  }

  /* walk back from the folder output: the chain must reach the pack stream
     through every coder exactly once (the length test also breaks a cycle) */
  len = 0;
  cur = (int)f->UnpackStream;
  while (feeder[cur] >= 0 && len + 1 < (int)f->NumCoders)
  {
    cur = feeder[cur];
    len++;
  }
  if (len + 1 != (int)f->NumCoders || feeder[cur] != -1 || f->PackStreams[0] != (UInt32)cur)
    return SZ_ERROR_UNSUPPORTED;

  /* the order within the chain: AES takes the pack stream, the filter is last */
  if (*mainCi < 0 && *fltCi >= 0)
    return SZ_ERROR_UNSUPPORTED;   /* a filter with nothing to filter */
  if (*aesCi >= 0 && feeder[*aesCi] != -1)
    return SZ_ERROR_UNSUPPORTED;
  if (*fltCi >= 0 && (int)f->UnpackStream != *fltCi)
    return SZ_ERROR_UNSUPPORTED;

  return SZ_OK;
}

static SRes Sz7zStream_GetFolder(const CSzAr *p, UInt32 folderIndex, CSzFolder *folder, CSzData *sd)
{
  sd->Data = p->CodersData + p->FoCodersOffsets[folderIndex];
  sd->Size = p->FoCodersOffsets[(size_t)folderIndex + 1] - p->FoCodersOffsets[folderIndex];
  return SzGetNextFolderItem(folder, sd);
}

int SzAr_IsFolderStreamable(const CSzAr *p, UInt32 folderIndex)
{
  CSzFolder folder;
  CSzData sd;
  int mainCi, aesCi, fltCi;
  if (Sz7zStream_GetFolder(p, folderIndex, &folder, &sd) != SZ_OK)
    return 0;
  return (Sz7zStream_ParseFolder(&folder, &mainCi, &aesCi, &fltCi) == SZ_OK) ? 1 : 0;
}

/* ---- main coder setup ---- */

static SRes Sz7zFolderStream_InitLzma(CSzFolderStream *s, const Byte *props, unsigned propsSize, UInt64 unpackSize)
{
  Byte props2[LZMA_PROPS_SIZE];
  if (propsSize != LZMA_PROPS_SIZE)
    return SZ_ERROR_UNSUPPORTED;
  memcpy(props2, props, LZMA_PROPS_SIZE);
  Sz7zStream_CapLzmaDicSize(props2, unpackSize);

  LzmaDec_CONSTRUCT(&s->lzma)
  s->lzmaInit = True;
  RINOK(LzmaDec_Allocate(&s->lzma, props2, LZMA_PROPS_SIZE, s->alloc))
  LzmaDec_Init(&s->lzma);
  return SZ_OK;
}

#ifndef Z7_NO_METHOD_LZMA2

static SRes Sz7zFolderStream_InitLzma2(CSzFolderStream *s, const Byte *props, unsigned propsSize, UInt64 unpackSize)
{
  if (propsSize != 1)
    return SZ_ERROR_DATA;

  Lzma2Dec_CONSTRUCT(&s->lzma2)
  s->lzma2Init = True;
  RINOK(Lzma2Dec_Allocate(&s->lzma2, Sz7zStream_CapLzma2Prop(props[0], unpackSize), s->alloc))
  Lzma2Dec_Init(&s->lzma2);
  return SZ_OK;
}

#endif

#ifdef Z7_PPMD_SUPPORT

static SRes Sz7zFolderStream_InitPpmd(CSzFolderStream *s, const Byte *props, unsigned propsSize)
{
  unsigned order;
  UInt32 memSize;

  if (propsSize != 5)
    return SZ_ERROR_UNSUPPORTED;
  order = props[0];
  memSize = GetUi32(props + 1);
  if (order < PPMD7_MIN_ORDER ||
      order > PPMD7_MAX_ORDER ||
      memSize < PPMD7_MIN_MEM_SIZE ||
      memSize > PPMD7_MAX_MEM_SIZE)
    return SZ_ERROR_UNSUPPORTED;

  s->ppmdIn.vt.Read = Sz7zPpmd_ReadByte;
  s->ppmdIn.in = &s->in;
  s->ppmdIn.cur = NULL;
  s->ppmdIn.end = NULL;
  s->ppmdIn.peeked = 0;
  s->ppmdIn.extra = False;
  s->ppmdIn.res = SZ_OK;

  Ppmd7_Construct(&s->ppmd);
  s->ppmdInit = True;
  if (!Ppmd7_Alloc(&s->ppmd, memSize, s->alloc))
    return SZ_ERROR_MEM;
  Ppmd7_Init(&s->ppmd, order);

  /* the range coder reads its first bytes here, i.e. still inside Create */
  s->ppmd.rc.dec.Stream = &s->ppmdIn.vt;
  if (!Ppmd7z_RangeDec_Init(&s->ppmd.rc.dec))
    return SZ_ERROR_DATA;
  return SZ_OK;
}

#endif

void SzAr_FolderStream_Free(CSzFolderStream *s)
{
  ISzAllocPtr alloc;

  if (!s)
    return;
  alloc = s->alloc;

  Sz7zPackIn_Free(&s->in);
  if (s->lzmaInit)
    LzmaDec_Free(&s->lzma, alloc);
 #ifndef Z7_NO_METHOD_LZMA2
  if (s->lzma2Init)
    Lzma2Dec_Free(&s->lzma2, alloc);
 #endif
 #ifdef Z7_PPMD_SUPPORT
  if (s->ppmdInit)
    Ppmd7_Free(&s->ppmd, alloc);
 #endif
  if (s->buf)
    ISzAlloc_Free(alloc, s->buf);
  ISzAlloc_Free(alloc, s);
}

SRes SzAr_FolderStream_Create(CSzFolderStream **pp, const CSzAr *p, UInt32 folderIndex,
    ILookInStreamPtr inStream, UInt64 startPos, ISzAllocPtr alloc)
{
  const Byte *propsData = p->CodersData + p->FoCodersOffsets[folderIndex];
  const UInt64 *unpackSizes = &p->CoderUnpackSizes[p->FoToCoderUnpackSizes[folderIndex]];
  const UInt64 *packPositions = p->PackPositions + p->FoStartPackStreamIndex[folderIndex];
  CSzFolderStream *s;
  CSzFolder folder;
  CSzData sd;
  UInt64 outSize, packSize, mainInSize;
  int mainCi, aesCi, fltCi;
  SRes res;

  *pp = NULL;

  RINOK(Sz7zStream_GetFolder(p, folderIndex, &folder, &sd))
  outSize = SzAr_GetFolderUnpackSize(p, folderIndex);
  if (sd.Size != 0 || folder.UnpackStream != p->FoToMainUnpackSizeIndex[folderIndex])
    return SZ_ERROR_FAIL;

  RINOK(Sz7zStream_ParseFolder(&folder, &mainCi, &aesCi, &fltCi))

  s = (CSzFolderStream *)ISzAlloc_Alloc(alloc, sizeof(CSzFolderStream));
  if (!s)
    return SZ_ERROR_MEM;
  memset(s, 0, sizeof(CSzFolderStream));
  s->alloc = alloc;
  s->ar = p;
  s->folderIndex = folderIndex;
  s->outSize = outSize;
  s->outRemain = outSize;
  s->crc = CRC_INIT_VAL;
  s->res = SZ_OK;

  packSize = packPositions[1] - packPositions[0];
  mainInSize = packSize;

  Sz7zPackIn_Construct(&s->in, inStream, packSize);
  res = LookInStream_SeekTo(inStream, startPos + packPositions[0]);

  if (res == SZ_OK && aesCi >= 0)
  {
    const CSzCoderInfo *aesCoder = &folder.Coders[aesCi];
    mainInSize = unpackSizes[aesCi];
    g_7zAesUsed = 1;
    if (g_7zAesPasswordSize == 0)
      res = SZ_ERROR_UNSUPPORTED;
    else if (packSize == 0 || (packSize & 15) != 0 || mainInSize > packSize)
      res = SZ_ERROR_DATA;
    else
      res = Sz7zPackIn_SetAes(&s->in, propsData + aesCoder->PropsOffset, aesCoder->PropsSize,
          mainInSize, alloc);
  }

  if (res == SZ_OK && fltCi >= 0)
  {
    const CSzCoderInfo *fltCoder = &folder.Coders[fltCi];
    if (unpackSizes[fltCi] != outSize)
      res = SZ_ERROR_DATA;
    else
    {
      res = Sz7zFilter_Init(&s->filter, fltCoder->MethodID,
          propsData + fltCoder->PropsOffset, fltCoder->PropsSize);
      s->hasFilter = (res == SZ_OK);
    }
  }

  if (res == SZ_OK)
  {
    if (mainCi < 0)
    {
      /* AES alone: the decrypted bytes are the folder output */
      s->mainKind = SZ7Z_MAIN_COPY;
      if (mainInSize != outSize)
        res = SZ_ERROR_DATA;
    }
    else
    {
      const CSzCoderInfo *mainCoder = &folder.Coders[mainCi];
      const Byte *mainProps = propsData + mainCoder->PropsOffset;
      if (unpackSizes[mainCi] != outSize)
        res = SZ_ERROR_DATA;
      else switch (mainCoder->MethodID)
      {
        case k_Copy:
          s->mainKind = SZ7Z_MAIN_COPY;
          if (mainInSize != outSize)
            res = SZ_ERROR_DATA;
          break;
        case k_LZMA:
          s->mainKind = SZ7Z_MAIN_LZMA;
          res = Sz7zFolderStream_InitLzma(s, mainProps, mainCoder->PropsSize, outSize);
          break;
      #ifndef Z7_NO_METHOD_LZMA2
        case k_LZMA2:
          s->mainKind = SZ7Z_MAIN_LZMA2;
          res = Sz7zFolderStream_InitLzma2(s, mainProps, mainCoder->PropsSize, outSize);
          break;
      #endif
      #ifdef Z7_PPMD_SUPPORT
        case k_PPMD:
          s->mainKind = SZ7Z_MAIN_PPMD;
          res = Sz7zFolderStream_InitPpmd(s, mainProps, mainCoder->PropsSize);
          break;
      #endif
        default:
          res = SZ_ERROR_UNSUPPORTED;
          break;
      }
    }
  }

  /* Copy without a filter hands the packed bytes out as they are; everything
     else decodes (and converts) through the staging buffer */
  if (res == SZ_OK && (s->mainKind != SZ7Z_MAIN_COPY || s->hasFilter))
  {
    s->buf = (Byte *)ISzAlloc_Alloc(alloc, SZ7Z_STREAM_BUF_SIZE);
    if (!s->buf)
      res = SZ_ERROR_MEM;
  }

  if (res != SZ_OK)
  {
    SzAr_FolderStream_Free(s);
    return res;
  }

  *pp = s;
  return SZ_OK;
}

SRes SzAr_FolderStream_Peek(CSzFolderStream *s, const Byte **data, size_t *size)
{
  *data = NULL;
  *size = 0;
  s->peekData = NULL;
  s->peekSize = 0;

  if (s->res != SZ_OK)
    return s->res;

  if (!s->buf)
  {
    /* the packed (or just decrypted) bytes are the output: hand them out as is */
    const Byte *src = NULL;
    size_t avail = 0;

    if (s->outRemain == 0)
      return SZ_OK;
    s->res = Sz7zPackIn_Peek(&s->in, &src, &avail);
    if (s->res != SZ_OK)
      return s->res;
    if (avail == 0)
    {
      s->res = SZ_ERROR_INPUT_EOF;
      return s->res;
    }
    if ((UInt64)avail > s->outRemain)
      avail = (size_t)s->outRemain;

    s->peekData = src;
    s->peekSize = avail;
    s->peekFromBuf = False;
    *data = src;
    *size = avail;
    return SZ_OK;
  }

  for (;;)
  {
    size_t produced;

    if (s->bufPos != s->bufConv)
    {
      s->peekData = s->buf + s->bufPos;
      s->peekSize = s->bufConv - s->bufPos;
      s->peekFromBuf = True;
      *data = s->peekData;
      *size = s->peekSize;
      return SZ_OK;
    }

    /* nothing converted is pending: keep the filter's tail and refill */
    s->bufTotal -= s->bufPos;
    if (s->bufTotal != 0)
      memmove(s->buf, s->buf + s->bufPos, s->bufTotal);
    s->bufPos = 0;
    s->bufConv = 0;

    if (s->outRemain != 0 && s->bufTotal != SZ7Z_STREAM_BUF_SIZE)
    {
      produced = 0;
      s->res = Sz7zFolderStream_Produce(s, s->buf + s->bufTotal,
          SZ7Z_STREAM_BUF_SIZE - s->bufTotal, &produced);
      if (s->res != SZ_OK)
        return s->res;
      s->bufTotal += produced;
      s->outRemain -= produced;
    }

    if (s->bufTotal == 0)
      return SZ_OK;   /* end of the folder */

    s->bufConv = s->hasFilter ? Sz7zFilter_Apply(&s->filter, s->buf, s->bufTotal) : s->bufTotal;
    if (s->bufConv == 0)
    {
      if (s->outRemain != 0)
      {
        if (s->bufTotal != SZ7Z_STREAM_BUF_SIZE)
          continue;   /* the converter wants a whole instruction: produce more */
        /* a full staging buffer is far past every converter's alignment, so it
           converts something -- unless the props lied about the method */
        s->res = SZ_ERROR_DATA;
        return s->res;
      }
      s->bufConv = s->bufTotal;   /* end of stream: the tail goes out unconverted */
    }
  }
}

SRes SzAr_FolderStream_Consume(CSzFolderStream *s, size_t size)
{
  if (s->res != SZ_OK)
    return s->res;
  if (size > s->peekSize)
  {
    s->res = SZ_ERROR_PARAM;
    return s->res;
  }
  if (size == 0)
    return SZ_OK;

  s->crc = CrcUpdate(s->crc, s->peekData, size);
  s->consumed += size;

  if (s->peekFromBuf)
    s->bufPos += size;
  else
  {
    s->outRemain -= size;
    s->res = Sz7zPackIn_Consume(&s->in, size);
  }

  s->peekData += size;
  s->peekSize -= size;
  return s->res;
}

SRes SzAr_FolderStream_Finish(CSzFolderStream *s)
{
  if (s->res != SZ_OK)
    return s->res;
  if (s->consumed != s->outSize)
    return SZ_OK;   /* still mid-folder: there is nothing to verify yet */

  if (SzBitWithVals_Check(&s->ar->FolderCRCs, s->folderIndex))
    if (CRC_GET_DIGEST(s->crc) != s->ar->FolderCRCs.Vals[s->folderIndex])
      s->res = SZ_ERROR_CRC;
  return s->res;
}

/* ---------------------- end SSP streaming decode patch ------------------- */


SRes SzAr_DecodeFolder(const CSzAr *p, UInt32 folderIndex,
    ILookInStreamPtr inStream, UInt64 startPos,
    Byte *outBuffer, size_t outSize,
    ISzAllocPtr allocMain)
{
  SRes res;
  CSzFolder folder;
  CSzData sd;
  
  const Byte *data = p->CodersData + p->FoCodersOffsets[folderIndex];
  sd.Data = data;
  sd.Size = p->FoCodersOffsets[(size_t)folderIndex + 1] - p->FoCodersOffsets[folderIndex];
  
  res = SzGetNextFolderItem(&folder, &sd);
  
  if (res != SZ_OK)
    return res;

  if (sd.Size != 0
      || folder.UnpackStream != p->FoToMainUnpackSizeIndex[folderIndex]
      || outSize != SzAr_GetFolderUnpackSize(p, folderIndex))
    return SZ_ERROR_FAIL;
  {
    unsigned i;
    Byte *tempBuf[3] = { 0, 0, 0};

    /* SSP: route AES-encrypted folders through the patched decoder */
    if (Sz7zAes_FindAesCoder(&folder) >= 0)
      res = Sz7zAes_DecodeFolder2(&folder, data,
          &p->CoderUnpackSizes[p->FoToCoderUnpackSizes[folderIndex]],
          p->PackPositions + p->FoStartPackStreamIndex[folderIndex],
          inStream, startPos,
          outBuffer, (SizeT)outSize, allocMain, tempBuf);
    else
    res = SzFolder_Decode2(&folder, data,
        &p->CoderUnpackSizes[p->FoToCoderUnpackSizes[folderIndex]],
        p->PackPositions + p->FoStartPackStreamIndex[folderIndex],
        inStream, startPos,
        outBuffer, (SizeT)outSize, allocMain, tempBuf);
    
    for (i = 0; i < 3; i++)
      ISzAlloc_Free(allocMain, tempBuf[i]);

    if (res == SZ_OK)
      if (SzBitWithVals_Check(&p->FolderCRCs, folderIndex))
        if (CrcCalc(outBuffer, outSize) != p->FolderCRCs.Vals[folderIndex])
          res = SZ_ERROR_CRC;

    return res;
  }
}
