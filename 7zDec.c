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
