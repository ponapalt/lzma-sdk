/* 7z.h -- 7z interface
2023-04-02 : Igor Pavlov : Public domain */

#ifndef ZIP7_INC_7Z_H
#define ZIP7_INC_7Z_H

#include "7zTypes.h"

EXTERN_C_BEGIN

#define k7zStartHeaderSize 0x20
#define k7zSignatureSize 6

extern const Byte k7zSignature[k7zSignatureSize];

typedef struct
{
  const Byte *Data;
  size_t Size;
} CSzData;

/* CSzCoderInfo & CSzFolder support only default methods */

typedef struct
{
  size_t PropsOffset;
  UInt32 MethodID;
  Byte NumStreams;
  Byte PropsSize;
} CSzCoderInfo;

typedef struct
{
  UInt32 InIndex;
  UInt32 OutIndex;
} CSzBond;

#define SZ_NUM_CODERS_IN_FOLDER_MAX 4
#define SZ_NUM_BONDS_IN_FOLDER_MAX 3
#define SZ_NUM_PACK_STREAMS_IN_FOLDER_MAX 4

typedef struct
{
  UInt32 NumCoders;
  UInt32 NumBonds;
  UInt32 NumPackStreams;
  UInt32 UnpackStream;
  UInt32 PackStreams[SZ_NUM_PACK_STREAMS_IN_FOLDER_MAX];
  CSzBond Bonds[SZ_NUM_BONDS_IN_FOLDER_MAX];
  CSzCoderInfo Coders[SZ_NUM_CODERS_IN_FOLDER_MAX];
} CSzFolder;


SRes SzGetNextFolderItem(CSzFolder *f, CSzData *sd);

typedef struct
{
  UInt32 Low;
  UInt32 High;
} CNtfsFileTime;

typedef struct
{
  Byte *Defs; /* MSB 0 bit numbering */
  UInt32 *Vals;
} CSzBitUi32s;

typedef struct
{
  Byte *Defs; /* MSB 0 bit numbering */
  // UInt64 *Vals;
  CNtfsFileTime *Vals;
} CSzBitUi64s;

#define SzBitArray_Check(p, i) (((p)[(i) >> 3] & (0x80 >> ((i) & 7))) != 0)

#define SzBitWithVals_Check(p, i) ((p)->Defs && ((p)->Defs[(i) >> 3] & (0x80 >> ((i) & 7))) != 0)

typedef struct
{
  UInt32 NumPackStreams;
  UInt32 NumFolders;

  UInt64 *PackPositions;          // NumPackStreams + 1
  CSzBitUi32s FolderCRCs;         // NumFolders

  size_t *FoCodersOffsets;        // NumFolders + 1
  UInt32 *FoStartPackStreamIndex; // NumFolders + 1
  UInt32 *FoToCoderUnpackSizes;   // NumFolders + 1
  Byte *FoToMainUnpackSizeIndex;  // NumFolders
  UInt64 *CoderUnpackSizes;       // for all coders in all folders

  Byte *CodersData;

  UInt64 RangeLimit;
} CSzAr;

UInt64 SzAr_GetFolderUnpackSize(const CSzAr *p, UInt32 folderIndex);

SRes SzAr_DecodeFolder(const CSzAr *p, UInt32 folderIndex,
    ILookInStreamPtr stream, UInt64 startPos,
    Byte *outBuffer, size_t outSize,
    ISzAllocPtr allocMain);

/* SSP patch: resumable streaming folder decode.

   SzAr_DecodeFolder() needs an output buffer holding the whole folder, so the
   peak allocation is the folder's unpacked size. 7z stores the files of a solid
   folder back to back inside one compressed stream, so that is every file of
   the folder put together -- and it is paid even to read one small file.

   CSzFolderStream decodes a folder incrementally instead, and it is resumable:
   the caller pulls the unpacked bytes in order, stops wherever it likes (at a
   file boundary), and resumes the same decoder for the next file. Peak memory
   is the LZMA window (capped at the folder's unpacked size) or the PPMd model,
   plus a 256 KiB staging buffer, and does not grow with the folder or the file.

   The accepted folder shape is a linear one-pack-stream chain

     pack -> [AES] -> main -> [filter] -> out

   with main = Copy / LZMA / LZMA2 / PPMd, AES = 7zAES (CBC, so it decrypts on
   the fly) and filter = Delta / BCJ / PPC / IA64 / ARM / ARMT / ARM64 / SPARC /
   RISCV. BCJ2 (four pack streams) and any other graph give SZ_ERROR_UNSUPPORTED
   and the caller must fall back to SzArEx_Extract for those.
   SzAr_IsFolderStreamable() reports the same decision without decoding, so a
   caller can choose the path up front.

   Peek() hands out the next run of unpacked bytes without consuming them (the
   returned pointer stays valid until the next Peek); Consume() takes however
   much of it the caller used and rolls the folder CRC over those bytes. A
   returned size of 0 is the end of the folder. Finish() verifies the folder CRC
   once everything has been consumed, i.e. after the bytes have already been
   handed out, so a caller that must not publish unverified data has to stage
   its output (write to a temporary file and rename it only on success) and to
   check its own per-file digest as well.

   The stream owns its position in the ILookInStream it was created on: nothing
   else may read or seek that stream while the folder stream is alive. */

typedef struct CSzFolderStream CSzFolderStream;

int SzAr_IsFolderStreamable(const CSzAr *p, UInt32 folderIndex);

SRes SzAr_FolderStream_Create(CSzFolderStream **pp, const CSzAr *p, UInt32 folderIndex,
    ILookInStreamPtr stream, UInt64 startPos, ISzAllocPtr alloc);
SRes SzAr_FolderStream_Peek(CSzFolderStream *p, const Byte **data, size_t *size);
SRes SzAr_FolderStream_Consume(CSzFolderStream *p, size_t size);
SRes SzAr_FolderStream_Finish(CSzFolderStream *p);
void SzAr_FolderStream_Free(CSzFolderStream *p);

typedef struct
{
  CSzAr db;

  UInt64 startPosAfterHeader;
  UInt64 dataPos;
  
  UInt32 NumFiles;

  UInt64 *UnpackPositions;  // NumFiles + 1
  // Byte *IsEmptyFiles;
  Byte *IsDirs;
  CSzBitUi32s CRCs;

  CSzBitUi32s Attribs;
  // CSzBitUi32s Parents;
  CSzBitUi64s MTime;
  CSzBitUi64s CTime;

  UInt32 *FolderToFile;   // NumFolders + 1
  UInt32 *FileToFolder;   // NumFiles

  size_t *FileNameOffsets; /* in 2-byte steps */
  Byte *FileNames;  /* UTF-16-LE */
} CSzArEx;

#define SzArEx_IsDir(p, i) (SzBitArray_Check((p)->IsDirs, i))

#define SzArEx_GetFileSize(p, i) ((p)->UnpackPositions[(i) + 1] - (p)->UnpackPositions[i])

void SzArEx_Init(CSzArEx *p);
void SzArEx_Free(CSzArEx *p, ISzAllocPtr alloc);
UInt64 SzArEx_GetFolderStreamPos(const CSzArEx *p, UInt32 folderIndex, UInt32 indexInFolder);
int SzArEx_GetFolderFullPackSize(const CSzArEx *p, UInt32 folderIndex, UInt64 *resSize);

/*
if dest == NULL, the return value specifies the required size of the buffer,
  in 16-bit characters, including the null-terminating character.
if dest != NULL, the return value specifies the number of 16-bit characters that
  are written to the dest, including the null-terminating character. */

size_t SzArEx_GetFileNameUtf16(const CSzArEx *p, size_t fileIndex, UInt16 *dest);

/*
size_t SzArEx_GetFullNameLen(const CSzArEx *p, size_t fileIndex);
UInt16 *SzArEx_GetFullNameUtf16_Back(const CSzArEx *p, size_t fileIndex, UInt16 *dest);
*/



/*
  SzArEx_Extract extracts file from archive

  *outBuffer must be 0 before first call for each new archive.

  Extracting cache:
    If you need to decompress more than one file, you can send
    these values from previous call:
      *blockIndex,
      *outBuffer,
      *outBufferSize
    You can consider "*outBuffer" as cache of solid block. If your archive is solid,
    it will increase decompression speed.
  
    If you use external function, you can declare these 3 cache variables
    (blockIndex, outBuffer, outBufferSize) as static in that external function.
    
    Free *outBuffer and set *outBuffer to 0, if you want to flush cache.
*/

SRes SzArEx_Extract(
    const CSzArEx *db,
    ILookInStreamPtr inStream,
    UInt32 fileIndex,         /* index of file */
    UInt32 *blockIndex,       /* index of solid block */
    Byte **outBuffer,         /* pointer to pointer to output buffer (allocated with allocMain) */
    size_t *outBufferSize,    /* buffer size for output buffer */
    size_t *offset,           /* offset of stream for required file in *outBuffer */
    size_t *outSizeProcessed, /* size of file in *outBuffer */
    ISzAllocPtr allocMain,
    ISzAllocPtr allocTemp);


/*
SzArEx_Open Errors:
SZ_ERROR_NO_ARCHIVE
SZ_ERROR_ARCHIVE
SZ_ERROR_UNSUPPORTED
SZ_ERROR_MEM
SZ_ERROR_CRC
SZ_ERROR_INPUT_EOF
SZ_ERROR_FAIL
*/

SRes SzArEx_Open(CSzArEx *p, ILookInStreamPtr inStream,
    ISzAllocPtr allocMain, ISzAllocPtr allocTemp);

/* SSP patch: 7z AES (MethodID 0x06F10701) support.
   Set the password (UTF-16LE bytes) before SzArEx_Open / SzArEx_Extract on an
   encrypted archive; pass NULL/0 to clear it. Sz7zAes_WasUsed reports whether an
   AES coder was encountered since the last Sz7zAes_ResetUsed (used to detect that
   an archive open needed a password, e.g. an encrypted header). */
void Sz7zAes_SetPassword(const Byte *utf16lePassword, size_t sizeInBytes);
int  Sz7zAes_WasUsed(void);
void Sz7zAes_ResetUsed(void);

/* Encrypt for the writer side (C7zipper). Set the password via
   Sz7zAes_SetPassword first, then encrypt a 16-byte-multiple buffer in place;
   props (>=18 bytes) receives the 7zAES coder properties to store in the folder. */
SRes Sz7zAes_Encode(Byte *data, size_t size, Byte *props, unsigned *pPropsSize);

EXTERN_C_END

#endif
