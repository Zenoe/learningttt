// ============================================================
//  SandboxFlt_Crypto.c - transparent block encryption for vault roots
// ============================================================
#include "SandboxFlt.h"
#include <bcrypt.h>

static BCRYPT_ALG_HANDLE g_AesAlg = NULL;
static BCRYPT_ALG_HANDLE g_ShaAlg = NULL;
static ULONG g_AesObjectLength = 0;
static ULONG g_ShaObjectLength = 0;

typedef struct _CRYPTO_IO_CONTEXT {
    PVOID         CryptoBuffer;
    PMDL          CryptoMdl;
    PMDL          OriginalMdl;
    PVOID         OriginalBuffer;
    PBOX_ENTRY    Box;
    ULONG         OriginalLength;
    LARGE_INTEGER OriginalOffset;
    ULONG         FirstBlock;
    ULONG         BlockCount;
    ULONG         InBlockOffset;
    BOOLEAN       IsRead;
} CRYPTO_IO_CONTEXT, *PCRYPTO_IO_CONTEXT;

static VOID
Crypto_FreeIoContext(_In_opt_ PCRYPTO_IO_CONTEXT Ctx)
{
    if (!Ctx)
        return;

    if (Ctx->CryptoMdl)
        IoFreeMdl(Ctx->CryptoMdl);
    if (Ctx->CryptoBuffer)
        ExFreePoolWithTag(Ctx->CryptoBuffer, SANDBOX_POOL_TAG);

    ExFreePoolWithTag(Ctx, SANDBOX_POOL_TAG);
}

static NTSTATUS
Crypto_QueryObjectLength(_In_ BCRYPT_ALG_HANDLE Alg, _Out_ PULONG Length)
{
    ULONG bytes = 0;
    return BCryptGetProperty(Alg, BCRYPT_OBJECT_LENGTH,
        (PUCHAR)Length, sizeof(*Length), &bytes, 0);
}

NTSTATUS Crypto_Initialize(VOID)
{
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&g_AesAlg,
        BCRYPT_AES_ALGORITHM, NULL, BCRYPT_PROV_DISPATCH);
    if (!NT_SUCCESS(status)) {
        status = BCryptOpenAlgorithmProvider(&g_AesAlg,
            BCRYPT_AES_ALGORITHM, NULL, 0);
    }
    if (!NT_SUCCESS(status))
        return status;

    status = BCryptSetProperty(g_AesAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(status))
        goto Fail;

    status = Crypto_QueryObjectLength(g_AesAlg, &g_AesObjectLength);
    if (!NT_SUCCESS(status))
        goto Fail;

    status = BCryptOpenAlgorithmProvider(&g_ShaAlg,
        BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_PROV_DISPATCH);
    if (!NT_SUCCESS(status)) {
        status = BCryptOpenAlgorithmProvider(&g_ShaAlg,
            BCRYPT_SHA256_ALGORITHM, NULL, 0);
    }
    if (!NT_SUCCESS(status))
        goto Fail;

    status = Crypto_QueryObjectLength(g_ShaAlg, &g_ShaObjectLength);
    if (!NT_SUCCESS(status))
        goto Fail;

    return STATUS_SUCCESS;

Fail:
    Crypto_Cleanup();
    return status;
}

VOID Crypto_Cleanup(VOID)
{
    if (g_AesAlg) {
        BCryptCloseAlgorithmProvider(g_AesAlg, 0);
        g_AesAlg = NULL;
    }
    if (g_ShaAlg) {
        BCryptCloseAlgorithmProvider(g_ShaAlg, 0);
        g_ShaAlg = NULL;
    }
    g_AesObjectLength = 0;
    g_ShaObjectLength = 0;
}

static NTSTATUS
Crypto_DeriveNonce(
    _In_ PBOX_ENTRY Box,
    _In_ ULONG BlockIndex,
    _Out_writes_(CRYPTO_NONCE_SIZE) UCHAR* Nonce)
{
    NTSTATUS status;
    PUCHAR hashObject;
    BCRYPT_HASH_HANDLE hash;
    UCHAR digest[32];
    ULONG index;
    ULONG bytes;

    if (!g_ShaAlg || g_ShaObjectLength == 0)
        return STATUS_INVALID_DEVICE_STATE;

    hashObject = (PUCHAR)ExAllocatePoolWithTag(
        NonPagedPool, g_ShaObjectLength, SANDBOX_POOL_TAG);
    if (!hashObject)
        return STATUS_INSUFFICIENT_RESOURCES;

    hash = NULL;
    RtlZeroMemory(digest, sizeof(digest));
    index = BlockIndex;
    status = BCryptCreateHash(g_ShaAlg, &hash, hashObject,
        g_ShaObjectLength, NULL, 0, 0);
    if (!NT_SUCCESS(status))
        goto Cleanup;

    status = BCryptHashData(hash, Box->MasterKey, sizeof(Box->MasterKey), 0);
    if (!NT_SUCCESS(status))
        goto Cleanup;
    status = BCryptHashData(hash, Box->HmacKey, sizeof(Box->HmacKey), 0);
    if (!NT_SUCCESS(status))
        goto Cleanup;
    status = BCryptHashData(hash, (PUCHAR)&index, sizeof(index), 0);
    if (!NT_SUCCESS(status))
        goto Cleanup;
    status = BCryptHashData(hash, (PUCHAR)Box->BoxName.Buffer,
        Box->BoxName.Length, 0);
    if (!NT_SUCCESS(status))
        goto Cleanup;

    bytes = 0;
    status = BCryptFinishHash(hash, digest, sizeof(digest), 0);
    if (NT_SUCCESS(status))
        RtlCopyMemory(Nonce, digest, CRYPTO_NONCE_SIZE);
    UNREFERENCED_PARAMETER(bytes);

Cleanup:
    if (hash)
        BCryptDestroyHash(hash);
    RtlSecureZeroMemory(digest, sizeof(digest));
    ExFreePoolWithTag(hashObject, SANDBOX_POOL_TAG);
    return status;
}

static NTSTATUS
Crypto_GenerateKey(_In_ PBOX_ENTRY Box,
                   _Out_ BCRYPT_KEY_HANDLE* Key,
                   _Outptr_ PUCHAR* KeyObject)
{
    NTSTATUS status;

    *Key = NULL;
    *KeyObject = NULL;
    if (!g_AesAlg || g_AesObjectLength == 0)
        return STATUS_INVALID_DEVICE_STATE;

    *KeyObject = (PUCHAR)ExAllocatePoolWithTag(
        NonPagedPool, g_AesObjectLength, SANDBOX_POOL_TAG);
    if (!*KeyObject)
        return STATUS_INSUFFICIENT_RESOURCES;

    status = BCryptGenerateSymmetricKey(g_AesAlg, Key,
        *KeyObject, g_AesObjectLength,
        Box->MasterKey, sizeof(Box->MasterKey), 0);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(*KeyObject, SANDBOX_POOL_TAG);
        *KeyObject = NULL;
    }
    return status;
}

NTSTATUS Crypto_EncryptBlock(
    _In_ PBOX_ENTRY Box,
    _In_ ULONG BlockIndex,
    _In_reads_(CRYPTO_BLOCK_SIZE) const UCHAR* Plaintext,
    _Out_writes_(CRYPTO_BLOCK_SIZE + CRYPTO_HEADER_SIZE) UCHAR* Ciphertext)
{
    NTSTATUS status;
    BCRYPT_KEY_HANDLE key;
    PUCHAR keyObject;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    ULONG bytesDone;
    ULONG storedIndex;

    if (!Box || !Box->CryptoEnabled)
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(Ciphertext, CRYPTO_BLOCK_SIZE + CRYPTO_HEADER_SIZE);
    storedIndex = BlockIndex;
    RtlCopyMemory(Ciphertext + CRYPTO_NONCE_SIZE + CRYPTO_TAG_SIZE,
        &storedIndex, sizeof(storedIndex));

    status = Crypto_DeriveNonce(Box, BlockIndex, Ciphertext);
    if (!NT_SUCCESS(status))
        return status;

    status = Crypto_GenerateKey(Box, &key, &keyObject);
    if (!NT_SUCCESS(status))
        return status;

    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = Ciphertext;
    authInfo.cbNonce = CRYPTO_NONCE_SIZE;
    authInfo.pbTag = Ciphertext + CRYPTO_NONCE_SIZE;
    authInfo.cbTag = CRYPTO_TAG_SIZE;
    authInfo.pbAuthData = Ciphertext + CRYPTO_NONCE_SIZE + CRYPTO_TAG_SIZE;
    authInfo.cbAuthData = sizeof(storedIndex);

    bytesDone = 0;
    status = BCryptEncrypt(key,
        (PUCHAR)Plaintext,
        CRYPTO_BLOCK_SIZE,
        &authInfo,
        NULL,
        0,
        Ciphertext + CRYPTO_HEADER_SIZE,
        CRYPTO_BLOCK_SIZE,
        &bytesDone,
        0);

    BCryptDestroyKey(key);
    RtlSecureZeroMemory(keyObject, g_AesObjectLength);
    ExFreePoolWithTag(keyObject, SANDBOX_POOL_TAG);

    if (NT_SUCCESS(status) && bytesDone != CRYPTO_BLOCK_SIZE)
        status = STATUS_DATA_ERROR;
    return status;
}

NTSTATUS Crypto_DecryptBlock(
    _In_ PBOX_ENTRY Box,
    _In_ ULONG BlockIndex,
    _In_reads_(CRYPTO_BLOCK_SIZE + CRYPTO_HEADER_SIZE) const UCHAR* Ciphertext,
    _Out_writes_(CRYPTO_BLOCK_SIZE) UCHAR* Plaintext)
{
    NTSTATUS status;
    BCRYPT_KEY_HANDLE key;
    PUCHAR keyObject;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    ULONG bytesDone;
    ULONG storedIndex;
    UCHAR expectedNonce[CRYPTO_NONCE_SIZE];

    if (!Box || !Box->CryptoEnabled)
        return STATUS_INVALID_PARAMETER;

    RtlCopyMemory(&storedIndex,
        Ciphertext + CRYPTO_NONCE_SIZE + CRYPTO_TAG_SIZE,
        sizeof(storedIndex));
    if (storedIndex != BlockIndex)
        return STATUS_DATA_ERROR;

    status = Crypto_DeriveNonce(Box, BlockIndex, expectedNonce);
    if (!NT_SUCCESS(status))
        return status;
    if (RtlCompareMemory(expectedNonce, Ciphertext,
        CRYPTO_NONCE_SIZE) != CRYPTO_NONCE_SIZE)
        return STATUS_DATA_ERROR;

    status = Crypto_GenerateKey(Box, &key, &keyObject);
    if (!NT_SUCCESS(status))
        return status;

    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)Ciphertext;
    authInfo.cbNonce = CRYPTO_NONCE_SIZE;
    authInfo.pbTag = (PUCHAR)Ciphertext + CRYPTO_NONCE_SIZE;
    authInfo.cbTag = CRYPTO_TAG_SIZE;
    authInfo.pbAuthData = (PUCHAR)Ciphertext + CRYPTO_NONCE_SIZE + CRYPTO_TAG_SIZE;
    authInfo.cbAuthData = sizeof(storedIndex);

    bytesDone = 0;
    status = BCryptDecrypt(key,
        (PUCHAR)Ciphertext + CRYPTO_HEADER_SIZE,
        CRYPTO_BLOCK_SIZE,
        &authInfo,
        NULL,
        0,
        Plaintext,
        CRYPTO_BLOCK_SIZE,
        &bytesDone,
        0);

    BCryptDestroyKey(key);
    RtlSecureZeroMemory(keyObject, g_AesObjectLength);
    ExFreePoolWithTag(keyObject, SANDBOX_POOL_TAG);

    if (NT_SUCCESS(status) && bytesDone != CRYPTO_BLOCK_SIZE)
        status = STATUS_DATA_ERROR;
    return status;
}

LONGLONG Crypto_LogicalToPhysical(_In_ LONGLONG LogicalOffset)
{
    LONGLONG block = LogicalOffset / CRYPTO_BLOCK_SIZE;
    LONGLONG inside = LogicalOffset % CRYPTO_BLOCK_SIZE;
    return block * (CRYPTO_BLOCK_SIZE + CRYPTO_HEADER_SIZE) +
        CRYPTO_HEADER_SIZE + inside;
}

LONGLONG Crypto_PhysicalToLogical(_In_ LONGLONG PhysicalOffset)
{
    LONGLONG physicalBlock = CRYPTO_BLOCK_SIZE + CRYPTO_HEADER_SIZE;
    LONGLONG block = PhysicalOffset / physicalBlock;
    LONGLONG inside = PhysicalOffset % physicalBlock;
    if (inside < CRYPTO_HEADER_SIZE)
        inside = CRYPTO_HEADER_SIZE;
    return block * CRYPTO_BLOCK_SIZE + (inside - CRYPTO_HEADER_SIZE);
}

static LONGLONG
Crypto_BlockPhysicalOffset(_In_ ULONG BlockIndex)
{
    return ((LONGLONG)BlockIndex) *
        (CRYPTO_BLOCK_SIZE + CRYPTO_HEADER_SIZE);
}

static USHORT
Crypto_PathGetVolumeEnd(_In_ PC_UNICODE_STRING Path)
{
    USHORT i;
    USHORT slashCount;
    USHORT charCount;

    slashCount = 0;
    charCount = Path->Length / sizeof(WCHAR);
    for (i = 0; i < charCount; i++) {
        if (Path->Buffer[i] == L'\\') {
            slashCount++;
            if (slashCount == 3)
                return i;
        }
    }
    return 0;
}

static BOOLEAN
Crypto_PathInBoxVault(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PBOX_ENTRY Box)
{
    PFLT_FILE_NAME_INFORMATION nameInfo;
    UNICODE_STRING relPath;
    USHORT volumeEnd;
    NTSTATUS status;
    BOOLEAN match;

    nameInfo = NULL;
    match = FALSE;
    status = FltGetFileNameInformationUnsafe(FltObjects->FileObject,
        FltObjects->Instance,
        FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status))
        return FALSE;

    if (Box->AccessControlEnabled &&
        Box->MountPointNt.Length != 0 &&
        Path_StartsWith((PC_UNICODE_STRING)&nameInfo->Name,
            (PC_UNICODE_STRING)&Box->MountPointNt)) {
        match = TRUE;
        goto Done;
    }

    volumeEnd = Crypto_PathGetVolumeEnd((PC_UNICODE_STRING)&nameInfo->Name);
    if (volumeEnd != 0) {
        relPath.Buffer = nameInfo->Name.Buffer + volumeEnd;
        relPath.Length = nameInfo->Name.Length -
            (USHORT)(volumeEnd * sizeof(WCHAR));
        relPath.MaximumLength = relPath.Length;
        if (Path_StartsWith((PC_UNICODE_STRING)&relPath,
            (PC_UNICODE_STRING)&Box->SandboxRootNt)) {
            match = TRUE;
        }
    }

Done:
    FltReleaseFileNameInformation(nameInfo);
    return match;
}

static PVOID
Crypto_GetWriteSourceBuffer(_In_ PFLT_CALLBACK_DATA Data)
{
    PMDL mdl;

    mdl = Data->Iopb->Parameters.Write.MdlAddress;
    if (mdl)
        return MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    return Data->Iopb->Parameters.Write.WriteBuffer;
}

static PVOID
Crypto_GetOriginalReadBuffer(_In_ PCRYPTO_IO_CONTEXT Ctx)
{
    if (Ctx->OriginalMdl)
        return MmGetSystemAddressForMdlSafe(Ctx->OriginalMdl,
            NormalPagePriority);
    return Ctx->OriginalBuffer;
}

static BOOLEAN
Crypto_BuildMdlForBuffer(_Inout_ PCRYPTO_IO_CONTEXT Ctx, _In_ ULONG Length)
{
    Ctx->CryptoMdl = IoAllocateMdl(Ctx->CryptoBuffer, Length,
        FALSE, FALSE, NULL);
    if (!Ctx->CryptoMdl)
        return FALSE;
    MmBuildMdlForNonPagedPool(Ctx->CryptoMdl);
    return TRUE;
}

static NTSTATUS
Crypto_ReadPlainBlockForWrite(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PBOX_ENTRY Box,
    _In_ ULONG BlockIndex,
    _Out_writes_(CRYPTO_BLOCK_SIZE) UCHAR* PlainBlock)
{
    UCHAR* cipherBlock;
    LARGE_INTEGER offset;
    ULONG bytesRead;
    NTSTATUS status;

    RtlZeroMemory(PlainBlock, CRYPTO_BLOCK_SIZE);
    cipherBlock = (UCHAR*)ExAllocatePoolWithTag(
        NonPagedPool, CRYPTO_BLOCK_SIZE + CRYPTO_HEADER_SIZE,
        SANDBOX_POOL_TAG);
    if (!cipherBlock)
        return STATUS_INSUFFICIENT_RESOURCES;

    offset.QuadPart = Crypto_BlockPhysicalOffset(BlockIndex);
    bytesRead = 0;
    status = FltReadFile(FltObjects->Instance,
        FltObjects->FileObject,
        &offset,
        CRYPTO_BLOCK_SIZE + CRYPTO_HEADER_SIZE,
        cipherBlock,
        FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
        &bytesRead,
        NULL,
        NULL);
    if (NT_SUCCESS(status) &&
        bytesRead == CRYPTO_BLOCK_SIZE + CRYPTO_HEADER_SIZE) {
        status = Crypto_DecryptBlock(Box, BlockIndex, cipherBlock,
            PlainBlock);
    }
    else {
        status = STATUS_SUCCESS;
    }

    RtlSecureZeroMemory(cipherBlock,
        CRYPTO_BLOCK_SIZE + CRYPTO_HEADER_SIZE);
    ExFreePoolWithTag(cipherBlock, SANDBOX_POOL_TAG);
    return status;
}

FLT_PREOP_CALLBACK_STATUS
SandboxFlt_PreWrite(
    _Inout_ PFLT_CALLBACK_DATA             Data,
    _In_    PCFLT_RELATED_OBJECTS          FltObjects,
    _Outptr_result_maybenull_ PVOID*       CompletionContext)
{
    PBOX_ENTRY box;
    PCRYPTO_IO_CONTEXT ctx;
    PVOID source;
    UCHAR* plainBlock;
    UCHAR* encrypted;
    LONGLONG logicalOffset;
    LONGLONG logicalEnd;
    ULONG logicalLength;
    ULONG firstBlock;
    ULONG lastBlock;
    ULONG blockCount;
    ULONG i;
    ULONG physicalLength;
    NTSTATUS status;

    *CompletionContext = NULL;

    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) ||
        FlagOn(Data->Iopb->IrpFlags, IRP_SYNCHRONOUS_PAGING_IO) ||
        FLT_IS_REISSUED_IO(Data))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    box = Filter_GetCurrentBox();
    if (!box || !box->CryptoEnabled)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!Crypto_PathInBoxVault(FltObjects, box))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    logicalLength = Data->Iopb->Parameters.Write.Length;
    logicalOffset = Data->Iopb->Parameters.Write.ByteOffset.QuadPart;
    if (logicalLength == 0 || logicalOffset < 0)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    status = FltLockUserBuffer(Data);
    if (!NT_SUCCESS(status))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    source = Crypto_GetWriteSourceBuffer(Data);
    if (!source)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    logicalEnd = logicalOffset + logicalLength;
    firstBlock = (ULONG)(logicalOffset / CRYPTO_BLOCK_SIZE);
    lastBlock = (ULONG)((logicalEnd - 1) / CRYPTO_BLOCK_SIZE);
    blockCount = lastBlock - firstBlock + 1;
    if (blockCount > (MAXULONG / (CRYPTO_BLOCK_SIZE + CRYPTO_HEADER_SIZE)))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    physicalLength = blockCount * (CRYPTO_BLOCK_SIZE + CRYPTO_HEADER_SIZE);

    ctx = (PCRYPTO_IO_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(CRYPTO_IO_CONTEXT), SANDBOX_POOL_TAG);
    if (!ctx)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    RtlZeroMemory(ctx, sizeof(*ctx));

    encrypted = (UCHAR*)ExAllocatePoolWithTag(
        NonPagedPool, physicalLength, SANDBOX_POOL_TAG);
    plainBlock = (UCHAR*)ExAllocatePoolWithTag(
        NonPagedPool, CRYPTO_BLOCK_SIZE, SANDBOX_POOL_TAG);
    if (!encrypted || !plainBlock) {
        if (encrypted)
            ExFreePoolWithTag(encrypted, SANDBOX_POOL_TAG);
        if (plainBlock)
            ExFreePoolWithTag(plainBlock, SANDBOX_POOL_TAG);
        ExFreePoolWithTag(ctx, SANDBOX_POOL_TAG);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    for (i = 0; i < blockCount; ++i) {
        LONGLONG blockLogicalStart;
        LONGLONG copyStart;
        LONGLONG copyEnd;
        ULONG dstOffset;
        ULONG srcOffset;
        ULONG copyLength;
        BOOLEAN fullBlock;

        blockLogicalStart = ((LONGLONG)(firstBlock + i)) *
            CRYPTO_BLOCK_SIZE;
        copyStart = logicalOffset > blockLogicalStart ?
            logicalOffset : blockLogicalStart;
        copyEnd = logicalEnd < blockLogicalStart + CRYPTO_BLOCK_SIZE ?
            logicalEnd : blockLogicalStart + CRYPTO_BLOCK_SIZE;
        dstOffset = (ULONG)(copyStart - blockLogicalStart);
        srcOffset = (ULONG)(copyStart - logicalOffset);
        copyLength = (ULONG)(copyEnd - copyStart);
        fullBlock = (BOOLEAN)(dstOffset == 0 &&
            copyLength == CRYPTO_BLOCK_SIZE);

        if (fullBlock) {
            RtlCopyMemory(plainBlock, (UCHAR*)source + srcOffset,
                CRYPTO_BLOCK_SIZE);
        }
        else {
            status = Crypto_ReadPlainBlockForWrite(FltObjects, box,
                firstBlock + i, plainBlock);
            if (!NT_SUCCESS(status)) {
                RtlSecureZeroMemory(plainBlock, CRYPTO_BLOCK_SIZE);
                RtlSecureZeroMemory(encrypted, physicalLength);
                ExFreePoolWithTag(plainBlock, SANDBOX_POOL_TAG);
                ExFreePoolWithTag(encrypted, SANDBOX_POOL_TAG);
                ExFreePoolWithTag(ctx, SANDBOX_POOL_TAG);
                Data->IoStatus.Status = status;
                Data->IoStatus.Information = 0;
                return FLT_PREOP_COMPLETE;
            }
            RtlCopyMemory(plainBlock + dstOffset,
                (UCHAR*)source + srcOffset, copyLength);
        }

        status = Crypto_EncryptBlock(box, firstBlock + i, plainBlock,
            encrypted + i * (CRYPTO_BLOCK_SIZE + CRYPTO_HEADER_SIZE));
        if (!NT_SUCCESS(status)) {
            RtlSecureZeroMemory(plainBlock, CRYPTO_BLOCK_SIZE);
            RtlSecureZeroMemory(encrypted, physicalLength);
            ExFreePoolWithTag(plainBlock, SANDBOX_POOL_TAG);
            ExFreePoolWithTag(encrypted, SANDBOX_POOL_TAG);
            ExFreePoolWithTag(ctx, SANDBOX_POOL_TAG);
            Data->IoStatus.Status = status;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }
    }

    RtlSecureZeroMemory(plainBlock, CRYPTO_BLOCK_SIZE);
    ExFreePoolWithTag(plainBlock, SANDBOX_POOL_TAG);

    ctx->CryptoBuffer = encrypted;
    ctx->OriginalMdl = Data->Iopb->Parameters.Write.MdlAddress;
    ctx->OriginalBuffer = Data->Iopb->Parameters.Write.WriteBuffer;
    ctx->Box = box;
    ctx->OriginalLength = logicalLength;
    ctx->OriginalOffset = Data->Iopb->Parameters.Write.ByteOffset;
    ctx->IsRead = FALSE;
    if (!Crypto_BuildMdlForBuffer(ctx, physicalLength)) {
        Crypto_FreeIoContext(ctx);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    Data->Iopb->Parameters.Write.WriteBuffer = encrypted;
    Data->Iopb->Parameters.Write.MdlAddress = ctx->CryptoMdl;
    Data->Iopb->Parameters.Write.Length = physicalLength;
    Data->Iopb->Parameters.Write.ByteOffset.QuadPart =
        Crypto_BlockPhysicalOffset(firstBlock);
    FltSetCallbackDataDirty(Data);

    *CompletionContext = ctx;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
SandboxFlt_PostWrite(
    _Inout_ PFLT_CALLBACK_DATA       Data,
    _In_    PCFLT_RELATED_OBJECTS    FltObjects,
    _In_opt_ PVOID                   CompletionContext,
    _In_    FLT_POST_OPERATION_FLAGS Flags)
{
    PCRYPTO_IO_CONTEXT ctx;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    ctx = (PCRYPTO_IO_CONTEXT)CompletionContext;
    if (!ctx)
        return FLT_POSTOP_FINISHED_PROCESSING;

    Data->Iopb->Parameters.Write.WriteBuffer = ctx->OriginalBuffer;
    Data->Iopb->Parameters.Write.MdlAddress = ctx->OriginalMdl;
    Data->Iopb->Parameters.Write.Length = ctx->OriginalLength;
    Data->Iopb->Parameters.Write.ByteOffset = ctx->OriginalOffset;
    if (NT_SUCCESS(Data->IoStatus.Status))
        Data->IoStatus.Information = ctx->OriginalLength;
    FltSetCallbackDataDirty(Data);

    Crypto_FreeIoContext(ctx);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
SandboxFlt_PreRead(
    _Inout_ PFLT_CALLBACK_DATA             Data,
    _In_    PCFLT_RELATED_OBJECTS          FltObjects,
    _Outptr_result_maybenull_ PVOID*       CompletionContext)
{
    PBOX_ENTRY box;
    PCRYPTO_IO_CONTEXT ctx;
    ULONG logicalLength;
    LONGLONG logicalOffset;
    LONGLONG logicalEnd;
    ULONG firstBlock;
    ULONG lastBlock;
    ULONG blockCount;
    ULONG physicalLength;
    NTSTATUS status;

    *CompletionContext = NULL;

    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) ||
        FlagOn(Data->Iopb->IrpFlags, IRP_SYNCHRONOUS_PAGING_IO) ||
        FLT_IS_REISSUED_IO(Data))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    box = Filter_GetCurrentBox();
    if (!box || !box->CryptoEnabled)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!Crypto_PathInBoxVault(FltObjects, box))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    logicalLength = Data->Iopb->Parameters.Read.Length;
    logicalOffset = Data->Iopb->Parameters.Read.ByteOffset.QuadPart;
    if (logicalLength == 0 || logicalOffset < 0)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    status = FltLockUserBuffer(Data);
    if (!NT_SUCCESS(status))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    logicalEnd = logicalOffset + logicalLength;
    firstBlock = (ULONG)(logicalOffset / CRYPTO_BLOCK_SIZE);
    lastBlock = (ULONG)((logicalEnd - 1) / CRYPTO_BLOCK_SIZE);
    blockCount = lastBlock - firstBlock + 1;
    if (blockCount > (MAXULONG / (CRYPTO_BLOCK_SIZE + CRYPTO_HEADER_SIZE)))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    physicalLength = blockCount * (CRYPTO_BLOCK_SIZE + CRYPTO_HEADER_SIZE);

    ctx = (PCRYPTO_IO_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(CRYPTO_IO_CONTEXT), SANDBOX_POOL_TAG);
    if (!ctx)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    RtlZeroMemory(ctx, sizeof(*ctx));

    ctx->CryptoBuffer = ExAllocatePoolWithTag(
        NonPagedPool, physicalLength, SANDBOX_POOL_TAG);
    if (!ctx->CryptoBuffer) {
        ExFreePoolWithTag(ctx, SANDBOX_POOL_TAG);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    RtlZeroMemory(ctx->CryptoBuffer, physicalLength);

    ctx->OriginalMdl = Data->Iopb->Parameters.Read.MdlAddress;
    ctx->OriginalBuffer = Data->Iopb->Parameters.Read.ReadBuffer;
    ctx->Box = box;
    ctx->OriginalLength = logicalLength;
    ctx->OriginalOffset = Data->Iopb->Parameters.Read.ByteOffset;
    ctx->FirstBlock = firstBlock;
    ctx->BlockCount = blockCount;
    ctx->InBlockOffset = (ULONG)(logicalOffset % CRYPTO_BLOCK_SIZE);
    ctx->IsRead = TRUE;
    if (!Crypto_BuildMdlForBuffer(ctx, physicalLength)) {
        Crypto_FreeIoContext(ctx);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    Data->Iopb->Parameters.Read.ReadBuffer = ctx->CryptoBuffer;
    Data->Iopb->Parameters.Read.MdlAddress = ctx->CryptoMdl;
    Data->Iopb->Parameters.Read.Length = physicalLength;
    Data->Iopb->Parameters.Read.ByteOffset.QuadPart =
        Crypto_BlockPhysicalOffset(firstBlock);
    FltSetCallbackDataDirty(Data);

    *CompletionContext = ctx;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
SandboxFlt_PostRead(
    _Inout_ PFLT_CALLBACK_DATA       Data,
    _In_    PCFLT_RELATED_OBJECTS    FltObjects,
    _In_opt_ PVOID                   CompletionContext,
    _In_    FLT_POST_OPERATION_FLAGS Flags)
{
    PCRYPTO_IO_CONTEXT ctx;
    PBOX_ENTRY box;
    UCHAR* outBuffer;
    UCHAR* plainBlock;
    ULONG physicalReturned;
    ULONG fullBlocks;
    ULONG i;
    ULONG logicalCopied;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(FltObjects);

    ctx = (PCRYPTO_IO_CONTEXT)CompletionContext;
    if (!ctx)
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) {
        Crypto_FreeIoContext(ctx);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    Data->Iopb->Parameters.Read.ReadBuffer = ctx->OriginalBuffer;
    Data->Iopb->Parameters.Read.MdlAddress = ctx->OriginalMdl;
    Data->Iopb->Parameters.Read.Length = ctx->OriginalLength;
    Data->Iopb->Parameters.Read.ByteOffset = ctx->OriginalOffset;

    if (!NT_SUCCESS(Data->IoStatus.Status)) {
        Crypto_FreeIoContext(ctx);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    box = ctx->Box;
    if (!box || !box->CryptoEnabled) {
        Crypto_FreeIoContext(ctx);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    outBuffer = (UCHAR*)Crypto_GetOriginalReadBuffer(ctx);
    if (!outBuffer) {
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Data->IoStatus.Information = 0;
        Crypto_FreeIoContext(ctx);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    plainBlock = (UCHAR*)ExAllocatePoolWithTag(
        NonPagedPool, CRYPTO_BLOCK_SIZE, SANDBOX_POOL_TAG);
    if (!plainBlock) {
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Data->IoStatus.Information = 0;
        Crypto_FreeIoContext(ctx);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    physicalReturned = (ULONG)Data->IoStatus.Information;
    fullBlocks = physicalReturned /
        (CRYPTO_BLOCK_SIZE + CRYPTO_HEADER_SIZE);
    if (fullBlocks > ctx->BlockCount)
        fullBlocks = ctx->BlockCount;

    logicalCopied = 0;
    status = STATUS_SUCCESS;
    for (i = 0; i < fullBlocks; ++i) {
        ULONG startInBlock;
        ULONG available;
        ULONG copyLength;

        status = Crypto_DecryptBlock(box, ctx->FirstBlock + i,
            (UCHAR*)ctx->CryptoBuffer +
            i * (CRYPTO_BLOCK_SIZE + CRYPTO_HEADER_SIZE),
            plainBlock);
        if (!NT_SUCCESS(status))
            break;

        startInBlock = (i == 0) ? ctx->InBlockOffset : 0;
        available = CRYPTO_BLOCK_SIZE - startInBlock;
        copyLength = ctx->OriginalLength - logicalCopied;
        if (copyLength > available)
            copyLength = available;

        RtlCopyMemory(outBuffer + logicalCopied,
            plainBlock + startInBlock, copyLength);
        logicalCopied += copyLength;
        if (logicalCopied >= ctx->OriginalLength)
            break;
    }

    RtlSecureZeroMemory(plainBlock, CRYPTO_BLOCK_SIZE);
    ExFreePoolWithTag(plainBlock, SANDBOX_POOL_TAG);

    if (!NT_SUCCESS(status)) {
        Data->IoStatus.Status = status;
        Data->IoStatus.Information = 0;
    }
    else {
        Data->IoStatus.Information = logicalCopied;
    }
    FltSetCallbackDataDirty(Data);

    Crypto_FreeIoContext(ctx);
    return FLT_POSTOP_FINISHED_PROCESSING;
}
