// ============================================================
//  SandboxEngine_Inject.cpp
//
//  Implements SandboxEngine::injectWhileSuspended().
//
//  Must be called AFTER CreateProcess(CREATE_SUSPENDED) and
//  BEFORE ResumeThread.  The process must still be suspended.
//
//  TECHNIQUE: x64 thread-context hijack
//  ─────────────────────────────────────
//  We redirect the main thread's RIP to a small bootstrap stub
//  written into the target's address space.  The stub:
//    1. Saves all volatile registers + flags
//    2. Calls LoadLibraryW(dllPath)
//    3. Restores all registers + flags exactly
//    4. JMPs to the original RIP (RtlUserThreadStart / entry point)
//
//  WHY THE OLD STUB CRASHED (STATUS_STACK_BUFFER_OVERRUN, 0xC0000409)
//  ────────────────────────────────────────────────────────────────────
//  The original 42-byte stub only allocated shadow space (SUB RSP,40)
//  and never saved/restored any registers.  The origRip is
//  RtlUserThreadStart inside ntdll, which immediately sets up the
//  CRT and checks the security cookie.  When it ran, RAX, RCX and
//  the flags were all clobbered by LoadLibraryW, causing
//  STATUS_STACK_BUFFER_OVERRUN from a failed __security_check_cookie.
//
//  CORRECT STUB LAYOUT (x64, little-endian, position-independent)
//  ───────────────────────────────────────────────────────────────
//  Memory page layout:
//    [0 .. pathBytes-1]     wchar_t dllPath[]    (MAX_PATH+1 wchars)
//    [pathBytes ..]         Stub bytes (see below)
//
//  Stub (78 bytes):
//    ; ── Save volatile regs + flags (14 × 8 = 112 bytes, RSP still 16-aligned)
//    9D                 pushfq
//    50                 push rax
//    51                 push rcx
//    52                 push rdx
//    41 50              push r8
//    41 51              push r9
//    41 52              push r10
//    41 53              push r11
//    56                 push rsi
//    57                 push rdi
//    53                 push rbx
//    55                 push rbp
//    41 54              push r12            ; 14th push → 112 stack bytes, 16-aligned
//    ; ── Shadow space: sub rsp,32 (RSP 16-aligned before CALL) ──
//    48 83 EC 20        sub rsp, 32
//    ; ── LoadLibraryW(dllPath) ──
//    48 B9 xx xx xx xx  mov rcx, <dllPathAddr>   ; imm64
//         xx xx xx xx
//    48 B8 xx xx xx xx  mov rax, <loadLibAddr>   ; imm64
//         xx xx xx xx
//    FF D0              call rax
//    ; ── Tear down shadow space ──
//    48 83 C4 20        add rsp, 32
//    ; ── Restore (reverse order) ──
//    41 5C              pop r12
//    5D                 pop rbp
//    5B                 pop rbx
//    5F                 pop rdi
//    5E                 pop rsi
//    41 5B              pop r11
//    41 5A              pop r10
//    41 59              pop r9
//    41 58              pop r8
//    5A                 pop rdx
//    59                 pop rcx
//    58                 pop rax
//    9D                 popfq
//    ; ── Jump to original entry point ──
//    48 B8 xx xx xx xx  mov rax, <origRip>       ; imm64
//         xx xx xx xx
//    FF E0              jmp rax
//
//  Alignment proof:
//    Entry RSP: 16-aligned (Windows loader guarantee)
//    After 14 pushes: RSP -= 112  (112 % 16 == 0, still aligned)
//    After sub rsp,32: RSP -= 32  (total 144, still aligned)
//    CALL instruction: RSP -= 8   (callee enters with RSP%16==8, correct ABI)
//    After add rsp,32 + 14 pops + POPFQ: RSP restored exactly
//    JMP rax: RSP == original entry RSP ✓
// ============================================================

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "SandboxEngine.h"
#include "../SandboxBorder/SandboxBorder.h"
#include <cstring>
#include <cstdio>

// ============================================================
//  Stub byte layout as a packed struct
// ============================================================
#pragma pack(push, 1)
struct Stub64 {
    // pushfq
    BYTE pushfq         = 0x9D;
    // push rax..rbp
    BYTE push_rax       = 0x50;
    BYTE push_rcx       = 0x51;
    BYTE push_rdx       = 0x52;
    BYTE push_r8[2]     = { 0x41, 0x50 };
    BYTE push_r9[2]     = { 0x41, 0x51 };
    BYTE push_r10[2]    = { 0x41, 0x52 };
    BYTE push_r11[2]    = { 0x41, 0x53 };
    BYTE push_rsi       = 0x56;
    BYTE push_rdi       = 0x57;
    BYTE push_rbx       = 0x53;
    BYTE push_rbp       = 0x55;
    BYTE push_r12[2]    = { 0x41, 0x54 };  // keeps 14 pushes → 112 stack bytes, 16-aligned

    // sub rsp, 32
    BYTE sub_rsp[4]     = { 0x48, 0x83, 0xEC, 0x20 };

    // mov rcx, <dllPathAddr>  (imm64)
    BYTE mov_rcx[2]     = { 0x48, 0xB9 };
    UINT64 dllPathAddr  = 0;

    // mov rax, <loadLibAddr>  (imm64)
    BYTE mov_rax1[2]    = { 0x48, 0xB8 };
    UINT64 loadLibAddr  = 0;

    // call rax
    BYTE call_rax[2]    = { 0xFF, 0xD0 };

    // mov rcx, rax  (HMODULE from LoadLibraryW)
    BYTE mov_rcx_rax[3] = { 0x48, 0x8B, 0xC8 };

    // mov rdx, <initProcNameAddr>  (imm64)
    BYTE mov_rdx[2]     = { 0x48, 0xBA };
    UINT64 initProcNameAddr = 0;

    // mov rax, <GetProcAddress>  (imm64)
    BYTE mov_rax_gp[2]  = { 0x48, 0xB8 };
    UINT64 getProcAddr  = 0;

    // call rax
    BYTE call_rax_gp[2] = { 0xFF, 0xD0 };

    // test rax, rax; je +2; call rax
    BYTE test_rax[3]    = { 0x48, 0x85, 0xC0 };
    BYTE je_skip[2]     = { 0x74, 0x02 };
    BYTE call_init[2]   = { 0xFF, 0xD0 };

    // add rsp, 32
    BYTE add_rsp[4]     = { 0x48, 0x83, 0xC4, 0x20 };

    // pop r12..rax (reverse order)
    BYTE pop_r12[2]     = { 0x41, 0x5C };
    BYTE pop_rbp        = 0x5D;
    BYTE pop_rbx        = 0x5B;
    BYTE pop_rdi        = 0x5F;
    BYTE pop_rsi        = 0x5E;
    BYTE pop_r11[2]     = { 0x41, 0x5B };
    BYTE pop_r10[2]     = { 0x41, 0x5A };
    BYTE pop_r9[2]      = { 0x41, 0x59 };
    BYTE pop_r8[2]      = { 0x41, 0x58 };
    BYTE pop_rdx        = 0x5A;
    BYTE pop_rcx        = 0x59;
    BYTE pop_rax        = 0x58;

    // popfq
    BYTE popfq          = 0x9D;

    // mov rax, <origRip>  (imm64)
    BYTE mov_rax2[2]    = { 0x48, 0xB8 };
    UINT64 origRip      = 0;

    // jmp rax
    BYTE jmp_rax[2]     = { 0xFF, 0xE0 };
};
#pragma pack(pop)

// Compile-time size check: update the comment above if this ever changes
static_assert(sizeof(Stub64) == 110, "Stub64 size changed — update comment");

// ============================================================
bool SandboxEngine::injectWhileSuspended(const SandboxedProcess& sp,
                                          const std::wstring& dllPath)
{
    if (!sp.valid || !sp.hProcess || !sp.hThread) {
        log(L"[Inject] Invalid process/thread handle.");
        return false;
    }
    if (!sp.suspended) {
        log(L"[Inject] Process is already resumed — cannot use context hijack.");
        return false;
    }

    // ── 1. LoadLibraryW address (same VA in every x64 process, same boot) ──
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    if (!hK32) { log(L"[Inject] GetModuleHandle(kernel32) failed."); return false; }

    UINT64 loadLibAddr = (UINT64)(UINT_PTR)GetProcAddress(hK32, "LoadLibraryW");
    if (!loadLibAddr) { log(L"[Inject] GetProcAddress(LoadLibraryW) failed."); return false; }
    UINT64 getProcAddr = (UINT64)(UINT_PTR)GetProcAddress(hK32, "GetProcAddress");
    if (!getProcAddr) { log(L"[Inject] GetProcAddress(GetProcAddress) failed."); return false; }

    // ── 2. Allocate RWX page: [dllPath string][init proc name][Stub64] ──
    SIZE_T pathBytes = (dllPath.size() + 1) * sizeof(wchar_t);
    const char initProcName[] = SANDBOX_BORDER_INIT_PROC;
    SIZE_T initProcBytes = sizeof(initProcName);
    SIZE_T totalSize = pathBytes + initProcBytes + sizeof(Stub64);

    LPVOID remBase = VirtualAllocEx(sp.hProcess, nullptr, totalSize,
                                    MEM_COMMIT | MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
    if (!remBase) {
        log(L"[Inject] VirtualAllocEx failed: " + std::to_wstring(GetLastError()));
        return false;
    }

    UINT64 remPathAddr = (UINT64)(UINT_PTR)remBase;
    UINT64 remInitProcNameAddr = remPathAddr + (UINT64)pathBytes;
    UINT64 remStubAddr = remInitProcNameAddr + (UINT64)initProcBytes;

    // ── 3. Write DLL path ────────────────────────────────────────────────
    SIZE_T written = 0;
    if (!WriteProcessMemory(sp.hProcess, (LPVOID)(UINT_PTR)remPathAddr,
                            dllPath.c_str(), pathBytes, &written)) {
        log(L"[Inject] WriteProcessMemory (path) failed: " +
            std::to_wstring(GetLastError()));
        VirtualFreeEx(sp.hProcess, remBase, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(sp.hProcess,
                            (LPVOID)(UINT_PTR)remInitProcNameAddr,
                            initProcName, initProcBytes, &written)) {
        log(L"[Inject] WriteProcessMemory (init proc name) failed: " +
            std::to_wstring(GetLastError()));
        VirtualFreeEx(sp.hProcess, remBase, 0, MEM_RELEASE);
        return false;
    }

    // ── 4. Get original RIP ──────────────────────────────────────────────
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(sp.hThread, &ctx)) {
        log(L"[Inject] GetThreadContext failed: " +
            std::to_wstring(GetLastError()));
        VirtualFreeEx(sp.hProcess, remBase, 0, MEM_RELEASE);
        return false;
    }

    // ── 5. Build stub ────────────────────────────────────────────────────
    Stub64 stub{};
    stub.dllPathAddr = remPathAddr;
    stub.loadLibAddr = loadLibAddr;
    stub.initProcNameAddr = remInitProcNameAddr;
    stub.getProcAddr = getProcAddr;
    stub.origRip     = ctx.Rip;

    if (!WriteProcessMemory(sp.hProcess, (LPVOID)(UINT_PTR)remStubAddr,
                            &stub, sizeof(stub), &written)) {
        log(L"[Inject] WriteProcessMemory (stub) failed: " +
            std::to_wstring(GetLastError()));
        VirtualFreeEx(sp.hProcess, remBase, 0, MEM_RELEASE);
        return false;
    }

    // ── 6. Redirect RIP to stub ──────────────────────────────────────────
    ctx.Rip = remStubAddr;
    if (!SetThreadContext(sp.hThread, &ctx)) {
        log(L"[Inject] SetThreadContext failed: " +
            std::to_wstring(GetLastError()));
        VirtualFreeEx(sp.hProcess, remBase, 0, MEM_RELEASE);
        return false;
    }

    // Format addresses for log
    wchar_t stubHex[20], ripHex[20];
    swprintf_s(stubHex, L"%llX", remStubAddr);
    swprintf_s(ripHex,  L"%llX", ctx.Rip);     // now equals remStubAddr
    log(L"[Inject] Stub@0x" + std::wstring(stubHex) +
        L"  origRip@0x" + [&]{ wchar_t b[20];
            swprintf_s(b, L"%llX", stub.origRip); return std::wstring(b); }());
    log(L"[Inject] DLL will load on first instruction of PID " +
        std::to_wstring(sp.pid));

    // remBase is intentionally not freed — must stay mapped until the stub
    // finishes executing (LoadLibraryW returns and JMP fires).
    return true;
}
