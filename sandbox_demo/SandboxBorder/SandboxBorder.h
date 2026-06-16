#pragma once
// ============================================================
//  SandboxBorder.h  —  Shared definitions for the injected shell broker
//
//  This header is included by:
//    - SandboxBorder.dll  (the injected payload)
//    - SandboxExplorer.cpp (the launcher that injects it)
//
//  The DLL is injected into sandboxed processes and watches for
//  SHOpenFolderAndSelectItems / ShellExecute
//      "open" verbs that Chrome fires for "Show in folder".
//      When detected, it marshals the call to a helper that
//      launches a NEW sandboxed Explorer pointing at the
//      virtual (sandbox) download path, instead of the real one.
//
//  IPC between the DLL and the Qt host uses a single named pipe:
//      \\.\pipe\SandboxFlt_Broker
//  ALL boxes share one pipe; the box name is inside the JSON payload.
//  The DLL sends: {"cmd":"openFolder","box":"Box00","path":"C:\\..."}
//  The Qt host reads it and calls SandboxEngine::launch(explorer).
// ============================================================

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

// Name of the exported init function the launcher calls after injection
#define SANDBOX_BORDER_INIT_PROC   "SandboxBorder_Init"
#define SANDBOX_BORDER_UNINIT_PROC "SandboxBorder_Uninit"

// Environment variable the launcher sets in the child so the DLL
// can identify the box without a pipe round-trip.
#define SANDBOX_BORDER_BOX_ENV     L"SANDBOX_BOX"

// Single broker pipe shared by all boxes.
// Box identity is carried in the JSON body, not the pipe name.
// Must match kPipeName in SandboxExplorer.cpp.
#define SANDBOX_PIPE_NAME          L"\\\\.\\pipe\\SandboxFlt_Broker"

// Exported from the DLL
#ifdef SANDBOXBORDER_EXPORTS
#  define SBAPI __declspec(dllexport)
#else
#  define SBAPI __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Called once by the launcher's suspended-thread bootstrap after LoadLibrary.
// The box name is read from an environment variable already in the child.
SBAPI BOOL WINAPI SandboxBorder_Init(void);
SBAPI BOOL WINAPI SandboxBorder_Uninit(void);

#ifdef __cplusplus
}
#endif
