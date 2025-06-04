#include "HookEngine.h"

namespace HookEngine
{
#pragma pack(push, 1) // Prevent padding bytes
  struct TrampolineInstruction
  {
    const BYTE PushEbp = 0x55;
    const WORD MovEbpEsp = _byteswap_ushort(0x8BEC);
    const BYTE PushOffset = 0x68;
    DWORD Offset = 0x00000000;
    const BYTE Ret = 0xC3;
  };
#pragma pack(pop)

#pragma pack(push, 1) // Prevent padding bytes
  struct HookInstruction
  {
    const BYTE Jmp = 0xE9;
    DWORD Offset = 0x00000000;
  };
#pragma pack(pop)

  const DWORD PATCH_SIZE = 5;

  struct Hook
  {
    PVOID OriginalFunction;
    PVOID HookFunction;
    LPVOID TrampolineFunction;
    BYTE OriginalCode[PATCH_SIZE];
  };
}

namespace HookEngine
{
  HookEngine::HookEngine()
  {
  }

  HookEngine::~HookEngine()
  {
  }

  BOOL HookEngine::InstallHook(PVOID originalFunction, PVOID hookFunction, PVOID& stubFunction)
  {
    if (!CanHook(originalFunction)) return FALSE;

    Hook hook;
    hook.OriginalFunction = originalFunction;
    hook.HookFunction = hookFunction;
    hook.TrampolineFunction = NULL;

    DWORD oldProtect = 0;
    VirtualProtect(hook.OriginalFunction, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy_s(hook.OriginalCode, PATCH_SIZE, hook.OriginalFunction, PATCH_SIZE);

    HookInstruction hookInstruction;
    hookInstruction.Offset = (DWORD)hook.HookFunction - (DWORD)(hook.OriginalFunction) - PATCH_SIZE;
    memcpy_s(hook.OriginalFunction, sizeof(HookInstruction), &hookInstruction, sizeof(HookInstruction));

    hook.TrampolineFunction = VirtualAlloc(NULL, sizeof(TrampolineInstruction), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    TrampolineInstruction trampolineInstruction;
    trampolineInstruction.Offset = (DWORD)((BYTE*)hook.OriginalFunction + PATCH_SIZE);
    memcpy_s(hook.TrampolineFunction, sizeof(TrampolineInstruction), &trampolineInstruction, sizeof(TrampolineInstruction));

    stubFunction = (PVOID*)hook.TrampolineFunction;

    return TRUE;
  }

  BOOL HookEngine::CanHook(PVOID originalFunction)
  {
    // Only supporting WinAPIs using
    // 
    // mov edi, edi
    // push ebp
    // mov ebp, esp

    if (*(WORD*)originalFunction != _byteswap_ushort(0x8BFF)) return FALSE;
    return TRUE;
  }
}