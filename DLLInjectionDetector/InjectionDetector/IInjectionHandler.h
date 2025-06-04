#pragma once
#include <Windows.h>
#include "..\TypeDefs\TypeDefs.h"

namespace InjectionDetector
{
  class IInjectionHandler
  {
  public:
    virtual NTSTATUS NTAPI HandleLdrLoadDll(_In_opt_ PCWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ PUNICODE_STRING DllName, _Out_ PVOID* DllHandle) = 0;
    virtual ULONG __stdcall HandleRtlGetFullPathName_U(PWSTR FileName, ULONG BufferLength, PWSTR Buffer, PWSTR* FilePart) = 0;
    virtual void __fastcall HandleBaseThreadInitThunk(IN DWORD LdrReserved, IN LPTHREAD_START_ROUTINE lpStartAddress, IN LPVOID lpParameter) = 0;
  };
}