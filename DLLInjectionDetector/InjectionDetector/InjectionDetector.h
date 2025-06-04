#pragma once
#include <mutex>
#include "IInjectionHandler.h"
#include "..\TypeDefs\TypeDefs.h"

namespace InjectionDetector
{
  class IInjectionHandler;
}

namespace InjectionDetector
{
  class InjectionDetector
  {
  public:
    static InjectionDetector* Instance();
    void Initialze(IInjectionHandler* injectionHandler);

    NTSTATUS NTAPI CallLdrLoadDllStub(_In_opt_ PCWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ PUNICODE_STRING DllName, _Out_ PVOID* DllHandle);
    ULONG __stdcall CallRtlGetFullPathName_UStub(PWSTR FileName, ULONG BufferLength, PWSTR Buffer, PWSTR* FilePart);
    void __fastcall CallBaseThreadInitThunkStub(IN DWORD LdrReserved, IN LPTHREAD_START_ROUTINE lpStartAddress, IN LPVOID lpParameter);

    bool IsLdrLoadDllOriginal(DWORD address) { return address == (DWORD)_ldrLoadDll_Original; }
    bool IsLdrLoadDllStub(DWORD address) { return address == (DWORD)_baseThreadInitThunk_Stub; }
    bool IsLdrLoadDllHook(DWORD address) { return address == (DWORD)LdrLoadDll_Hook; }

    bool IsModuleAddress(DWORD startAddress);

  private:
    InjectionDetector();
    ~InjectionDetector();

    static NTSTATUS NTAPI LdrLoadDll_Hook(_In_opt_ PCWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ PUNICODE_STRING DllName, _Out_ PVOID* DllHandle);
    static ULONG __stdcall RtlGetFullPathName_U_Hook(PWSTR FileName, ULONG BufferLength, PWSTR Buffer, PWSTR* FilePart);
    static void __fastcall BaseThreadInitThunk_Hook(IN DWORD LdrReserved, IN LPTHREAD_START_ROUTINE lpStartAddress, IN LPVOID lpParameter);

    IInjectionHandler* GetInjectionHandler() { return _injectionHandler; }

  private:
    static InjectionDetector* _instance;
    static std::mutex _mutex;

    IInjectionHandler* _injectionHandler;

    LdrLoadDll* _ldrLoadDll_Original;
    LdrLoadDll* _ldrLoadDll_Stub;

    RtlGetFullPathName_U* _rtlGetFullPathName_U_Original;
    RtlGetFullPathName_U* _rtlGetFullPathName_U_Stub;

    BaseThreadInitThunk* _baseThreadInitThunk_Original;
    BaseThreadInitThunk* _baseThreadInitThunk_Stub;
  };
}