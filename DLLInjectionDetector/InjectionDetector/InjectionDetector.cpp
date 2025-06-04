#include <Windows.h>
#include "InjectionDetector.h"
#include "IInjectionHandler.h"
#include "..\HookEngine\HookEngine.h"

namespace InjectionDetector
{
  InjectionDetector* InjectionDetector::_instance = nullptr;
  std::mutex InjectionDetector::_mutex;

  InjectionDetector::InjectionDetector()
  {
    _injectionHandler = nullptr;

    _ldrLoadDll_Original = nullptr;
    _ldrLoadDll_Stub = nullptr;

    _rtlGetFullPathName_U_Original = nullptr;
    _rtlGetFullPathName_U_Stub = nullptr;

    _baseThreadInitThunk_Original = nullptr;
    _baseThreadInitThunk_Stub = nullptr;
  }

  InjectionDetector::~InjectionDetector()
  {
  }

  InjectionDetector* InjectionDetector::Instance()
  {
    std::lock_guard<std::mutex> lock(_mutex);
    if (_instance == nullptr)
    {
      _instance = new InjectionDetector();
    }
    return _instance;
  }

  void InjectionDetector::Initialze(IInjectionHandler* injectionHandler)
  {
    _injectionHandler = injectionHandler;

    HookEngine::HookEngine hookEngine;

    _ldrLoadDll_Original = (LdrLoadDll*)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "LdrLoadDll");
    hookEngine.InstallHook(_ldrLoadDll_Original, LdrLoadDll_Hook, (PVOID&)_ldrLoadDll_Stub);

    _rtlGetFullPathName_U_Original = (RtlGetFullPathName_U*)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlGetFullPathName_U");
    hookEngine.InstallHook(_rtlGetFullPathName_U_Original, RtlGetFullPathName_U_Hook, (PVOID&)_rtlGetFullPathName_U_Stub);

    _baseThreadInitThunk_Original = (BaseThreadInitThunk*)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "BaseThreadInitThunk");
    hookEngine.InstallHook(_baseThreadInitThunk_Original, BaseThreadInitThunk_Hook, (PVOID&)_baseThreadInitThunk_Stub);
  }
  
  NTSTATUS NTAPI InjectionDetector::LdrLoadDll_Hook(_In_opt_ PCWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ PUNICODE_STRING DllName, _Out_ PVOID* DllHandle)
  {
    return Instance()->GetInjectionHandler()->HandleLdrLoadDll(DllPath, DllCharacteristics, DllName, DllHandle);
  }

  ULONG __stdcall InjectionDetector::RtlGetFullPathName_U_Hook(PWSTR FileName, ULONG BufferLength, PWSTR Buffer, PWSTR* FilePart)
  {
    return Instance()->GetInjectionHandler()->HandleRtlGetFullPathName_U(FileName, BufferLength, Buffer, FilePart);
  }

  void __fastcall InjectionDetector::BaseThreadInitThunk_Hook(IN DWORD LdrReserved, IN LPTHREAD_START_ROUTINE lpStartAddress, IN LPVOID lpParameter)
  {
    Instance()->GetInjectionHandler()->HandleBaseThreadInitThunk(LdrReserved, lpStartAddress, lpParameter);
  }

  NTSTATUS NTAPI InjectionDetector::CallLdrLoadDllStub(_In_opt_ PCWSTR DllPath, _In_opt_ PULONG DllCharacteristics, _In_ PUNICODE_STRING DllName, _Out_ PVOID* DllHandle)
  {
    return _ldrLoadDll_Stub(DllPath, DllCharacteristics, DllName, DllHandle);
  }

  ULONG __stdcall InjectionDetector::CallRtlGetFullPathName_UStub(PWSTR FileName, ULONG BufferLength, PWSTR Buffer, PWSTR* FilePart)
  {
    return _rtlGetFullPathName_U_Stub(FileName, BufferLength, Buffer, FilePart);
  }

  void __fastcall InjectionDetector::CallBaseThreadInitThunkStub(IN DWORD LdrReserved, IN LPTHREAD_START_ROUTINE lpStartAddress, IN LPVOID lpParameter)
  {
    _baseThreadInitThunk_Stub(LdrReserved, lpStartAddress, lpParameter);
  }

  bool InjectionDetector::IsModuleAddress(DWORD startAddress)
  {
    // Iterate through the entire module list using PEB
    bool result = false;

    TEB* teb = (TEB*)NtCurrentTeb();
    PPEB peb = teb->ProcessEnvironmentBlock;
    PLIST_ENTRY pEntry = NULL;
    PLIST_ENTRY pHeadEntry = &peb->Ldr->InMemoryOrderModuleList;
    ULONG Count = 0;

    pEntry = pHeadEntry->Flink;
    while (pEntry != pHeadEntry)
    {
      PLDR_DATA_TABLE_ENTRY pLdrEntry = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
      DWORD base = (DWORD)pLdrEntry->DllBase;
      DWORD size = (DWORD)pLdrEntry->SizeOfImage;

      if (startAddress >= base && startAddress < base + size)
      {
        // startAddress is in a valid module
        result = true;
        break;
      }
      pEntry = pEntry->Flink;
    }

    return result;
  }
}