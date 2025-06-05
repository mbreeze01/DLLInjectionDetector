#include <iostream>
#include <string>
#include "InjectionGuard.h"
#include "..\InjectionDetector\InjectionDetector.h"

namespace InjectionDetector
{
  InjectionGuard::InjectionGuard()
  {
  }

  InjectionGuard::~InjectionGuard()
  {
  }

  NTSTATUS InjectionGuard::HandleLdrLoadDll(PCWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* DllHandle)
  {
    // This hook is not required for InjectionGuard, as thread creation for DLL loading is already blocked in BaseThreadInitThunk,
    // and DLL loading itself is handled in HandleRtlGetFullPathName_U.
    return InjectionDetector::Instance()->CallLdrLoadDllStub(DllPath, DllCharacteristics, DllName, DllHandle);
  }

  ULONG __stdcall InjectionGuard::HandleRtlGetFullPathName_U(PWSTR FileName, ULONG BufferLength, PWSTR Buffer, PWSTR* FilePart)
  {
    if (FileName != nullptr)
    {
      auto moduleHandle = GetModuleHandleW(FileName); // Checking if the filename belongs to a module. When injected, it is already available using GetModuleHandleW at this point.
      if (moduleHandle != nullptr)
      {
        std::wcout << std::endl << "RtlGetFullPathName_U: Blocked attempt to inject " << FileName << std::endl;
        memset(Buffer, 0, BufferLength);
        return InjectionDetector::Instance()->CallRtlGetFullPathName_UStub(NULL, BufferLength, Buffer, FilePart);
      }
    }
    return InjectionDetector::Instance()->CallRtlGetFullPathName_UStub(FileName, BufferLength, Buffer, FilePart);
  }

  void __fastcall InjectionGuard::HandleBaseThreadInitThunk(IN DWORD LdrReserved, IN LPTHREAD_START_ROUTINE lpStartAddress, IN LPVOID lpParameter)
  {
    bool threadBlocked = false;
    if ((DWORD)lpStartAddress == (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA"))
    {
      threadBlocked = true;
      std::wcout << std::endl << "BaseThreadInitThunk: Blocked thread creation on LoadLibraryA" << std::endl;
    }
    else if ((DWORD)lpStartAddress == (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW"))
    {
      threadBlocked = true;
      std::wcout << std::endl << "BaseThreadInitThunk: Blocked thread creation on LoadLibraryW" << std::endl;
    }
    else if (InjectionDetector::Instance()->IsLdrLoadDllOriginal((DWORD)lpStartAddress))
    {
      threadBlocked = true;
      std::wcout << std::endl << "BaseThreadInitThunk: Blocked thread creation on LdrLoadDll" << std::endl;
    }
    else if (InjectionDetector::Instance()->IsLdrLoadDllHook((DWORD)lpStartAddress))
    {
      threadBlocked = true;
      std::wcout << std::endl << "BaseThreadInitThunk: Blocked thread creation on LdrLoadDllHook" << std::endl;
    }
    else if (InjectionDetector::Instance()->IsLdrLoadDllStub((DWORD)lpStartAddress))
    {
      threadBlocked = true;
      std::wcout << std::endl << "BaseThreadInitThunk: Blocked thread creation on LdrLoadDllStub" << std::endl;
    }
    else
    {
      DWORD startAddress = (DWORD)lpStartAddress;
      if (!InjectionDetector::Instance()->IsModuleAddress(startAddress))
      {
        threadBlocked = true;
        std::wcout << std::endl << "BaseThreadInitThunk: Blocked creation of suspicious thread" << std::endl;
      }
    }

    if (threadBlocked)
    {
      InjectionDetector::Instance()->CallBaseThreadInitThunkStub(LdrReserved, (LPTHREAD_START_ROUTINE)Sleep, 0);
    }
    else
    {
      InjectionDetector::Instance()->CallBaseThreadInitThunkStub(LdrReserved, lpStartAddress, lpParameter);
    }
  }
}
