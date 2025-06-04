#include <iostream>
#include <string>
#include "InjectionGuard.h"
#include "..\InjectionDetector\InjectionDetector.h"

namespace InjectionDetector
{
  InjectionGuard::InjectionGuard()
  {
    _blockDllLoading = false;
  }

  InjectionGuard::~InjectionGuard()
  {
  }

  NTSTATUS InjectionGuard::HandleLdrLoadDll(PCWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* DllHandle)
  {
    if (_blockDllLoading == false)
    {
      return InjectionDetector::Instance()->CallLdrLoadDllStub(DllPath, DllCharacteristics, DllName, DllHandle);
    }
    else
    {
      _blockDllLoading = false;
      std::wcout << std::endl << "LdrLoadDll: Blocked attempt to inject " << DllName->Buffer << std::endl;
      return -1;
    }
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
        return InjectionDetector::Instance()->CallRtlGetFullPathName_UStub(NULL, BufferLength, Buffer, FilePart);;
      }
    }
    return InjectionDetector::Instance()->CallRtlGetFullPathName_UStub(FileName, BufferLength, Buffer, FilePart);
  }

  void __fastcall InjectionGuard::HandleBaseThreadInitThunk(IN DWORD LdrReserved, IN LPTHREAD_START_ROUTINE lpStartAddress, IN LPVOID lpParameter)
  {
    if ((DWORD)lpStartAddress == (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA"))
    {
      _blockDllLoading = true;
      std::wcout << std::endl << "BaseThreadInitThunk: Detected thread creation on LoadLibraryA" << std::endl;
    }
    else if ((DWORD)lpStartAddress == (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW"))
    {
      _blockDllLoading = true;
      std::wcout << std::endl << "BaseThreadInitThunk: Detected thread creation on LoadLibraryW" << std::endl;
    }
    else if (InjectionDetector::Instance()->IsLdrLoadDllOriginal((DWORD)lpStartAddress))
    {
      _blockDllLoading = true;
      std::wcout << std::endl << "BaseThreadInitThunk: Detected thread creation on LdrLoadDll" << std::endl;
    }
    else if (InjectionDetector::Instance()->IsLdrLoadDllHook((DWORD)lpStartAddress))
    {
      _blockDllLoading = true;
      std::wcout << std::endl << "BaseThreadInitThunk: Detected thread creation on LdrLoadDllHook" << std::endl;
    }
    else if (InjectionDetector::Instance()->IsLdrLoadDllStub((DWORD)lpStartAddress))
    {
      _blockDllLoading = true;
      std::wcout << std::endl << "BaseThreadInitThunk: Detected thread creation on LdrLoadDllStub" << std::endl;
    }
    else
    {
      DWORD startAddress = (DWORD)lpStartAddress;
      if (!InjectionDetector::Instance()->IsModuleAddress(startAddress))
      {
        std::wcout << std::endl << "BaseThreadInitThunk: Blocked creation of suspicious thread" << std::endl;
        InjectionDetector::Instance()->CallBaseThreadInitThunkStub(LdrReserved, (LPTHREAD_START_ROUTINE)Sleep, 0);
        return;
      }
    }
    InjectionDetector::Instance()->CallBaseThreadInitThunkStub(LdrReserved, lpStartAddress, lpParameter);
  }
}
