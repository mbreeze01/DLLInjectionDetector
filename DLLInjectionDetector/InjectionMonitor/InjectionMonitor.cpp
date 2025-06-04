#include <iostream>
#include <string>
#include "InjectionMonitor.h"
#include "..\InjectionDetector\InjectionDetector.h"

namespace InjectionDetector
{
  InjectionMonitor::InjectionMonitor()
  {
    _dllCreationThreadDetected = false;
  }

  InjectionMonitor::~InjectionMonitor()
  {
  }

  NTSTATUS InjectionMonitor::HandleLdrLoadDll(PCWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* DllHandle)
  {
    if (_dllCreationThreadDetected)
    {
      _dllCreationThreadDetected = false;
      std::wcout << std::endl << "LdrLoadDll: Detected dll " << DllName->Buffer << std::endl;
    }
    return InjectionDetector::Instance()->CallLdrLoadDllStub(DllPath, DllCharacteristics, DllName, DllHandle);
  }

  ULONG __stdcall InjectionMonitor::HandleRtlGetFullPathName_U(PWSTR FileName, ULONG BufferLength, PWSTR Buffer, PWSTR* FilePart)
  {
    if (FileName != nullptr)
    {
      auto moduleHandle = GetModuleHandleW(FileName);
      if (moduleHandle != nullptr)
      {
        std::wcout << std::endl << "RtlGetFullPathName_U: Detected dll " << FileName << std::endl;
      }
    }
    return InjectionDetector::Instance()->CallRtlGetFullPathName_UStub(FileName, BufferLength, Buffer, FilePart);
  }

  void __fastcall InjectionMonitor::HandleBaseThreadInitThunk(IN DWORD LdrReserved, IN LPTHREAD_START_ROUTINE lpStartAddress, IN LPVOID lpParameter)
  {
    if ((DWORD)lpStartAddress == (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA"))
    {
      _dllCreationThreadDetected = true;
      std::wcout << std::endl << "BaseThreadInitThunk: Detected thread creation on LoadLibraryA" << std::endl;
    }
    else if ((DWORD)lpStartAddress == (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW"))
    {
      _dllCreationThreadDetected = true;
      std::wcout << std::endl << "BaseThreadInitThunk: Detected thread creation on LoadLibraryW" << std::endl;
    }
    else if (InjectionDetector::Instance()->IsLdrLoadDllOriginal((DWORD)lpStartAddress))
    {
      _dllCreationThreadDetected = true;
      std::wcout << std::endl << "BaseThreadInitThunk: Detected thread creation on LdrLoadDll" << std::endl;
    }
    else if (InjectionDetector::Instance()->IsLdrLoadDllHook((DWORD)lpStartAddress))
    {
      _dllCreationThreadDetected = true;
      std::wcout << std::endl << "BaseThreadInitThunk: Detected thread creation on LdrLoadDllHook" << std::endl;
    }
    else if (InjectionDetector::Instance()->IsLdrLoadDllStub((DWORD)lpStartAddress))
    {
      _dllCreationThreadDetected = true;
      std::wcout << std::endl << "BaseThreadInitThunk: Detected thread creation on LdrLoadDllStub" << std::endl;
    }
    else
    {
      DWORD startAddress = (DWORD)lpStartAddress;
      if (!InjectionDetector::Instance()->IsModuleAddress(startAddress))
      {
        std::wcout << std::endl << "BaseThreadInitThunk: Detected creation of suspicious thread" << std::endl;
      }
    }
    InjectionDetector::Instance()->CallBaseThreadInitThunkStub(LdrReserved, lpStartAddress, lpParameter);
  }
}
