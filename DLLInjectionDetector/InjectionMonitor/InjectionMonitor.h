#pragma once
#include "..\InjectionDetector\IInjectionHandler.h"
#include "..\TypeDefs\TypeDefs.h"

namespace InjectionDetector
{
  class InjectionMonitor : public IInjectionHandler
  {
  public:
    InjectionMonitor();
    ~InjectionMonitor();

    virtual NTSTATUS NTAPI HandleLdrLoadDll(PCWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* DllHandle);
    virtual ULONG __stdcall HandleRtlGetFullPathName_U(PWSTR FileName, ULONG BufferLength, PWSTR Buffer, PWSTR* FilePart);
    virtual void __fastcall HandleBaseThreadInitThunk(IN DWORD LdrReserved, IN LPTHREAD_START_ROUTINE lpStartAddress, IN LPVOID lpParameter);

  private:
    bool _dllCreationThreadDetected;
  };
}