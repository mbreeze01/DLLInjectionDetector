#pragma once
#include <Windows.h>

namespace HookEngine
{
  class HookEngine
  {
  public:

    HookEngine();
    ~HookEngine();

    BOOL InstallHook(PVOID originalFunction, PVOID hookFunction, PVOID& stubFunction);
  
  private:
    BOOL CanHook(PVOID originalFunction);
  };
}