#include <iostream>
#include "InjectionDetector\InjectionDetector.h"
#include "InjectionMonitor\InjectionMonitor.h"
#include "InjectionGuard\InjectionGuard.h"

void ShowInfo();
void ShowHelp();

int wmain(int argc, wchar_t* argv[])
{
  if (argc != 2)
  {
    ShowHelp();
    return 0;
  }

  LPWSTR parameter = argv[1];
  if (wcscmp(parameter, L"-m") == 0)
  {
    ShowInfo();
    std::wcout << "Starting in monitoring mode." << std::endl;
    InjectionDetector::InjectionDetector::Instance()->Initialze(new InjectionDetector::InjectionMonitor());
  }
  else if (wcscmp(parameter, L"-g") == 0)
  {
    ShowInfo();
    std::wcout << "Starting in guard mode." << std::endl;
    InjectionDetector::InjectionDetector::Instance()->Initialze(new InjectionDetector::InjectionGuard());
  }
  else
  {
    ShowHelp();
    return 0;
  }

  std::wcout << std::endl << "Waiting for injection";

  while (true)
  {
    Sleep(200);
    std::wcout << ".";
  }
}

void ShowInfo()
{
  std::wcout << std::endl;
  std::wcout << "..::[Fatmike 2025]::.." << std::endl << std::endl;
  std::wcout << "Version: DLL Injection Detector 0.0.1" << std::endl;
}

void ShowHelp()
{
  ShowInfo();
  std::wcout << "Usage:\t DLLInjectionDetector.exe -m " << " : Start in monitoring mode (monitoring only)" << std::endl;
  std::wcout << "Usage:\t DLLInjectionDetector.exe -g " << " : Start in guard mode (blocking dll injections)" << std::endl << std::endl;
  std::wcout << "Press enter to exit." << std::endl;
  std::wcin.get();
}

