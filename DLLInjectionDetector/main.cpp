#include <iostream>
#include "InjectionDetector\InjectionDetector.h"
#include "InjectionMonitor\InjectionMonitor.h"
#include "InjectionGuard\InjectionGuard.h"

int main()
{
  std::wcout << "DLL Injection Detector." << std::endl;
  
  //InjectionDetector::InjectionDetector::Instance()->Initialze(new InjectionDetector::InjectionMonitor());

  InjectionDetector::InjectionDetector::Instance()->Initialze(new InjectionDetector::InjectionGuard());

  std::wcout << "Waiting for injection" << std::endl;

  while (true)
  {
    Sleep(200);
    std::wcout << ".";
  }
}