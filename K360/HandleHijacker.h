#pragma once
#include <Windows.h>
#include <winternl.h>
#include <memory>
#include <iostream>

#include "Native.hpp"
HANDLE HijackProcessHandle( HANDLE hProcess, DWORD dwDesiredAccess);
