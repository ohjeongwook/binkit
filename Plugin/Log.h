#pragma once
#include <windows.h>
#include <stdarg.h>
#include <wtypes.h>

void SetLogLevel(int level);
void LogMessage(int level, const char *function_name, const TCHAR *format, ...);
