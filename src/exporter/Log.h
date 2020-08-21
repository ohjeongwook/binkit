#pragma once
#include <windows.h>
#include <stdarg.h>
#include <wtypes.h>

void SetLogLevel(int logLevel);
void LogMessage(int level, const char *function_name, const TCHAR *format, ...);
