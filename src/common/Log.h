#pragma once
#include <windows.h>
#include <stdarg.h>

void SetLogLevel(int level);
void LogMessage(int level, const char *function_name, const char *format, ...);
