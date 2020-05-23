#pragma warning(disable:4996)
#include <windows.h>
#include <stdio.h>
#include "Log.h"

int gLogLevel = 0;
void SetLogLevel(int gLogLevel)
{
    gLogLevel = gLogLevel;
}

void LogMessage(int level, const char *function_name, const char *format, ...)
{
    if (level < gLogLevel)
    {
        return;
    }

    char statement_buffer[1024*4] = { 0, };

    va_list args;
    va_start(args, format);
    _vsnprintf(statement_buffer, sizeof(statement_buffer) / sizeof(char), format, args);
    va_end(args);

    SYSTEMTIME lt;
    GetLocalTime(&lt);

    printf("[%02d:%02d:%02d] %s: %s", lt.wHour, lt.wMinute, lt.wSecond, function_name, statement_buffer);
}
