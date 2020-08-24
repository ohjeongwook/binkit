#pragma warning(disable:4996)
#include <windows.h>
#include <stdio.h>
#include <TCHAR.H>
#include <ida.hpp>
#include <kernwin.hpp>

int gLogLevel = 2;
void SetLogLevel(int logLevel)
{
    gLogLevel = logLevel;
}

void LogMessage(int level, const char *function_name, const TCHAR *format, ...)
{
    if (level >= gLogLevel)
    {
        return;
    }

    TCHAR statement_buffer[1024*4] = { 0, };

    va_list args;
    va_start(args, format);
    _vsntprintf(statement_buffer, sizeof(statement_buffer) / sizeof(TCHAR), format, args);
    va_end(args);

    SYSTEMTIME lt;
    GetLocalTime(&lt);

    msg("[%02d:%02d:%02d] %s: %s", lt.wHour, lt.wMinute, lt.wSecond, function_name, statement_buffer);
}
