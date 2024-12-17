#include "common.h"

int loglevel = LOG_DEBUG;

const char *err2str(int e)
{
    switch (e)
    {
        case E_OK: return "Ok";
        case E_BUG: return "Bug";
        case E_OOM: return "Out-of-memory";
        case E_NOT_ENOUGH_DATA: return "Not-enough-data";
        case E_TOO_BIG: return "Msg-too-big";
        case E_INVAL: return "Invalid argument";
        case E_INVALID_DATA: return "Invalid data";
        case E_INCONSIST_LEN: return "Msg-inconsistent-length";
        case E_INVALID_MSG_TYPE: return "Invalid msg type";
        case E_EXCESS_BYTES: return "Excess data";
        case E_TOO_MANY_NHOPS: return "Too many next-hops";
        case E_TOO_MANY_OBJECTS: return "Too many objects";
        default: return "Other/Unknown";
    }
}

