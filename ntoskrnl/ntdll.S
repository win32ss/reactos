
#include <syscalls.inc>

#ifdef _M_ARM

    TEXTAREA

#define SVC_(name, syscallid, argcount) STUB_U name

#include <sysfuncs.h>

    END

#else

.code

#define SVC_(name, syscallid, argcount) STUB_U name, syscallid, argcount

#include <sysfuncs.h>

END
#endif
