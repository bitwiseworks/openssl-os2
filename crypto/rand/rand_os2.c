/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "cryptlib.h"
#include <openssl/rand.h>
#include "rand_lcl.h"

#ifdef OPENSSL_SYS_OS2

# define INCL_DOSPROCESS
# define INCL_DOSPROFILE
# define INCL_DOSMISC
# define INCL_DOSMODULEMGR
# include <os2.h>

# define   CMD_KI_ENABLE   (0x60)
# define   CMD_KI_RDCNT    (0x63)

typedef struct _CPUUTIL {
    ULONG ulTimeLow;            /* Low 32 bits of time stamp */
    ULONG ulTimeHigh;           /* High 32 bits of time stamp */
    ULONG ulIdleLow;            /* Low 32 bits of idle time */
    ULONG ulIdleHigh;           /* High 32 bits of idle time */
    ULONG ulBusyLow;            /* Low 32 bits of busy time */
    ULONG ulBusyHigh;           /* High 32 bits of busy time */
    ULONG ulIntrLow;            /* Low 32 bits of interrupt time */
    ULONG ulIntrHigh;           /* High 32 bits of interrupt time */
} CPUUTIL;

int RAND_poll(void)
{
    static int checked_to_use_dosperfsyscall = 0;
    static int use_dosperfsyscall = 0;
    APIRET rc;
    QWORD qwTime;
    ULONG SysVars[QSV_FOREGROUND_PROCESS];

    if (!checked_to_use_dosperfsyscall) {
        char *env;
        env = getenv("OPENSSL_USE_DOSPERFSYSCALL");
        if (env) {
            switch(*env) {
                case 'T': case 't': case 'Y': case 'y': case 'O': case 'o':
                    use_dosperfsyscall = 1; break;
                default:
                    use_dosperfsyscall = atoi(env) > 0;
                    break;
            }
        }
        else {
            use_dosperfsyscall = 0;
        }
        checked_to_use_dosperfsyscall = 1; /* true */
    }

    /* Sample the hi-res timer, runs at around 1.1 MHz */
    DosTmrQueryTime(&qwTime);
    RAND_add(&qwTime, sizeof(qwTime), 2);

    /*
     * Sample a bunch of system variables, includes various process & memory
     * statistics
     */
    DosQuerySysInfo(1, QSV_FOREGROUND_PROCESS, SysVars, sizeof(SysVars));
    RAND_add(SysVars, sizeof(SysVars), 4);

    /*
     * If available, sample CPU registers that count at CPU MHz Only fairly
     * new CPUs (PPro & K6 onwards) & OS/2 versions support this
     */
    if (use_dosperfsyscall) {
        static volatile int perfsyscall_initcount = 0;
        // 2011-04-22 SHL really should check #CPUs just in case
        CPUUTIL util[16];

        /* APAR: The API call to DosPerfSysCall needs to be added 
         *       to the startup code.
         * reference: http://www-01.ibm.com/support/docview.wss?uid=swg1IY67424
         */
        if (perfsyscall_initcount == 0) {
            if (DosEnterCritSec() == 0) {
                if (perfsyscall_initcount == 0)
                    DosPerfSysCall(CMD_KI_ENABLE, 0, 0, 0);
                ++perfsyscall_initcount;
                DosExitCritSec();
            }
        }
        if (DosPerfSysCall(CMD_KI_RDCNT, (ULONG)util, 0, 0) == 0) {
            RAND_add(&util, sizeof(util), 10);
        }
    }
    else {
        unsigned char tmpbuf[32];
        int i;
        for(i=0; i<sizeof(tmpbuf); i+=2) {
            unsigned long ul = (unsigned long)random();
            tmpbuf[i] = (unsigned char)(ul);
            tmpbuf[i+1] = (unsigned char)(ul >> 8);
        }
        RAND_add(tmpbuf, sizeof(tmpbuf), sizeof(tmpbuf));
    }

    /*
     * DosQuerySysState() gives us a huge quantity of process, thread, memory
     * & handle stats
     */
    ULONG buffer_size;
    char *buffer;
    buffer = NULL;
    buffer_size = 65536 * 4;
    rc = DosAllocMem((PVOID *)&buffer, buffer_size + 65535, PAG_READ | PAG_WRITE | PAG_COMMIT | OBJ_TILE);
    if (rc == 0 && DosQuerySysState(0x1F, 0, 0, 0, buffer, buffer_size) == 0) {
        /* First 4 bytes in buffer is a pointer to the thread count
        * there should be at least 1 byte of entropy per thread
        */
        RAND_add(buffer, buffer_size, **(ULONG **)buffer);
        DosFreeMem(buffer);
        return 1;
    }

    return 0;
}

#endif                          /* OPENSSL_SYS_OS2 */
