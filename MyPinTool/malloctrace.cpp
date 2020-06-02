#include "pin.H"
#include <iostream>
#include <fstream>

/* ===================================================================== */
/* ===================================================================== */

#define _rtn "alloc_jpeg"

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<bool> ProfileSyscalls(KNOB_MODE_WRITEONCE,"pintool","s","o","Profile syscalls");

/* ===================================================================== */
/* Analysis routines                                                     */
/* ===================================================================== */
 
std::map<ADDRINT, unsigned long> syscalls;
unsigned long syscall_count = 0;

static void
log_syscall(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v){
    syscalls[PIN_GetSyscallNumber(ctxt, std)]++;
    syscall_count++;
}

/* ===================================================================== */
/* Instrumentation routines                                              */
/* ===================================================================== */
   
VOID Image(IMG img, VOID *v)
{

    RTN mallocRtn = RTN_FindByName(img, _rtn);
    if (RTN_Valid(mallocRtn))
    {
        RTN_Open(mallocRtn);
        PIN_AddSyscallEntryFunction(log_syscall,NULL);
        RTN_Close(mallocRtn);
    }
}
/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
    unsigned long count;
    std::map<ADDRINT, unsigned long>::iterator j;
    if(!syscalls.empty()) {
        printf("\n******* SYSCALLS *******\n");
        for(j = syscalls.begin(); j != syscalls.end(); j++) {
           count = j->second;
           printf("%3ju: %3lu (%0.2f%%)\n", j->first, count, (double)count/syscall_count*100.0);
        }
    }
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
   
INT32 Usage()
{
    cerr << "This tool produces a trace of syscalls to alloc_jpeg." << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    // Initialize pin & symbol manager
    PIN_InitSymbols();
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    
  
    // Register Image to be called to instrument functions.
    IMG_AddInstrumentFunction(Image, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
