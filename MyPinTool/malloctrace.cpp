#include "pin.H"
#include <iostream>
#include <fstream>

/* ===================================================================== */
/* ===================================================================== */

#define _rtn "jpeg_create_decompress"

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<bool> ProfileSyscalls(KNOB_MODE_WRITEONCE,"pintool","s","o","Profile syscalls");

/* ===================================================================== */
/* Syscall                                                               */
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
int i=0;
int sum=0;   
VOID Image(IMG img, VOID *v)
{    
    sum++;
    //std::cout<<IMG_Name(img)<<std::endl;
    RTN rtn = RTN_FindByName(img, _rtn);
    if (!RTN_Valid(rtn))return;
    i++;
    PIN_AddSyscallEntryFunction(log_syscall,NULL);
}
/* ===================================================================== */
/* Instrumentation instructions                                          */                                                
/* ===================================================================== */
int insnum=0;
VOID Insn(INS ins, VOID *v){
    if(INS_IsSyscall(ins)){
        insnum++;
        std::cout<<RTN_Name(INS_Rtn(ins))<<std::endl;
    }

}
/* ===================================================================== */
/* Print result                                                          */
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
    printf("syscall=%d\ninssyscall=%d\n",(int)syscall_count,insnum);
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
     
    // Instrumentation
    // IMG_AddInstrumentFunction(Image, NULL);
    INS_AddInstrumentFunction(Insn,NULL);
    if(ProfileSyscalls.Value()){
        PIN_AddSyscallEntryFunction(log_syscall,0); 
    }
    PIN_AddFiniFunction(Fini, 0);
    // Never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
