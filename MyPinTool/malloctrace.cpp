#include "pin.H"
#include <iostream>
#include <fstream>
#include <string>

/* ===================================================================== */
/* ===================================================================== */

#define _rtn "jpeg_read_scanlines"

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<bool> ProfileSyscalls(KNOB_MODE_WRITEONCE,"pintool","s","o","Profile syscalls");

/* ===================================================================== */
/* Syscall                                                               */
/* ===================================================================== */
 
std::map<ADDRINT, unsigned long> syscalls;
unsigned long syscall_count = 0;
/*
static void
log_syscall(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v){
    syscalls[PIN_GetSyscallNumber(ctxt, std)]++;
    std::cout<<PIN_GetSyscallNumber(ctxt, std)<<std::endl;
    syscall_count++;
}*/
/*static void
sl_syscall(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v){
    std::cout<<"sl : "<<PIN_GetSyscallNumber(ctxt, std)<<std::endl;
}*/


static void
read_syscall(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v){
    ADDRINT syscall_num=PIN_GetSyscallNumber(ctxt, std);   
    switch(syscall_num){
    case 0:
    {
        ADDRINT buf = PIN_GetSyscallArgument(ctxt,std,1);
        size_t size = PIN_GetSyscallArgument(ctxt,std,2);

        std::cout<<"read_buf : "<<std::hex<<buf<<std::endl;
        std::cout<<"read_len : "<<size<<std::endl;

    }
    }
}
/* ===================================================================== */
/* Instrumentation routines                                              */
/* ===================================================================== */

VOID Rtn(RTN rtn, VOID *v)   //RTN_AddInstrumentFunction(Rtn, NULL);
{    
    if (!RTN_Valid(rtn))return;
   // std::cout<<RTN_Name(rtn)<<std::endl;
    char* c;
    c=const_cast<char*>(RTN_Name(rtn).c_str()); //RTN_Name : const string
  
    if(!strcmp(c,"jpeg_read_header"))
        printf("//////////////////start read header//////////////////\n");
    
    if(!strcmp(c,"alloc_jpeg"))
        printf("//////////////////start alloc jpeg//////////////////\n");


    if(!strcmp(c,_rtn)){ //#define _rtn "jpeg_read_scanlines"
        printf("//////////////////start read scanlines//////////////////\n");
        /*if(ProfileSyscalls.Value()){
            PIN_AddSyscallEntryFunction(log_syscall,0);
        }*/
       /* RTN_Open(rtn);
        for(INS ins=RTN_InsHead(rtn);INS_Valid(ins);ins=INS_Next(ins)){
            if(INS_IsRet(ins))printf("//////////////return/////////////////");
        }
        RTN_Close(rtn);*/
    }
   /* if(!strcmp(c,"jpeg_read_scanlines")){
        if(ProfileSyscalls.Value()){
            PIN_AddSyscallEntryFunction(sl_syscall,0);
        }
    }*/
}
/* ===================================================================== */
/* Instrumentation instructions                                          */                                                
/* ===================================================================== */
/*
static void
print_ret(){
  std::cout<<"////////////////return//////////////"<<std::endl;
}
static void
Insn(INS ins, VOID *v){
    if(INS_IsRet(ins))
    print_ret();
}*/       
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
    //printf("syscall=%d\ninssyscall=%d\n",(int)syscall_count,insnum);
    
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
   // RTN_AddInstrumentFunction(Rtn, NULL);
    //INS_AddInstrumentFunction(Insn,NULL);
    if(ProfileSyscalls.Value()){
        PIN_AddSyscallEntryFunction(read_syscall,0); 
    }
    RTN_AddInstrumentFunction(Rtn, NULL);
    //INS_AddInstrumentFunction(Insn,NULL);

    PIN_AddFiniFunction(Fini, 0);
    // Never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
