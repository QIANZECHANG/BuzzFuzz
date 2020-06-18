#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>

#include <map>
#include <string>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/net.h>

#include "pin.H"

#include "branch_pred.h"
#include "libdft_api.h"
#include "syscall_desc.h"
#include "tagmap.h"

extern syscall_desc_t syscall_desc[SYSCALL_MAX];
extern ins_desc_t ins_desc[XED_ICLASS_LAST];

void
alert(uintptr_t addr, uint8_t tag)
{
  printf("\n(BuzzFuzz) !!!!!!! ADDRESS 0x%x IS TAINTED (tag=0x%02x), ABORTING !!!!!!!\n",
          addr, tag);
  exit(1);
}

//jpegファイルの全部のバイトにcolorを付ける
static void
post_read_hook(syscall_ctx_t *ctx)
{
  int fd     =    (int)ctx->arg[SYSCALL_ARG0];
  void *buf  =  (void*)ctx->arg[SYSCALL_ARG1];
  size_t len = (size_t)ctx->ret;
  uint8_t color=0x01;
 
  if(unlikely(len <= 0)) {
    return;
  }

  printf("(BuzzFuzz_read) read: %zu bytes from fd %u\n", len, fd);
  printf("(BuzzFuzz_read) tainting bytes %p -- 0x%x with color 0x%x\n", 
          buf, (uintptr_t)buf+len, color);

  tagmap_setn((uintptr_t)buf, len, color); 
  
}
/*
32bitでmmapがmmap２となる

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
第二引数（length）を注目する。colorがあるかどうかをcheck

*/
static void
post_mmap2_hook(syscall_ctx_t *ctx){
  void *len_addr=&ctx->arg[SYSCALL_ARG1];
  uint8_t color;

  printf("(mmap2) len_addr : %p\n",len_addr);
  color = tagmap_getb((uintptr_t)len_addr);

  if(color){
    alert((uintptr_t)len_addr,color);
  }else{
    return;
  }
}

static void
taint_eax(uint32_t reg){
        uint8_t color=0x01;
        void* addr=&reg;
        
        if(reg==0x3)
        printf("(taint_eax) %p\n",&reg);
	
        tagmap_setn((uintptr_t)addr,1,color);
}


static void
dta_eax(INS ins,void* v)
{
	IMG img = IMG_FindByAddress(INS_Address(ins));
        if(!IMG_Valid(img)||!IMG_IsMainExecutable(img))return;

        REG reg;

        if (INS_OperandIsReg(ins, 0)) {
         	reg = INS_OperandReg(ins, 0);
                
		INS_InsertCall(ins,
			IPOINT_BEFORE,
                        (AFUNPTR)taint_eax,
			IARG_REG_VALUE, reg,
			IARG_END);
	}
}

int
main(int argc, char **argv)
{
  PIN_InitSymbols();

  if(unlikely(PIN_Init(argc, argv))) {
    return 1;
  }

  if(unlikely(libdft_init() != 0)) {
    libdft_die();
    return 1;
  }
  
  syscall_set_post(&syscall_desc[__NR_read], post_read_hook);
  syscall_set_pre(&syscall_desc[__NR_mmap2], post_mmap2_hook);
  //ins_set_pre(&ins_desc[XED_ICLASS_MOVZX],dta_eax);
  INS_AddInstrumentFunction(dta_eax,NULL);
 
  PIN_StartProgram();
 
  return 0;
}

